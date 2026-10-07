package hub

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/vfilby/interpose/broker/internal/apns"
	"github.com/vfilby/interpose/internal/audit"
	"github.com/vfilby/interpose/internal/protocol"
)

// API serves adapters and devices (docs/PROTOCOL.md, "Hub HTTP API"). Tokens here are transport credentials only.
type API struct {
	Store   *Store
	Audit   *audit.Log
	Log     *slog.Logger
	Now     func() time.Time
	MaxWait time.Duration // cap on the decisions long-poll
	Push    Pusher        // nil: no push notifications
	// TrustedProxies are reverse proxies whose X-Forwarded-For names the client (for the enrollment rate limit).
	TrustedProxies []netip.Prefix

	enrollFails *failLimiter

	pushed chan struct{} // tests: signalled after each background push batch
}

func (a *API) Handler() http.Handler {
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.MaxWait == 0 {
		a.MaxWait = 30 * time.Second
	}
	if a.enrollFails == nil {
		a.enrollFails = newFailLimiter(EnrollFailBurst, EnrollFailEvery)
	}
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/adapter/requests", a.adapter(a.publish))
	m.HandleFunc("GET /v1/adapter/decisions", a.adapter(a.decisions))
	m.HandleFunc("POST /v1/adapter/acks", a.adapter(a.ack))
	m.HandleFunc("GET /v1/adapter/rosters", a.adapter(a.adapterRosters))
	m.HandleFunc("POST /v1/enroll", a.enroll)
	// A device that asked to join and is not in its user's roster yet may only read the roster (to learn when it is
	// admitted and show the account fingerprint) and withdraw; everything else waits for a member to admit it.
	m.HandleFunc("GET /v1/device/roster", a.anyDevice(a.deviceRoster))
	m.HandleFunc("POST /v1/device/leave", a.anyDevice(a.deviceLeave))
	m.HandleFunc("POST /v1/device/roster", a.device(a.postRoster))
	m.HandleFunc("POST /v1/device/push", a.device(a.devicePush))
	m.HandleFunc("GET /v1/device/joins", a.device(a.deviceJoins))
	m.HandleFunc("GET /v1/device/adapters", a.device(a.deviceAdapters))
	m.HandleFunc("GET /v1/device/requests", a.device(a.deviceRequests))
	m.HandleFunc("POST /v1/device/decisions", a.device(a.deviceDecide))
	m.HandleFunc("GET /v1/device/acks", a.device(a.deviceAcks))
	m.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "ok\n") })
	return m
}

func bearer(r *http.Request) string {
	t, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	if !ok {
		return ""
	}
	return strings.TrimSpace(t)
}

func (a *API) adapter(h func(http.ResponseWriter, *http.Request, *Adapter)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ad, ok := a.Store.AdapterByToken(bearer(r), a.Now())
		if !ok {
			httpErr(w, http.StatusUnauthorized, "unknown adapter token")
			return
		}
		h(w, r, ad)
	}
}

// device serves admitted devices only: a join request nobody has approved gets 403.
func (a *API) device(h func(http.ResponseWriter, *http.Request, *Device)) http.HandlerFunc {
	return a.anyDevice(func(w http.ResponseWriter, r *http.Request, d *Device) {
		if d.JoinRequested {
			httpErr(w, http.StatusForbidden, "join not approved yet: a device of this account must admit this one")
			return
		}
		h(w, r, d)
	})
}

// anyDevice serves any device with a valid token, including a pending join request.
func (a *API) anyDevice(h func(http.ResponseWriter, *http.Request, *Device)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		d, ok := a.Store.DeviceByToken(bearer(r), a.Now())
		if !ok {
			httpErr(w, http.StatusUnauthorized, "unknown or revoked device token")
			return
		}
		h(w, r, d)
	}
}

func (a *API) publish(w http.ResponseWriter, r *http.Request, ad *Adapter) {
	var in struct {
		ID        string                     `json:"id"`
		Kind      string                     `json:"kind"`
		CreatedAt int64                      `json:"created_at"`
		ExpiresAt int64                      `json:"expires_at"`
		Boxes     map[string]protocol.Sealed `json:"boxes"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	now := a.Now()
	if in.CreatedAt == 0 {
		in.CreatedAt = now.Unix()
	}
	err := a.Store.Publish(ad.ID, Request{ID: in.ID, Kind: in.Kind, CreatedAt: in.CreatedAt, ExpiresAt: in.ExpiresAt, Boxes: in.Boxes}, now)
	switch {
	case errors.Is(err, ErrConflict):
		w.WriteHeader(http.StatusOK) // idempotent: the adapter retries after a lost response
		return
	case errors.Is(err, ErrTooMany):
		httpErr(w, http.StatusTooManyRequests, err.Error())
		return
	case err != nil:
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	a.audit(audit.Event{Time: now, Event: "published", Adapter: ad.ID, RequestID: in.ID, Detail: in.Kind})
	ids := make([]string, 0, len(in.Boxes))
	for id := range in.Boxes {
		ids = append(ids, id)
	}
	exp := time.Time{}
	if in.ExpiresAt > 0 {
		exp = time.Unix(in.ExpiresAt, 0)
	}
	a.wake(ids, apns.Notification{Title: "Approval request", Body: "Open Interpose to review it.", Expiration: exp,
		ThreadID: "requests"})
	w.WriteHeader(http.StatusCreated)
}

// decisions long-polls: it answers at once if decisions are queued, else waits up to ?wait= seconds for one.
func (a *API) decisions(w http.ResponseWriter, r *http.Request, ad *Adapter) {
	wait, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	d := min(time.Duration(wait)*time.Second, a.MaxWait)
	timer := time.NewTimer(max(d, 0))
	defer timer.Stop()
	for {
		ch := a.Store.Changed()
		if out := a.Store.TakeDecisions(ad.ID); len(out) > 0 {
			writeJSON(w, out)
			return
		}
		select {
		case <-ch:
		case <-timer.C:
			writeJSON(w, []QueuedDecision{})
			return
		case <-r.Context().Done():
			return
		}
	}
}

func (a *API) ack(w http.ResponseWriter, r *http.Request, ad *Adapter) {
	var in struct {
		RequestID string            `json:"request_id"`
		Ack       protocol.Envelope `json:"ack"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	// The hub can check this one: the adapter's key is registered here. It keeps a broken adapter from resolving
	// requests with garbage; it is not what the app relies on (the app verifies against its own pinned key).
	key, _ := protocol.UnB64(ad.Key)
	ack, err := protocol.VerifyAck(in.Ack, key)
	if err != nil || ack.RequestID != in.RequestID || ack.Adapter != ad.ID {
		httpErr(w, http.StatusBadRequest, "ack does not verify for this adapter and request")
		return
	}
	now := a.Now()
	if err := a.Store.Ack(ad.ID, in.RequestID, ack.Outcome, in.Ack, now); err != nil {
		httpErr(w, http.StatusNotFound, err.Error())
		return
	}
	a.audit(audit.Event{Time: now, Event: "acked", Adapter: ad.ID, RequestID: in.RequestID, Detail: ack.Outcome + " " + ack.Detail})
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) enroll(w http.ResponseWriter, r *http.Request) {
	now := a.Now()
	client := clientIP(r, a.TrustedProxies)
	if ok, first := a.enrollFails.allow(client, now); !ok {
		if first {
			a.audit(audit.Event{Time: now, Event: "enroll-limited", Detail: "too many failed enrollments from " + client})
		}
		w.Header().Set("Retry-After", strconv.Itoa(int(EnrollFailEvery/time.Second)))
		httpErr(w, http.StatusTooManyRequests, "too many failed enrollments: try again later")
		return
	}
	var in struct {
		Code    string             `json:"code"`
		Card    protocol.Envelope  `json:"card"`
		Genesis *protocol.Envelope `json:"genesis"`
	}
	if !readJSON(w, r, &in) {
		a.enrollFails.fail(client, now)
		return
	}
	e, err := a.Store.Enroll(in.Code, in.Card, in.Genesis, now)
	if err != nil {
		a.enrollFails.fail(client, now)
		// Nothing here is authenticated: the card's kid is whatever the client sent, so it is clipped, not trusted.
		a.audit(audit.Event{Time: now, Event: "enroll-failed", Device: clip(in.Card.Kid, 64),
			Detail: clip(err.Error(), 200) + " (from " + client + ")"})
		httpErr(w, http.StatusForbidden, err.Error())
		return
	}
	status := "active"
	if !e.Active {
		status = "pending"
	}
	if !e.Active {
		a.wake(a.Store.members(e.User), apns.Notification{Title: "New device",
			Body: "A device asks to join your account. Open Interpose to compare fingerprints.", ThreadID: "joins"})
	}
	ak, _ := protocol.UnB64(e.Card.ApproveKey)
	a.audit(audit.Event{Time: now, Event: "enrolled", Device: e.Card.DeviceID, Requester: e.User,
		Detail: status + " " + e.Card.Name + " " + protocol.Fingerprint(ak)})
	writeJSON(w, map[string]string{"device_id": e.Card.DeviceID, "token": e.Token, "user": e.User, "status": status})
}

type chainOut struct {
	User  string              `json:"user"`
	Chain []protocol.Envelope `json:"chain"`
}

func (a *API) adapterRosters(w http.ResponseWriter, r *http.Request, _ *Adapter) {
	user := r.URL.Query().Get("user")
	chain, ok := a.Store.Chain(user)
	if !ok {
		httpErr(w, http.StatusNotFound, "no such user")
		return
	}
	writeJSON(w, chainOut{user, chain})
}

func (a *API) deviceRoster(w http.ResponseWriter, _ *http.Request, d *Device) {
	chain, ok := a.Store.Chain(d.User)
	if !ok {
		httpErr(w, http.StatusNotFound, "this device has no account (enrolled before accounts existed): enroll again")
		return
	}
	writeJSON(w, chainOut{d.User, chain})
}

// postRoster appends the next roster to the device's user. The hub checks the chain so it stores nothing broken;
// the security of it rests on adapters and devices checking it again.
func (a *API) postRoster(w http.ResponseWriter, r *http.Request, d *Device) {
	var in struct {
		Roster protocol.Envelope `json:"roster"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	h, err := a.Store.AppendRoster(d.User, in.Roster)
	if err != nil {
		httpErr(w, http.StatusConflict, err.Error())
		return
	}
	a.audit(audit.Event{Time: a.Now(), Event: "roster", Device: d.ID, Requester: d.User,
		Detail: fmt.Sprintf("seq %d, %d devices", h.Roster.Seq, len(h.Devices))})
	w.WriteHeader(http.StatusNoContent)
}

// deviceLeave: the device goes away from the hub (Store.Leave). Its token stops working. A pending join request
// may only withdraw itself.
func (a *API) deviceLeave(w http.ResponseWriter, r *http.Request, d *Device) {
	var in struct {
		Roster        *protocol.Envelope `json:"roster,omitempty"`
		DeleteAccount bool               `json:"delete_account,omitempty"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if d.JoinRequested && (in.Roster != nil || in.DeleteAccount) {
		httpErr(w, http.StatusForbidden, "join not approved yet: this device can only withdraw its request")
		return
	}
	deleted, err := a.Store.Leave(d.ID, in.Roster, in.DeleteAccount)
	if err != nil {
		httpErr(w, http.StatusConflict, err.Error())
		return
	}
	detail := "roster unchanged"
	switch {
	case deleted:
		detail = "last device: account " + d.User + " deleted"
	case in.Roster != nil:
		detail = "removed itself from the roster"
	}
	a.audit(audit.Event{Time: a.Now(), Event: "device-left", Device: d.ID, Requester: d.User, Detail: detail})
	w.WriteHeader(http.StatusNoContent)
}

// devicePush: the app registers (or, with an empty token, withdraws) its APNs device token.
func (a *API) devicePush(w http.ResponseWriter, r *http.Request, d *Device) {
	var in struct {
		Token       string `json:"token"`
		Environment string `json:"environment"` // production | development
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Environment != "production" && in.Environment != "development" {
		httpErr(w, http.StatusBadRequest, "environment: production or development")
		return
	}
	if err := a.Store.SetPushToken(d.ID, in.Token, in.Environment == "development"); err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (a *API) deviceJoins(w http.ResponseWriter, _ *http.Request, d *Device) {
	type out struct {
		DeviceID    string            `json:"device_id"`
		Name        string            `json:"name"`
		Card        protocol.Envelope `json:"card"`
		RequestedAt int64             `json:"requested_at"`
	}
	res := []out{}
	for _, j := range a.Store.Joins(d.User) {
		res = append(res, out{j.ID, j.Name, j.Card, j.EnrolledAt.Unix()})
	}
	writeJSON(w, res)
}

func (a *API) deviceAdapters(w http.ResponseWriter, _ *http.Request, _ *Device) {
	type out struct {
		ID          string `json:"id"`
		Key         string `json:"key"`
		Fingerprint string `json:"fingerprint"`
	}
	res := []out{}
	for _, ad := range a.Store.Adapters() {
		k, _ := protocol.UnB64(ad.Key)
		res = append(res, out{ad.ID, ad.Key, protocol.Fingerprint(k)})
	}
	writeJSON(w, res)
}

func (a *API) deviceRequests(w http.ResponseWriter, _ *http.Request, d *Device) {
	type out struct {
		ID        string          `json:"id"`
		Adapter   string          `json:"adapter"`
		Kind      string          `json:"kind"`
		CreatedAt int64           `json:"created_at"`
		ExpiresAt int64           `json:"expires_at"`
		Box       protocol.Sealed `json:"box"`
	}
	res := []out{}
	for _, r := range a.Store.ForDevice(d.ID, a.Now()) {
		res = append(res, out{r.ID, r.Adapter, r.Kind, r.CreatedAt, r.ExpiresAt, r.Boxes[d.ID]})
	}
	writeJSON(w, res)
}

func (a *API) deviceDecide(w http.ResponseWriter, r *http.Request, d *Device) {
	var in struct {
		Adapter   string            `json:"adapter"`
		RequestID string            `json:"request_id"`
		Decision  protocol.Envelope `json:"decision"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	if in.Decision.Kid != d.ID {
		httpErr(w, http.StatusBadRequest, "decision is not signed as this device")
		return
	}
	now := a.Now()
	switch err := a.Store.Decide(d.ID, in.Adapter, in.RequestID, in.Decision, now); {
	case errors.Is(err, ErrBadDecision):
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	case errors.Is(err, ErrQueueFull):
		httpErr(w, http.StatusTooManyRequests, err.Error())
		return
	case err != nil:
		httpErr(w, http.StatusNotFound, err.Error())
		return
	}
	a.audit(audit.Event{Time: now, Event: "decision-queued", Adapter: in.Adapter, RequestID: in.RequestID, Device: d.ID})
	w.WriteHeader(http.StatusAccepted)
}

func (a *API) deviceAcks(w http.ResponseWriter, r *http.Request, d *Device) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	res := a.Store.Acks(d.ID, time.Unix(since, 0))
	if res == nil {
		res = []AckEntry{}
	}
	writeJSON(w, res)
}

func (a *API) audit(e audit.Event) {
	if a.Audit == nil {
		return
	}
	if err := a.Audit.Write(e); err != nil && a.Log != nil {
		a.Log.Error("audit write failed", "event", e.Event, "err", err)
	}
}

const maxBody = 256 << 10

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxBody))
	if err := dec.Decode(v); err != nil {
		httpErr(w, http.StatusBadRequest, "bad JSON: "+err.Error())
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": msg})
}
