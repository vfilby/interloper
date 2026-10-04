package hub

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"warpgate-approver/broker/internal/audit"
	"warpgate-approver/broker/internal/protocol"
)

// API serves adapters and devices (docs/PROTOCOL.md, "Hub HTTP API"). Tokens here are transport credentials only.
type API struct {
	Store   *Store
	Audit   *audit.Log
	Log     *slog.Logger
	Now     func() time.Time
	MaxWait time.Duration // cap on the decisions long-poll
}

func (a *API) Handler() http.Handler {
	if a.Now == nil {
		a.Now = time.Now
	}
	if a.MaxWait == 0 {
		a.MaxWait = 30 * time.Second
	}
	m := http.NewServeMux()
	m.HandleFunc("POST /v1/adapter/requests", a.adapter(a.publish))
	m.HandleFunc("GET /v1/adapter/decisions", a.adapter(a.decisions))
	m.HandleFunc("POST /v1/adapter/acks", a.adapter(a.ack))
	m.HandleFunc("POST /v1/enroll", a.enroll)
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

func (a *API) device(h func(http.ResponseWriter, *http.Request, *Device)) http.HandlerFunc {
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
	p, err := protocol.VerifyEd25519(in.Ack, key)
	var ack protocol.Ack
	if err == nil {
		err = json.Unmarshal(p, &ack)
	}
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
	var in struct {
		Code string            `json:"code"`
		Card protocol.Envelope `json:"card"`
	}
	if !readJSON(w, r, &in) {
		return
	}
	now := a.Now()
	c, tok, err := a.Store.Enroll(in.Code, in.Card, now)
	if err != nil {
		a.audit(audit.Event{Time: now, Event: "enroll-failed", Device: c.DeviceID, Detail: err.Error()})
		httpErr(w, http.StatusForbidden, err.Error())
		return
	}
	ak, _ := protocol.UnB64(c.ApproveKey)
	a.audit(audit.Event{Time: now, Event: "enrolled", Device: c.DeviceID, Detail: c.Name + " " + protocol.Fingerprint(ak)})
	writeJSON(w, map[string]string{"device_id": c.DeviceID, "token": tok})
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
	if err := a.Store.Decide(d.ID, in.Adapter, in.RequestID, in.Decision, now); err != nil {
		httpErr(w, http.StatusNotFound, err.Error())
		return
	}
	a.audit(audit.Event{Time: now, Event: "decision-queued", Adapter: in.Adapter, RequestID: in.RequestID, Device: d.ID})
	w.WriteHeader(http.StatusAccepted)
}

func (a *API) deviceAcks(w http.ResponseWriter, r *http.Request, _ *Device) {
	since, _ := strconv.ParseInt(r.URL.Query().Get("since"), 10, 64)
	res := a.Store.Acks(time.Unix(since, 0))
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
