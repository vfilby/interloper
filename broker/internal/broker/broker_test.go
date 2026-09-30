package broker

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warpgate-approver/broker/internal/audit"
	"warpgate-approver/broker/internal/notify"
	"warpgate-approver/broker/internal/policy"
	"warpgate-approver/broker/internal/warpgate"
)

var t0 = time.Date(2026, 9, 30, 12, 0, 0, 0, time.UTC)

type fakeWG struct {
	pending  []warpgate.TicketRequest
	users    map[string]string
	targets  map[string]string
	denied   map[string]string
	pollErr  error
	usersErr error
	expiries []time.Time
}

func (f *fakeWG) PendingRequests(context.Context) ([]warpgate.TicketRequest, error) {
	return f.pending, f.pollErr
}
func (f *fakeWG) Usernames(context.Context) (map[string]string, error) { return f.users, f.usersErr }
func (f *fakeWG) TargetNames(context.Context) (map[string]string, error) {
	return f.targets, nil
}
func (f *fakeWG) Deny(_ context.Context, id, reason string) error {
	f.denied[id] = reason
	var keep []warpgate.TicketRequest
	for _, r := range f.pending {
		if r.ID != id {
			keep = append(keep, r)
		}
	}
	f.pending = keep
	return nil
}
func (f *fakeWG) TokenExpiries(context.Context) ([]time.Time, error) { return f.expiries, nil }

type fakeN struct {
	sent []notify.Message
	fail bool
}

func (n *fakeN) Send(_ context.Context, m notify.Message) error {
	if n.fail {
		return errors.New("pushover down")
	}
	n.sent = append(n.sent, m)
	return nil
}

func req(id, user, target string, durS int64, created time.Time, desc string) warpgate.TicketRequest {
	return warpgate.TicketRequest{ID: id, UserID: user, TargetID: target, RequestedDurationSeconds: &durS,
		Description: desc, Status: "Pending", Created: created}
}

func setup(t *testing.T, mode Mode) (*Broker, *fakeWG, *fakeN, string) {
	t.Helper()
	dir := t.TempDir()
	wg := &fakeWG{
		users:   map[string]string{"u-claude": "claude", "u-assistant": "assistant"},
		targets: map[string]string{"t-forge-rw": "build-01-rw", "t-files-01-admin": "files-01-admin", "t-db-01-ro": "db-01-ro"},
		denied:  map[string]string{},
	}
	n := &fakeN{}
	return newBroker(t, dir, mode, wg, n), wg, n, dir
}

func newBroker(t *testing.T, dir string, mode Mode, wg *fakeWG, n *fakeN) *Broker {
	t.Helper()
	a, err := audit.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	b, err := New(Config{
		Mode: mode,
		Policy: policy.Policy{
			Requesters:  map[string]bool{"claude": true},
			MaxDuration: map[policy.Tier]time.Duration{policy.TierRW: 2 * time.Hour, policy.TierAdmin: 30 * time.Minute},
			TTL:         15 * time.Minute,
		},
		ApprovalURL: "https://wg/@warpgate/admin#/config/tickets",
		StateFile:   filepath.Join(dir, "state.json"),
		NotifyBurst: 3, NotifyWindow: 10 * time.Minute, AlertAfter: 5 * time.Minute,
		TokenWarn: 30 * 24 * time.Hour, RetryAfter: 30 * time.Second,
	}, wg, n, a, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func events(t *testing.T, dir string) []string {
	t.Helper()
	f, err := os.Open(filepath.Join(dir, "audit.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		var e audit.Event
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatal(err)
		}
		out = append(out, e.Event+":"+e.RequestID)
	}
	return out
}

func TestAllowedRequestNotifiedOnceThenLeaves(t *testing.T) {
	b, wg, n, dir := setup(t, ModeEnforce)
	ctx := context.Background()
	wg.pending = []warpgate.TicketRequest{req("r1", "u-claude", "t-forge-rw", 7200, t0, "restart\x1b[31m sentinel\u202e")}
	b.Tick(ctx, t0)
	b.Tick(ctx, t0.Add(5*time.Second))
	if len(n.sent) != 1 {
		t.Fatalf("want exactly one notification, got %d", len(n.sent))
	}
	m := n.sent[0]
	if m.Title != "claude wants RW on build-01" {
		t.Errorf("title %q", m.Title)
	}
	for _, want := range []string{"Target: build-01-rw", "Duration: 2h", "Reason given by claude: “restart[31m sentinel”", "unanswered by"} {
		if !strings.Contains(m.Body, want) {
			t.Errorf("body missing %q:\n%s", want, m.Body)
		}
	}
	if m.URL == "" || m.TTL != 15*time.Minute {
		t.Errorf("url %q ttl %v", m.URL, m.TTL)
	}
	wg.pending = nil // approved in the UI
	b.Tick(ctx, t0.Add(10*time.Second))
	got := strings.Join(events(t, dir), " ")
	if got != "seen:r1 notified:r1 left-pending:r1" {
		t.Errorf("audit = %s", got)
	}
	if len(wg.denied) != 0 {
		t.Errorf("denied %v", wg.denied)
	}
}

func TestEnforceDeniesPolicyViolations(t *testing.T) {
	b, wg, n, _ := setup(t, ModeEnforce)
	ctx := context.Background()
	wg.pending = []warpgate.TicketRequest{
		req("over", "u-claude", "t-files-01-admin", 7200, t0, "long"),
		req("who", "u-assistant", "t-forge-rw", 600, t0, "x"),
		req("ro", "u-claude", "t-db-01-ro", 600, t0, "x"),
	}
	b.Tick(ctx, t0)
	want := map[string]string{
		"over": "warpgate-approver: asks for 2h, over the 30m cap for admin",
		"who":  "warpgate-approver: assistant may not ask for tickets",
		"ro":   "warpgate-approver: db-01-ro is not an rw or admin tier",
	}
	for id, reason := range want {
		if wg.denied[id] != reason {
			t.Errorf("%s denied with %q, want %q", id, wg.denied[id], reason)
		}
	}
	if len(n.sent) != 3 || n.sent[0].Priority != -1 || !strings.HasPrefix(n.sent[0].Title, "Denied: ") {
		t.Errorf("want 3 quiet denial notices, got %+v", n.sent)
	}
}

func TestEnforceDeniesAfterTTL(t *testing.T) {
	b, wg, n, _ := setup(t, ModeEnforce)
	ctx := context.Background()
	wg.pending = []warpgate.TicketRequest{req("r1", "u-claude", "t-forge-rw", 3600, t0, "x")}
	b.Tick(ctx, t0)
	b.Tick(ctx, t0.Add(16*time.Minute))
	if wg.denied["r1"] != "warpgate-approver: unanswered for more than 15m" {
		t.Errorf("denied = %v", wg.denied)
	}
	if len(n.sent) != 2 {
		t.Errorf("want request + denial notices, got %d", len(n.sent))
	}
}

func TestReportModeNeverDenies(t *testing.T) {
	b, wg, n, dir := setup(t, ModeReport)
	ctx := context.Background()
	wg.pending = []warpgate.TicketRequest{
		req("over", "u-claude", "t-files-01-admin", 7200, t0, "long"),
		req("ok", "u-claude", "t-forge-rw", 3600, t0, "fine"),
	}
	b.Tick(ctx, t0)
	b.Tick(ctx, t0.Add(16*time.Minute)) // "ok" now past the TTL: reported once, not denied
	b.Tick(ctx, t0.Add(17*time.Minute))
	if len(wg.denied) != 0 {
		t.Fatalf("report mode denied %v", wg.denied)
	}
	if len(n.sent) != 3 {
		t.Fatalf("want 2 request notices + 1 would-deny follow-up, got %d: %+v", len(n.sent), n.sent)
	}
	if !strings.Contains(n.sent[0].Body, "POLICY WOULD DENY: asks for 2h, over the 30m cap for admin") {
		t.Errorf("over-cap notice not flagged:\n%s", n.sent[0].Body)
	}
	if n.sent[1].TTL != 0 || strings.Contains(n.sent[1].Body, "unanswered by") {
		t.Errorf("report mode must not promise an automatic denial: %+v", n.sent[1])
	}
	if !strings.HasPrefix(n.sent[2].Title, "Policy would deny: claude on build-01-rw") {
		t.Errorf("follow-up %q", n.sent[2].Title)
	}
	if got := strings.Join(events(t, dir), " "); !strings.Contains(got, "would-deny:ok") {
		t.Errorf("audit = %s", got)
	}
}

func TestNameLookupFailureNeverDenies(t *testing.T) {
	b, wg, n, _ := setup(t, ModeEnforce)
	ctx := context.Background()
	wg.users = nil
	wg.usersErr = errors.New("HTTP 500")
	wg.pending = []warpgate.TicketRequest{req("r1", "u-claude", "t-forge-rw", 3600, t0, "x")}
	b.Tick(ctx, t0)
	if len(wg.denied) != 0 || len(n.sent) != 0 {
		t.Fatalf("lookup failure acted: denied %v sent %d", wg.denied, len(n.sent))
	}
	wg.users, wg.usersErr = map[string]string{"u-claude": "claude"}, nil
	b.Tick(ctx, t0.Add(5*time.Second))
	if len(wg.denied) != 0 || len(n.sent) != 1 {
		t.Fatalf("after recovery: denied %v sent %d", wg.denied, len(n.sent))
	}
}

func TestBurstIsCollapsed(t *testing.T) {
	b, wg, n, dir := setup(t, ModeReport)
	ctx := context.Background()
	for _, id := range []string{"a", "b", "c", "d", "e"} {
		wg.pending = append(wg.pending, req(id, "u-claude", "t-forge-rw", 600, t0, id))
	}
	b.Tick(ctx, t0)
	if len(n.sent) != 4 || n.sent[3].Title != "Ticket request burst" {
		t.Fatalf("want 3 notices + 1 burst warning, got %d: %+v", len(n.sent), n.sent)
	}
	b.Tick(ctx, t0.Add(5*time.Second))
	if len(n.sent) != 4 {
		t.Fatalf("suppressed requests re-notified: %d", len(n.sent))
	}
	got := strings.Join(events(t, dir), " ")
	if strings.Count(got, "notify-suppressed:") != 2 || !strings.Contains(got, "burst:") {
		t.Errorf("audit = %s", got)
	}
}

func TestNotificationRetry(t *testing.T) {
	b, wg, n, _ := setup(t, ModeReport)
	ctx := context.Background()
	wg.pending = []warpgate.TicketRequest{req("r1", "u-claude", "t-forge-rw", 600, t0, "x")}
	n.fail = true
	b.Tick(ctx, t0)
	n.fail = false
	b.Tick(ctx, t0.Add(10*time.Second)) // inside the 30s back-off
	if len(n.sent) != 0 {
		t.Fatalf("retried too early")
	}
	b.Tick(ctx, t0.Add(31*time.Second))
	if len(n.sent) != 1 {
		t.Fatalf("not retried: %d", len(n.sent))
	}
}

func TestWarpgateOutageAlertsOnceAndRecovers(t *testing.T) {
	b, wg, n, _ := setup(t, ModeEnforce)
	ctx := context.Background()
	wg.pollErr = fmt.Errorf("GET /ticket-requests: HTTP 401: %w", warpgate.ErrUnauthorized)
	b.Tick(ctx, t0)
	b.Tick(ctx, t0.Add(4*time.Minute))
	if len(n.sent) != 0 {
		t.Fatalf("alerted before ALERT_AFTER")
	}
	b.Tick(ctx, t0.Add(5*time.Minute))
	b.Tick(ctx, t0.Add(6*time.Minute))
	if len(n.sent) != 1 || !strings.Contains(n.sent[0].Body, "bastion-apply --mint-token approver") {
		t.Fatalf("want one alert naming the fix, got %+v", n.sent)
	}
	wg.pollErr = nil
	b.Tick(ctx, t0.Add(7*time.Minute))
	if len(n.sent) != 2 || !strings.Contains(n.sent[1].Title, "again") {
		t.Fatalf("no recovery notice: %+v", n.sent)
	}
}

func TestStateSurvivesRestart(t *testing.T) {
	b, wg, n, dir := setup(t, ModeReport)
	ctx := context.Background()
	wg.pending = []warpgate.TicketRequest{req("r1", "u-claude", "t-forge-rw", 600, t0, "x")}
	b.Tick(ctx, t0)
	b2 := newBroker(t, dir, ModeReport, wg, n)
	b2.Tick(ctx, t0.Add(time.Minute))
	if len(n.sent) != 1 {
		t.Fatalf("restart re-notified: %d", len(n.sent))
	}
}

func TestTokenExpiryWarning(t *testing.T) {
	b, wg, n, _ := setup(t, ModeReport)
	ctx := context.Background()
	wg.expiries = []time.Time{t0.Add(365 * 24 * time.Hour), t0.Add(10 * 24 * time.Hour)}
	b.Tick(ctx, t0)
	b.Tick(ctx, t0.Add(time.Hour)) // checked at most daily
	if len(n.sent) != 1 || !strings.Contains(n.sent[0].Body, "in 10 days") {
		t.Fatalf("want one expiry warning, got %+v", n.sent)
	}
}
