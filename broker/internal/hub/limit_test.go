package hub

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vfilby/interpose/internal/audit"
	"github.com/vfilby/interpose/internal/protocol"
	"github.com/vfilby/interpose/internal/softdevice"
)

func TestFailLimiter(t *testing.T) {
	l := newFailLimiter(3, time.Minute)
	now := time.Now()
	for i := range 3 {
		if ok, _ := l.allow("a", now); !ok {
			t.Fatalf("attempt %d refused", i)
		}
		l.fail("a", now)
	}
	if ok, first := l.allow("a", now); ok || !first {
		t.Fatalf("after the burst: ok=%v first=%v", ok, first)
	}
	if ok, first := l.allow("a", now); ok || first {
		t.Fatalf("again: ok=%v first=%v, want refused and not first", ok, first)
	}
	if ok, _ := l.allow("b", now); !ok {
		t.Fatal("another client is refused")
	}
	if ok, _ := l.allow("a", now.Add(time.Minute)); !ok {
		t.Fatal("no token back after a minute")
	}
	l.fail("a", now.Add(time.Minute))
	if ok, first := l.allow("a", now.Add(time.Minute)); ok || !first {
		t.Fatalf("a new episode: ok=%v first=%v", ok, first)
	}
}

func TestFailLimiterBounded(t *testing.T) {
	l := newFailLimiter(3, time.Minute)
	now := time.Now()
	for i := range maxLimitClients + 10 {
		l.fail(fmt.Sprint(i), now)
	}
	if n := len(l.clients); n > maxLimitClients {
		t.Fatalf("%d clients kept", n)
	}
}

func TestClientIP(t *testing.T) {
	proxies, err := ParsePrefixes("127.0.0.1, 10.0.0.0/8")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrefixes("nope"); err == nil {
		t.Fatal("ParsePrefixes accepted junk")
	}
	for _, c := range []struct {
		name, remote, xff string
		trusted           []netip.Prefix
		want              string
	}{
		{"direct", "203.0.113.7:5000", "", nil, "203.0.113.7"},
		{"untrusted peer's header is ignored", "203.0.113.7:5000", "198.51.100.1", proxies, "203.0.113.7"},
		{"behind the proxy", "127.0.0.1:5000", "198.51.100.1", proxies, "198.51.100.1"},
		{"a forged hop to the left is ignored", "127.0.0.1:5000", "1.2.3.4, 198.51.100.1", proxies, "198.51.100.1"},
		{"two trusted proxies", "127.0.0.1:5000", "198.51.100.1, 10.1.2.3", proxies, "198.51.100.1"},
		{"proxy without a header", "127.0.0.1:5000", "", proxies, "127.0.0.1"},
		{"no proxies trusted", "127.0.0.1:5000", "198.51.100.1", nil, "127.0.0.1"},
		{"IPv6 by /64", "[2001:db8:1:2:3:4:5:6]:5000", "", nil, "2001:db8:1:2::/64"},
	} {
		r := httptest.NewRequest("POST", "/v1/enroll", nil)
		r.RemoteAddr = c.remote
		if c.xff != "" {
			r.Header.Set("X-Forwarded-For", c.xff)
		}
		if got := clientIP(r, c.trusted); got != c.want {
			t.Errorf("%s: %q, want %q", c.name, got, c.want)
		}
	}
}

func TestClip(t *testing.T) {
	if got := clip("short", 64); got != "short" {
		t.Fatal(got)
	}
	if got := clip(strings.Repeat("x", 100), 10); got != strings.Repeat("x", 10)+"…" {
		t.Fatal(got)
	}
	if got := clip("ééééé", 3); got != "é…" { // 2-byte runes: cut at a boundary
		t.Fatalf("%q", got)
	}
}

// Failed enrollments are unauthenticated: their audit lines are short, and a client that keeps failing is refused
// (with one line saying so) instead of writing a line per attempt.
func TestEnrollFailuresAreBounded(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.jsonl")
	al, err := audit.Open(logPath)
	if err != nil {
		t.Fatal(err)
	}
	defer al.Close()
	h := (&API{Store: st, Audit: al}).Handler()
	enroll := func(remote string, body any) int {
		b, _ := json.Marshal(body)
		r := httptest.NewRequest("POST", "/v1/enroll", bytes.NewReader(b))
		r.RemoteAddr = remote
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w.Code
	}
	huge := map[string]any{"code": "nope", "card": protocol.Envelope{Kid: strings.Repeat("K", 200<<10)}}
	for i := range EnrollFailBurst {
		if code := enroll("203.0.113.7:1", huge); code != http.StatusForbidden {
			t.Fatalf("attempt %d: %d", i, code)
		}
	}
	for range 50 {
		if code := enroll("203.0.113.7:1", huge); code != http.StatusTooManyRequests {
			t.Fatalf("past the burst: %d", code)
		}
	}
	// Another client still gets to try, and a good code still enrolls.
	if code := enroll("198.51.100.1:1", huge); code != http.StatusForbidden {
		t.Fatalf("another client: %d", code)
	}
	d, _ := softdevice.New("phone")
	card, _ := d.Card(time.Now())
	code, _, _ := st.NewEnrollCode(time.Now(), "vince", ModeNew)
	genesis, err := d.Genesis("vince", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if c := enroll("198.51.100.1:1", map[string]any{"code": code, "card": card, "genesis": genesis}); c != http.StatusOK {
		t.Fatalf("good enrollment: %d", c)
	}

	raw, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	counts := map[string]int{}
	for _, l := range lines {
		if len(l) > 512 {
			t.Fatalf("audit line of %d bytes", len(l))
		}
		var e audit.Event
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		counts[e.Event]++
	}
	if counts["enroll-failed"] != EnrollFailBurst+1 || counts["enroll-limited"] != 1 || counts["enrolled"] != 1 {
		t.Fatalf("audit events: %v", counts)
	}
}

func TestEnrollRefusesLongNames(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	d, _ := softdevice.New(strings.Repeat("n", MaxDeviceName+1))
	card, _ := d.Card(now)
	genesis, err := d.Genesis("vince", now)
	if err != nil {
		t.Fatal(err)
	}
	code, _, _ := st.NewEnrollCode(now, "vince", ModeNew)
	if _, err := st.Enroll(code, card, &genesis, now); err == nil || !strings.Contains(err.Error(), "name") {
		t.Fatalf("long name: %v", err)
	}
}

func TestTailLines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	write := func(s string) {
		if err := os.WriteFile(path, []byte(s), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var b strings.Builder
	for i := range 100000 {
		fmt.Fprintf(&b, "line %d\n", i)
	}
	write(b.String()) // ~1 MB: more than the first chunk

	lines, note, err := tailLines(path, 200, 16<<20)
	if err != nil || note != "" || len(lines) != 200 || lines[0] != "line 99800" || lines[199] != "line 99999" {
		t.Fatalf("tail: %d lines, %q..%q, note %q, err %v", len(lines), lines[0], lines[len(lines)-1], note, err)
	}
	// A small file is read whole.
	write("a\nb\n")
	if lines, note, err := tailLines(path, 200, 16<<20); err != nil || note != "" || strings.Join(lines, ",") != "a,b" {
		t.Fatalf("small: %v %q %v", lines, note, err)
	}
	// A huge line does not stop the reader; it is shown cut, and the lines after it are there.
	write("old\n" + strings.Repeat("x", 100<<10) + "\nnew\n")
	lines, _, err = tailLines(path, 200, 16<<20)
	if err != nil || len(lines) != 3 || lines[2] != "new" || !strings.Contains(lines[1], "[line cut: 102400 bytes]") ||
		len(lines[1]) > auditLineMax+100 {
		t.Fatalf("long line: %d lines, err %v", len(lines), err)
	}
	// More log than the reader may look at: the newest lines it can see, and a note.
	write(strings.Repeat("y", 300<<10) + "\nnewest\n")
	lines, note, err = tailLines(path, 200, 256<<10)
	if err != nil || len(lines) != 1 || lines[0] != "newest" || note == "" {
		t.Fatalf("capped: %v %q %v", lines, note, err)
	}
	if _, _, err := tailLines(filepath.Join(t.TempDir(), "missing"), 200, 16<<20); !os.IsNotExist(err) {
		t.Fatalf("missing: %v", err)
	}
}

// The audit page shows the end of the log, newest first, however long the log has grown.
func TestAdminAuditPageShowsTheTail(t *testing.T) {
	dir := t.TempDir()
	st, err := Open(filepath.Join(dir, "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "audit.jsonl")
	var b strings.Builder
	for i := range 5000 {
		fmt.Fprintf(&b, "event-%d\n", i)
	}
	if err := os.WriteFile(path, []byte(b.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	h := (&Admin{Store: st, AuditPath: path, HubURL: "http://hub.test:8740"}).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "http://127.0.0.1:8741/audit", nil))
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "event-4999\nevent-4998") || !strings.Contains(body, "event-4800\n") ||
		strings.Contains(body, "event-4799\n") {
		t.Fatalf("%d\n%s", rec.Code, body)
	}
}
