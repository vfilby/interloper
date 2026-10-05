package hub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"warpgate-approver/broker/internal/protocol"
	"warpgate-approver/broker/internal/softdevice"
)

func TestAdminCSRF(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := (&Admin{Store: st, HubURL: "http://hub.test:8740"}).Handler()

	cases := []struct {
		name    string
		headers map[string]string
		want    int
	}{
		// What browsers really send for the UI's own form posts.
		{"browser same-origin, Origin null", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "null"}, http.StatusSeeOther},
		{"browser same-origin", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:8741"}, http.StatusSeeOther},
		{"behind a proxy (Host differs)", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://interpose-hub.home.example"}, http.StatusSeeOther},
		{"curl", nil, http.StatusSeeOther},
		{"old browser, matching Origin", map[string]string{"Origin": "http://127.0.0.1:8741"}, http.StatusSeeOther},
		// Attacks.
		{"cross-site", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, http.StatusForbidden},
		{"same-site other origin", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://other.home.example"}, http.StatusForbidden},
		{"old browser, foreign Origin", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"old browser, Origin null", map[string]string{"Origin": "null"}, http.StatusForbidden},
	}
	for _, c := range cases {
		req := newUserForm("vince")
		for k, v := range c.headers {
			req.Header.Set(k, v)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s: got %d, want %d (%s)", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
}

// newUserForm is the overview's "New user" form post.
func newUserForm(user string) *http.Request {
	return enrollForm(user, ModeNew)
}

func enrollForm(user, mode string) *http.Request {
	req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8741/enroll",
		strings.NewReader(url.Values{"user": {user}, "mode": {mode}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return req
}

// The enroll page follows its code: a new user's first phone (device and account fingerprints, the trust-add-user
// command), then a second phone that waits for approval and is shown as approved once a phone on the roster admits it.
func TestEnrollPageFollowsTheCode(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := (&Admin{Store: st, HubURL: "http://hub.test:8740"}).Handler()
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8741"+path, nil))
		return rec.Code, rec.Body.String()
	}
	issue := func(req *http.Request) (loc, code string) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		loc = rec.Header().Get("Location")
		if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/enroll/") {
			t.Fatalf("POST /enroll: %d %q\n%s", rec.Code, loc, rec.Body.String())
		}
		_, body := get(loc)
		if strings.Contains(body, `http-equiv="refresh"`) {
			t.Fatal("the enroll page itself reloads: the link cannot be copied")
		}
		m := regexp.MustCompile(`code=([A-Za-z0-9_-]+)&amp;user=([a-z0-9._-]+)&amp;mode=(new|join)`).FindStringSubmatch(body)
		if m == nil {
			t.Fatalf("no code/user/mode in the page\n%s", body)
		}
		return loc, m[1]
	}
	now := time.Now()

	// First phone of a new user.
	loc, code := issue(newUserForm("vince"))
	if _, status := get(loc + "/status"); !strings.Contains(status, `http-equiv="refresh"`) || !strings.Contains(status, "Waiting") {
		t.Fatalf("status box while waiting:\n%s", status)
	}
	a, _ := softdevice.New("phone A")
	cardA, _ := a.Card(now)
	genesis, _ := a.Genesis("vince", now)
	if _, err := st.Enroll(code, cardA, &genesis, now); err != nil {
		t.Fatal(err)
	}
	head, _ := protocol.VerifyChain([]protocol.Envelope{genesis}, "vince", "")
	pubA, _ := a.Approve.PublicKey.Bytes()
	_, body := get(loc)
	for _, want := range []string{protocol.Fingerprint(pubA), head.Account, "trust add-user", "phone A"} {
		if !strings.Contains(body, want) {
			t.Fatalf("new-user page lacks %q\n%s", want, body)
		}
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8741"+loc+"/status", nil))
	if strings.Contains(rec.Body.String(), `http-equiv="refresh"`) {
		t.Fatal("status box keeps reloading after a new user's phone enrolled")
	}
	if csp := rec.Header().Get("Content-Security-Policy"); !strings.Contains(csp, "frame-ancestors 'self'") {
		t.Fatalf("status box CSP %q", csp)
	}

	// A second phone joins: it waits until phone A admits it.
	loc, code = issue(enrollForm("vince", ModeJoin))
	b, _ := softdevice.New("phone B")
	cardB, _ := b.Card(now)
	if e, err := st.Enroll(code, cardB, nil, now); err != nil || e.Active {
		t.Fatalf("join: %+v %v", e, err)
	}
	_, status := get(loc + "/status")
	if !strings.Contains(status, "waiting for approval") || !strings.Contains(status, `http-equiv="refresh"`) {
		t.Fatalf("pending join status:\n%s", status)
	}
	next, _ := a.Admit(head, cardB, now)
	if _, err := st.AppendRoster("vince", next); err != nil {
		t.Fatal(err)
	}
	_, status = get(loc + "/status")
	if strings.Contains(status, `http-equiv="refresh"`) || !strings.Contains(status, "is on vince's roster") {
		t.Fatalf("approved join status:\n%s", status)
	}

	if code, _ := get("/enroll/unknown"); code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", code)
	}
	// The overview lists the user with its account fingerprint and both phones.
	_, body = get("/")
	pubB, _ := b.Approve.PublicKey.Bytes()
	for _, want := range []string{head.Account, protocol.Fingerprint(pubA), protocol.Fingerprint(pubB), "roster v2"} {
		if !strings.Contains(body, want) {
			t.Fatalf("overview lacks %q", want)
		}
	}
}

func TestAppHello(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	(&Admin{Store: st, HubURL: "http://hub.test:8740"}).Handler().ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8741/app/hello", nil))
	var hello map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &hello); err != nil || hello["service"] != "interloper" || hello["signin"] != "local" || hello["api"] != "http://hub.test:8740" {
		t.Fatalf("hello: %d %s", rec.Code, rec.Body.String())
	}
}
