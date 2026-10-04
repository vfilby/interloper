package hub

import (
	"net/http"
	"net/http/httptest"
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
		{"behind a proxy (Host differs)", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://approvals.home.example"}, http.StatusSeeOther},
		{"curl", nil, http.StatusSeeOther},
		{"old browser, matching Origin", map[string]string{"Origin": "http://127.0.0.1:8741"}, http.StatusSeeOther},
		// Attacks.
		{"cross-site", map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example"}, http.StatusForbidden},
		{"same-site other origin", map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "https://other.home.example"}, http.StatusForbidden},
		{"old browser, foreign Origin", map[string]string{"Origin": "https://evil.example"}, http.StatusForbidden},
		{"old browser, Origin null", map[string]string{"Origin": "null"}, http.StatusForbidden},
	}
	for _, c := range cases {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8741/enroll", nil)
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

// The enroll page follows its code: QR and self-refresh while waiting, then the device and its fingerprint.
func TestEnrollPageShowsFingerprint(t *testing.T) {
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

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8741/enroll", nil))
	loc := rec.Header().Get("Location")
	if rec.Code != http.StatusSeeOther || !strings.HasPrefix(loc, "/enroll/") {
		t.Fatalf("POST /enroll: %d %q", rec.Code, loc)
	}
	code, body := get(loc)
	if code != http.StatusOK || !strings.Contains(body, `http-equiv="refresh"`) || !strings.Contains(body, "wga://enroll?") {
		t.Fatalf("waiting page: %d\n%s", code, body)
	}
	m := regexp.MustCompile(`code=([A-Za-z0-9_-]+)`).FindStringSubmatch(body)
	if m == nil {
		t.Fatal("no code in the page")
	}

	d, _ := softdevice.New("test phone")
	card, _ := d.Card(time.Now())
	if _, _, err := st.Enroll(m[1], card, time.Now()); err != nil {
		t.Fatal(err)
	}
	pub, _ := d.Approve.PublicKey.Bytes()
	code, body = get(loc)
	if code != http.StatusOK || !strings.Contains(body, protocol.Fingerprint(pub)) || !strings.Contains(body, "test phone") {
		t.Fatalf("enrolled page lacks the device or its fingerprint: %d\n%s", code, body)
	}
	if strings.Contains(body, `http-equiv="refresh"`) || strings.Contains(body, "wga://enroll?") {
		t.Fatal("enrolled page still refreshes or still shows the spent code")
	}
	if code, _ := get("/enroll/unknown"); code != http.StatusNotFound {
		t.Fatalf("unknown id: %d", code)
	}
}
