package hub

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
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
		{"browser same-origin, Origin null", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "null"}, http.StatusOK},
		{"browser same-origin", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://127.0.0.1:8741"}, http.StatusOK},
		{"behind a proxy (Host differs)", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "https://approvals.home.example"}, http.StatusOK},
		{"curl", nil, http.StatusOK},
		{"old browser, matching Origin", map[string]string{"Origin": "http://127.0.0.1:8741"}, http.StatusOK},
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
