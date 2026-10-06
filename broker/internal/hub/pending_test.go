package hub

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vfilby/interpose/internal/softdevice"
)

// A device that enrolled with a join code holds a token, but until a member admits it the hub serves it only its
// roster (to learn when it is admitted) and a plain leave (to withdraw).
func TestPendingJoinIsServedOnlyItsRoster(t *testing.T) {
	acc := newAccount(t, "vince")
	h := (&API{Store: acc.st}).Handler()
	call := func(method, path, tok string, body any) *httptest.ResponseRecorder {
		t.Helper()
		var rd *bytes.Reader
		if body != nil {
			b, _ := json.Marshal(body)
			rd = bytes.NewReader(b)
		} else {
			rd = bytes.NewReader(nil)
		}
		req := httptest.NewRequest(method, path, rd)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	c, _ := softdevice.New("phone C")
	cardC, _ := c.Card(acc.now)
	code, _, _ := acc.st.NewEnrollCode(acc.now, "vince", ModeJoin)
	e, err := acc.st.Enroll(code, cardC, nil, acc.now)
	if err != nil || e.Active {
		t.Fatalf("join: %+v %v", e, err)
	}
	tokC := e.Token

	refused := []struct {
		method, path string
		body         any
	}{
		{http.MethodPost, "/v1/device/roster", map[string]any{}},
		{http.MethodPost, "/v1/device/push", map[string]string{"token": "aa", "environment": "production"}},
		{http.MethodGet, "/v1/device/joins", nil},
		{http.MethodGet, "/v1/device/adapters", nil},
		{http.MethodGet, "/v1/device/requests", nil},
		{http.MethodPost, "/v1/device/decisions", map[string]any{}},
		{http.MethodGet, "/v1/device/acks?since=0", nil},
		{http.MethodPost, "/v1/device/leave", map[string]any{"delete_account": true}},
		{http.MethodPost, "/v1/device/leave", map[string]any{"roster": map[string]any{}}},
	}
	for _, r := range refused {
		if rec := call(r.method, r.path, tokC, r.body); rec.Code != http.StatusForbidden {
			t.Errorf("pending %s %s: %d %s", r.method, r.path, rec.Code, rec.Body)
		}
	}
	if d, _ := acc.st.Device(c.ID()); d.PushToken != "" {
		t.Fatal("pending device registered a push token")
	}
	if rec := call(http.MethodGet, "/v1/device/roster", tokC, nil); rec.Code != http.StatusOK {
		t.Fatalf("pending roster: %d %s", rec.Code, rec.Body)
	}

	// A admits C: everything opens up.
	next, _ := acc.a.Admit(headOf(t, acc.st, "vince"), cardC, acc.now)
	if rec := call(http.MethodPost, "/v1/device/roster", acc.tokA, map[string]any{"roster": next}); rec.Code != http.StatusNoContent {
		t.Fatalf("admit: %d %s", rec.Code, rec.Body)
	}
	for _, p := range []string{"/v1/device/roster", "/v1/device/joins", "/v1/device/adapters", "/v1/device/requests", "/v1/device/acks?since=0"} {
		if rec := call(http.MethodGet, p, tokC, nil); rec.Code != http.StatusOK {
			t.Errorf("admitted GET %s: %d %s", p, rec.Code, rec.Body)
		}
	}

	// A pending device may withdraw its request.
	d, _ := softdevice.New("phone D")
	cardD, _ := d.Card(acc.now)
	code, _, _ = acc.st.NewEnrollCode(acc.now, "vince", ModeJoin)
	e, err = acc.st.Enroll(code, cardD, nil, acc.now)
	if err != nil {
		t.Fatal(err)
	}
	if rec := call(http.MethodPost, "/v1/device/leave", e.Token, map[string]any{}); rec.Code != http.StatusNoContent {
		t.Fatalf("pending withdraws: %d %s", rec.Code, rec.Body)
	}
	if _, ok := acc.st.Device(d.ID()); ok {
		t.Fatal("withdrawn join still listed")
	}
}
