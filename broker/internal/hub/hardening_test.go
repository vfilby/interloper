package hub

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vfilby/interpose/internal/protocol"
	"github.com/vfilby/interpose/internal/softdevice"
)

// Without sign-in the UI answers only to loopback names: a rebinding page (evil.example resolving to 127.0.0.1) is
// same-origin to the browser and carries no cookie the hub could miss.
func TestLocalModeRefusesForeignHost(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := (&Admin{Store: st, HubURL: "http://127.0.0.1:8740"}).Handler()
	for host, want := range map[string]int{
		"127.0.0.1:8741":     http.StatusOK,
		"127.0.0.2:8741":     http.StatusOK,
		"localhost:8741":     http.StatusOK,
		"LocalHost":          http.StatusOK,
		"[::1]:8741":         http.StatusOK,
		"evil.example:8741":  http.StatusForbidden,
		"evil.example":       http.StatusForbidden,
		"localhost.evil.com": http.StatusForbidden,
		"192.0.2.1:8741":     http.StatusForbidden,
		"":                   http.StatusForbidden,
	} {
		for _, req := range []*http.Request{
			httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8741/", nil),
			func() *http.Request {
				r := newUserForm("vince")
				r.Header.Set("Sec-Fetch-Site", "same-origin")
				return r
			}(),
		} {
			req.Host = host
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			got := rec.Code
			if got == http.StatusSeeOther {
				got = http.StatusOK
			}
			if got != want {
				t.Errorf("%s %q: got %d, want %d", req.Method, host, rec.Code, want)
			}
		}
	}
}

// Open codes are capped per user: forged visits to /app/enroll (a GET) hold up only the victim's enrollment.
func TestEnrollCodesCappedPerUser(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	h := (&Admin{Store: st, HubURL: "http://127.0.0.1:8740"}).Handler()
	visit := func(user string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:8741/app/enroll?user="+user, nil))
		return rec.Code
	}
	for i := range MaxOpenCodesPerUser {
		if code := visit("vince"); code != http.StatusSeeOther {
			t.Fatalf("code %d: %d", i, code)
		}
	}
	if code := visit("vince"); code != http.StatusConflict {
		t.Fatalf("over the cap: %d", code)
	}
	if code := visit("kim"); code != http.StatusSeeOther {
		t.Fatalf("another user is held up: %d", code)
	}
	// Spent and expired codes do not count.
	now := time.Now().Add(EnrollCodeTTL + time.Second)
	if _, _, err := st.NewEnrollCode(now, "vince", ModeNew); err != nil {
		t.Fatalf("after expiry: %v", err)
	}
}

// A device revoked at the hub cannot undo that with a join code it issued itself; once an admin removes it from the
// list, it may enroll again.
func TestRevokedDeviceCannotReEnroll(t *testing.T) {
	acc := newAccount(t, "vince")
	st, now := acc.st, acc.now
	if err := st.RevokeDevice(acc.b.ID()); err != nil {
		t.Fatal(err)
	}
	cardB, _ := acc.b.Card(now)
	code, _, err := st.NewEnrollCode(now, "vince", ModeJoin)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Enroll(code, cardB, nil, now); err == nil || !strings.Contains(err.Error(), "revoked") {
		t.Fatalf("revoked device re-enrolled: %v", err)
	}
	if d, _ := st.Device(acc.b.ID()); !d.Revoked || d.TokenHash != "" {
		t.Fatalf("revocation undone: %+v", d)
	}
	if _, err := st.RemoveRevokedDevices(); err != nil {
		t.Fatal(err)
	}
	e, err := st.Enroll(code, cardB, nil, now) // the refused attempt did not spend the code
	if err != nil || !e.Active {
		t.Fatalf("after removal: %+v %v", e, err)
	}
}

// Publish keeps only boxes for devices the hub serves (so only those are woken) and caps expires_at.
func TestPublishDropsUnknownBoxesAndCapsExpiry(t *testing.T) {
	acc := newAccount(t, "vince")
	st, now := acc.st, acc.now
	if err := st.RevokeDevice(acc.b.ID()); err != nil {
		t.Fatal(err)
	}
	box := protocol.Sealed{Suite: protocol.SuiteHPKE, Enc: "e", CT: "c"}
	stranger, _ := softdevice.New("not enrolled")
	r := Request{ID: "r1", Kind: "k", ExpiresAt: now.Add(365 * 24 * time.Hour).Unix(),
		Boxes: map[string]protocol.Sealed{acc.a.ID(): box, acc.b.ID(): box, stranger.ID(): box, "made-up": box}}
	got, err := st.Publish("demo", r, now)
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Equal(got.Recipients, []string{acc.a.ID()}) {
		t.Fatalf("recipients %v", got.Recipients)
	}
	if want := now.Add(MaxRequestTTL).Unix(); got.ExpiresAt != want {
		t.Fatalf("expires_at %d, want %d", got.ExpiresAt, want)
	}
	if rs := st.ForDevice(acc.a.ID(), now); len(rs) != 1 || rs[0].ExpiresAt != got.ExpiresAt {
		t.Fatalf("for A: %+v", rs)
	}
	if rs := st.ForDevice(acc.a.ID(), now.Add(MaxRequestTTL+time.Second)); len(rs) != 0 {
		t.Fatalf("still offered after the cap: %+v", rs)
	}
	// An earlier expiry is kept as it is.
	soon := now.Add(time.Minute).Unix()
	if got, err := st.Publish("demo", Request{ID: "r2", ExpiresAt: soon, Boxes: map[string]protocol.Sealed{acc.a.ID(): box}}, now); err != nil || got.ExpiresAt != soon {
		t.Fatalf("r2: %+v %v", got, err)
	}
	// Nothing left to deliver: refused.
	if _, err := st.Publish("demo", Request{ID: "r3", ExpiresAt: soon, Boxes: map[string]protocol.Sealed{"made-up": box}}, now); err == nil {
		t.Fatal("published a request no device here can open")
	}
}
