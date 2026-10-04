package hub

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"warpgate-approver/broker/internal/protocol"
	"warpgate-approver/broker/internal/softdevice"
)

// account is a user with phones A (genesis) and B (admitted), enrolled at a fresh store.
type account struct {
	st         *Store
	a, b       *softdevice.Device
	tokA, tokB string
	now        time.Time
}

func newAccount(t *testing.T, user string) account {
	t.Helper()
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	a, _ := softdevice.New("phone A")
	b, _ := softdevice.New("phone B")
	cardA, _ := a.Card(now)
	cardB, _ := b.Card(now)
	g, _ := a.Genesis(user, now)
	code, _, _ := st.NewEnrollCode(now, user, ModeNew)
	ea, err := st.Enroll(code, cardA, &g, now)
	if err != nil {
		t.Fatal(err)
	}
	code, _, _ = st.NewEnrollCode(now, user, ModeJoin)
	eb, err := st.Enroll(code, cardB, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	next, _ := a.Admit(headOf(t, st, user), cardB, now)
	if _, err := st.AppendRoster(user, next); err != nil {
		t.Fatal(err)
	}
	return account{st, a, b, ea.Token, eb.Token, now}
}

func headOf(t *testing.T, st *Store, user string) protocol.Head {
	t.Helper()
	chain, ok := st.Chain(user)
	if !ok {
		t.Fatalf("no chain for %s", user)
	}
	h, err := protocol.VerifyChain(chain, user, "")
	if err != nil {
		t.Fatal(err)
	}
	return h
}

// Break glass: an admin deletes an account none of whose phones can approve any more; the user starts again as new.
func TestDeleteUser(t *testing.T) {
	acc := newAccount(t, "vince")
	st := acc.st
	if err := st.RevokeDevice(acc.a.ID()); err != nil {
		t.Fatal(err)
	}
	if err := st.RevokeDevice(acc.b.ID()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.NewEnrollCode(acc.now, "vince", ModeNew); err == nil {
		t.Fatal("a new account over an existing one")
	}
	pending, _, _ := st.NewEnrollCode(acc.now, "vince", ModeJoin)

	gone, err := st.DeleteUser("vince")
	if err != nil || len(gone) != 2 {
		t.Fatalf("delete: %v %v", gone, err)
	}
	if _, ok := st.Chain("vince"); ok || len(st.Devices()) != 0 || len(st.Users()) != 0 {
		t.Fatal("the account or its devices survived")
	}
	c, _ := softdevice.New("phone C")
	cardC, _ := c.Card(acc.now)
	if _, err := st.Enroll(pending, cardC, nil, acc.now); err == nil {
		t.Fatal("a join code of the deleted account still works")
	}
	g, _ := c.Genesis("vince", acc.now)
	code, _, err := st.NewEnrollCode(acc.now, "vince", ModeNew)
	if err != nil {
		t.Fatal(err)
	}
	if e, err := st.Enroll(code, cardC, &g, acc.now); err != nil || !e.Active {
		t.Fatalf("new account after delete: %+v %v", e, err)
	}
	if _, err := st.DeleteUser("nobody"); err != ErrUnknown {
		t.Fatalf("unknown user: %v", err)
	}
}

func TestRemoveRevokedDevices(t *testing.T) {
	acc := newAccount(t, "vince")
	if gone, err := acc.st.RemoveRevokedDevices(); err != nil || len(gone) != 0 {
		t.Fatalf("nothing revoked: %v %v", gone, err)
	}
	_ = acc.st.RevokeDevice(acc.b.ID())
	gone, err := acc.st.RemoveRevokedDevices()
	if err != nil || len(gone) != 1 || gone[0] != acc.b.ID() {
		t.Fatalf("remove: %v %v", gone, err)
	}
	if ds := acc.st.Devices(); len(ds) != 1 || ds[0].ID != acc.a.ID() {
		t.Fatalf("left: %+v", ds)
	}
}

// A phone going away: off the roster by its own signature, or the whole account with its last phone.
func TestLeave(t *testing.T) {
	api := func(st *Store) http.Handler { return (&API{Store: st}).Handler() }
	leave := func(h http.Handler, tok string, body any) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/v1/device/leave", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	acc := newAccount(t, "vince")
	h := api(acc.st)
	head := headOf(t, acc.st, "vince")

	// B may not delete an account that A is still on, nor leave with a roster that keeps it.
	if rec := leave(h, acc.tokB, map[string]any{"delete_account": true}); rec.Code != http.StatusConflict {
		t.Fatalf("delete with two members: %d %s", rec.Code, rec.Body)
	}
	keep, _ := acc.a.Remove(head, acc.a.ID(), acc.now) // removes A, not B
	if rec := leave(h, acc.tokB, map[string]any{"roster": keep}); rec.Code != http.StatusConflict {
		t.Fatalf("roster that keeps the leaver: %d %s", rec.Code, rec.Body)
	}

	// B takes itself off the roster: its record goes, A carries on alone.
	self, _ := acc.b.Remove(head, acc.b.ID(), acc.now)
	if rec := leave(h, acc.tokB, map[string]any{"roster": self}); rec.Code != http.StatusNoContent {
		t.Fatalf("leave with roster: %d %s", rec.Code, rec.Body)
	}
	if _, ok := acc.st.Device(acc.b.ID()); ok {
		t.Fatal("B still listed")
	}
	if h2 := headOf(t, acc.st, "vince"); len(h2.Devices) != 1 || h2.Devices[acc.a.ID()].DeviceID == "" {
		t.Fatalf("head after B left: %+v", h2.Devices)
	}
	if rec := leave(h, acc.tokB, map[string]any{}); rec.Code != http.StatusUnauthorized {
		t.Fatalf("B's token after leaving: %d", rec.Code)
	}

	// A, the last phone, resets: the account goes with it.
	if rec := leave(h, acc.tokA, map[string]any{"delete_account": true}); rec.Code != http.StatusNoContent {
		t.Fatalf("last device deletes the account: %d %s", rec.Code, rec.Body)
	}
	if _, ok := acc.st.Chain("vince"); ok || len(acc.st.Devices()) != 0 {
		t.Fatal("account survived its last device")
	}

	// Leaving without touching the roster: the record goes, the roster stays, and the phone can come back.
	acc = newAccount(t, "kim")
	h = api(acc.st)
	if rec := leave(h, acc.tokB, map[string]any{}); rec.Code != http.StatusNoContent {
		t.Fatalf("plain leave: %d %s", rec.Code, rec.Body)
	}
	if _, ok := acc.st.Device(acc.b.ID()); ok || len(headOf(t, acc.st, "kim").Devices) != 2 {
		t.Fatal("plain leave: record kept or roster changed")
	}
	code, _, _ := acc.st.NewEnrollCode(acc.now, "kim", ModeJoin)
	cardB, _ := acc.b.Card(acc.now)
	if e, err := acc.st.Enroll(code, cardB, nil, acc.now); err != nil || !e.Active {
		t.Fatalf("coming back: %+v %v", e, err)
	}
}

// The admin's break-glass forms: admins only, and deleting needs the user id typed.
func TestAdminDeleteUserForm(t *testing.T) {
	acc := newAccount(t, "vince")
	h := (&Admin{Store: acc.st, HubURL: "http://hub.test:8740"}).Handler() // local mode: admin
	post := func(path string, form url.Values) string {
		req := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8741"+path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	if body := post("/users/vince/delete", url.Values{"confirm": {"vinc"}}); !strings.Contains(body, "Not deleted") {
		t.Fatal("deleted without the typed confirmation")
	}
	if _, ok := acc.st.Chain("vince"); !ok {
		t.Fatal("account gone without confirmation")
	}
	if body := post("/users/vince/delete", url.Values{"confirm": {"vince"}}); !strings.Contains(body, "Deleted account vince") {
		t.Fatalf("delete: %s", body)
	}
	if _, ok := acc.st.Chain("vince"); ok {
		t.Fatal("account still there")
	}
}
