package hub

import (
	"path/filepath"
	"testing"
	"time"

	"warpgate-approver/broker/internal/softdevice"
)

func TestReEnroll(t *testing.T) {
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	d, _ := softdevice.New("phone")
	card, _ := d.Card(now)
	enroll := func() string {
		t.Helper()
		code, err := st.NewEnrollCode(now)
		if err != nil {
			t.Fatal(err)
		}
		_, tok, err := st.Enroll(code, card, now)
		if err != nil {
			t.Fatal(err)
		}
		return tok
	}

	first := enroll()
	second := enroll() // the phone left this hub and came back
	if _, ok := st.DeviceByToken(first, now); ok {
		t.Fatal("the old token still works after re-enrolling")
	}
	if _, ok := st.DeviceByToken(second, now); !ok {
		t.Fatal("the new token does not work")
	}

	if err := st.RevokeDevice(d.ID()); err != nil {
		t.Fatal(err)
	}
	if _, ok := st.DeviceByToken(second, now); ok {
		t.Fatal("revoked device's token still works")
	}
	third := enroll() // only a fresh admin-issued code brings it back
	if _, ok := st.DeviceByToken(third, now); !ok {
		t.Fatal("re-enrolling after revocation failed")
	}

	// A code is still single-use.
	code, _ := st.NewEnrollCode(now)
	if _, _, err := st.Enroll(code, card, now); err != nil {
		t.Fatal(err)
	}
	if _, _, err := st.Enroll(code, card, now); err == nil {
		t.Fatal("a spent code enrolled again")
	}
}
