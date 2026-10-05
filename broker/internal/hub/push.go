package hub

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/vfilby/interloper/broker/internal/apns"
	"github.com/vfilby/interloper/internal/audit"
)

// Pusher sends one wake-up to one device (apns.Client).
type Pusher interface {
	Send(ctx context.Context, deviceToken string, sandbox bool, n apns.Notification) error
}

// APNs device tokens are hex; 32 bytes today, longer allowed.
var pushTokenRE = regexp.MustCompile(`^[0-9a-f]{64,200}$`)

// SetPushToken records where to wake a device. An empty token stops pushes to it.
func (st *Store) SetPushToken(deviceID, token string, sandbox bool) error {
	if token != "" && !pushTokenRE.MatchString(token) {
		return errors.New("push token: lower-case hex, 64-200 characters")
	}
	st.mu.Lock()
	defer st.mu.Unlock()
	d, ok := st.s.Devices[deviceID]
	if !ok {
		return ErrUnknown
	}
	if d.PushToken == token && d.PushSandbox == sandbox {
		return nil
	}
	d.PushToken, d.PushSandbox = token, sandbox
	return st.commit()
}

// forgetPushToken drops a token APNs called dead, unless the device has registered another since.
func (st *Store) forgetPushToken(deviceID, token string) {
	st.mu.Lock()
	defer st.mu.Unlock()
	if d, ok := st.s.Devices[deviceID]; ok && d.PushToken == token {
		d.PushToken = ""
		_ = st.commit()
	}
}

type pushTarget struct {
	device, token string
	sandbox       bool
}

// pushTargets: the served devices among ids that have a push token.
func (st *Store) pushTargets(ids []string) []pushTarget {
	st.mu.Lock()
	defer st.mu.Unlock()
	var out []pushTarget
	for _, id := range ids {
		if d, ok := st.s.Devices[id]; ok && !d.Revoked && d.PushToken != "" {
			out = append(out, pushTarget{id, d.PushToken, d.PushSandbox})
		}
	}
	return out
}

// members: the device ids on a user's head roster.
func (st *Store) members(user string) []string {
	st.mu.Lock()
	defer st.mu.Unlock()
	u, ok := st.s.Users[user]
	if !ok {
		return nil
	}
	h, err := st.head(u)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(h.Devices))
	for id := range h.Devices {
		ids = append(ids, id)
	}
	return ids
}

// wake pushes a fixed notification to devices, in the background: a push is a hint, never part of a request's
// path, so failures are only logged. Tokens APNs reports dead are forgotten.
func (a *API) wake(ids []string, n apns.Notification) {
	if a.Push == nil || len(ids) == 0 {
		return
	}
	targets := a.Store.pushTargets(ids)
	if len(targets) == 0 {
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		for _, t := range targets {
			err := a.Push.Send(ctx, t.token, t.sandbox, n)
			switch {
			case errors.Is(err, apns.ErrUnregistered):
				a.Store.forgetPushToken(t.device, t.token)
				a.audit(audit.Event{Time: a.Now(), Event: "push-token-dropped", Device: t.device, Detail: err.Error()})
			case err != nil && a.Log != nil:
				a.Log.Warn("push", "device", t.device, "err", err)
			}
		}
		if a.pushed != nil {
			a.pushed <- struct{}{}
		}
	}()
}
