// Command interpose-device is a software stand-in for the iPhone, for testing the hub and adapters on a LAN without the
// app. Its private keys are in a file: it must never be trusted by an adapter guarding anything real.
//
//	interpose-device init    -f dev.json -name "test device"
//	interpose-device enroll  -f dev.json 'interpose://enroll?hub=…&code=…&user=…&mode=new|join'
//	interpose-device roster  -f dev.json                 (the user's verified devices; prints the account fingerprint)
//	interpose-device joins   -f dev.json                 (devices asking to join this user)
//	interpose-device admit   -f dev.json DEVICE_ID       (approve a join: sign the next roster with it)
//	interpose-device remove  -f dev.json DEVICE_ID       (sign the next roster without it)
//	interpose-device list    -f dev.json
//	interpose-device approve -f dev.json REQUEST_ID
//	interpose-device deny    -f dev.json REQUEST_ID
//	interpose-device acks    -f dev.json
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/url"
	"os"
	"time"

	"github.com/vfilby/interpose/internal/protocol"
	"github.com/vfilby/interpose/internal/softdevice"
)

// session is what the device keeps besides its keys: the hub, its token, the pinned adapter keys, and what it knows
// of its user's roster.
type session struct {
	Hub      string            `json:"hub"`
	Token    string            `json:"token"`
	Adapters map[string]string `json:"adapters"` // id -> b64 Ed25519 key, pinned on first use
	Roster   softdevice.Known  `json:"roster"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: interpose-device init|enroll|roster|joins|admit|remove|list|approve|deny|acks -f dev.json …")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	file := fs.String("f", "dev.json", "device key file")
	name := fs.String("name", "interpose-device", "device name (init)")
	_ = fs.Parse(os.Args[2:])
	if err := run(os.Args[1], *file, *name, fs.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "interpose-device:", err)
		os.Exit(1)
	}
}

func run(cmd, file, name string, args []string) error {
	ctx := context.Background()
	if cmd == "init" {
		if _, err := os.Stat(file); err == nil {
			return fmt.Errorf("%s exists", file)
		}
		d, err := softdevice.New(protocol.CleanDeviceName(name))
		if err != nil {
			return err
		}
		if err := d.Save(file); err != nil {
			return err
		}
		fmt.Printf("device %s\napprove key fingerprint: %s\n", d.ID(), protocol.Fingerprint(mustPub(d)))
		return nil
	}
	d, err := softdevice.Load(file)
	if err != nil {
		return err
	}
	sess := loadSession(file)
	client := &softdevice.Client{Base: sess.Hub, Token: sess.Token}

	switch cmd {
	case "enroll":
		if len(args) != 1 {
			return errors.New("enroll needs the interpose://enroll link")
		}
		u, err := url.Parse(args[0])
		if err != nil || u.Scheme != "interpose" || u.Host != "enroll" {
			return errors.New("not an interpose://enroll link")
		}
		q := u.Query()
		user, mode := q.Get("user"), q.Get("mode")
		client = &softdevice.Client{Base: q.Get("hub")}
		now := time.Now()
		c, err := d.Card(now)
		if err != nil {
			return err
		}
		var genesis *protocol.Envelope
		switch mode {
		case "new":
			g, err := d.Genesis(user, now)
			if err != nil {
				return err
			}
			genesis = &g
		case "join":
		default:
			return errors.New("the link has no mode: ask for a new code")
		}
		res, err := client.Enroll(ctx, q.Get("code"), c, genesis)
		if err != nil {
			return err
		}
		sess = session{Hub: client.Base, Token: client.Token, Adapters: map[string]string{}, Roster: softdevice.Known{User: res.User}}
		fmt.Printf("enrolled as %s for user %s (%s); device fingerprint %s\n", res.DeviceID, res.User, res.Status, protocol.Fingerprint(mustPub(d)))
		if res.Status == "active" {
			// A pending join is served its roster only: it pins adapters at its first list, once admitted.
			if err := pin(ctx, client, &sess); err != nil {
				return err
			}
			h, err := adopt(ctx, client, &sess)
			if err != nil {
				return err
			}
			fmt.Printf("account fingerprint %s\n", h.Account)
		} else {
			fmt.Printf("waiting for approval on another of %s's devices: compare the device fingerprint there\n", res.User)
		}
		return saveSession(file, sess)

	case "roster":
		h, err := adopt(ctx, client, &sess)
		if err != nil {
			return err
		}
		fmt.Printf("user %s  account %s  roster v%d\n", h.Roster.User, h.Account, h.Roster.Seq)
		for id, c := range h.Devices {
			ak, _ := protocol.UnB64(c.ApproveKey)
			me := ""
			if id == d.ID() {
				me = "  (this device)"
			}
			fmt.Printf("    %s  %s  %q%s\n", id, protocol.Fingerprint(ak), c.Name, me)
		}
		if _, in := h.Devices[d.ID()]; !in {
			fmt.Println("this device is not on the roster (waiting for approval, or removed)")
		}
		return saveSession(file, sess)

	case "joins":
		js, err := client.Joins(ctx)
		if err != nil {
			return err
		}
		for _, j := range js {
			c, err := protocol.VerifyCard(j.Card)
			if err != nil {
				fmt.Printf("%s  REFUSED: %v\n", j.DeviceID, err)
				continue
			}
			ak, _ := protocol.UnB64(c.ApproveKey)
			fmt.Printf("%s  %s  %q\n", c.DeviceID, protocol.Fingerprint(ak), c.Name)
		}
		if len(js) == 0 {
			fmt.Println("no join requests")
		}
		return nil

	case "admit", "remove":
		if len(args) != 1 {
			return errors.New("needs a device id")
		}
		h, err := adopt(ctx, client, &sess) // build only on our own verified copy of the chain
		if err != nil {
			return err
		}
		var next protocol.Envelope
		if cmd == "admit" {
			js, err := client.Joins(ctx)
			if err != nil {
				return err
			}
			var card *protocol.Envelope
			for _, j := range js {
				if j.DeviceID == args[0] && j.Card.Kid == args[0] {
					card = &j.Card
				}
			}
			if card == nil {
				return fmt.Errorf("no join request from %s", args[0])
			}
			if next, err = d.Admit(h, *card, time.Now()); err != nil {
				return err
			}
		} else {
			if _, ok := h.Devices[args[0]]; !ok {
				return fmt.Errorf("%s is not on the roster", args[0])
			}
			if len(h.Devices) == 1 {
				return errors.New("cannot remove the last device")
			}
			if next, err = d.Remove(h, args[0], time.Now()); err != nil {
				return err
			}
		}
		if err := client.PostRoster(ctx, next); err != nil {
			return err
		}
		h, err = adopt(ctx, client, &sess)
		if err != nil {
			return err
		}
		fmt.Printf("roster v%d: %d devices\n", h.Roster.Seq, len(h.Devices))
		return saveSession(file, sess)

	case "list":
		if err := pin(ctx, client, &sess); err != nil {
			return err
		}
		_ = saveSession(file, sess)
		reqs, err := client.Requests(ctx)
		if err != nil {
			return err
		}
		for _, r := range reqs {
			o, err := open(d, sess, r)
			if err != nil {
				fmt.Printf("%s  [%s]  REFUSED: %v\n", r.ID, r.Adapter, err)
				continue
			}
			rec := o.Record
			fmt.Printf("%s  [%s/%s risk=%s]  %s\n", r.ID, rec.Adapter, rec.Kind, rec.Risk, rec.Title)
			for _, f := range rec.Facts {
				fmt.Printf("    %-10s %s %s\n", f.Label+":", f.Value, f.Level)
			}
			if rec.OnBehalfOf != nil {
				fmt.Printf("    on behalf of %s (%s), attested by %s\n", rec.OnBehalfOf.Display, rec.OnBehalfOf.Principal, rec.OnBehalfOf.AttestedBy)
			}
			fmt.Printf("    reason given by %s: %q\n    expires %s\n", rec.Requester, rec.Reason, time.Unix(rec.ExpiresAt, 0).Format(time.Kitchen))
		}
		if len(reqs) == 0 {
			fmt.Println("nothing pending")
		}
		return nil

	case "approve", "deny":
		if len(args) != 1 {
			return errors.New("needs a request id")
		}
		reqs, err := client.Requests(ctx)
		if err != nil {
			return err
		}
		for _, r := range reqs {
			if r.ID != args[0] {
				continue
			}
			o, err := open(d, sess, r)
			if err != nil {
				return err
			}
			e, err := d.Decide(o, sess.Roster.User, cmd, time.Now())
			if err != nil {
				return err
			}
			if err := client.Decide(ctx, r.Adapter, r.ID, e); err != nil {
				return err
			}
			fmt.Println("sent; waiting for the adapter's ack…")
			return waitAck(ctx, client, sess, r.Adapter, r.ID)
		}
		return fmt.Errorf("request %s is not pending for this device", args[0])

	case "acks":
		acks, err := client.Acks(ctx, 0)
		if err != nil {
			return err
		}
		for _, a := range acks {
			printAck(sess, a)
		}
		return nil
	}
	return fmt.Errorf("unknown command %q", cmd)
}

// adopt fetches the user's chain and checks it against what this device knows (pin, no rollback, no fork).
func adopt(ctx context.Context, c *softdevice.Client, s *session) (protocol.Head, error) {
	chain, err := c.Roster(ctx)
	if err != nil {
		return protocol.Head{}, err
	}
	h, k, err := softdevice.Adopt(chain, s.Roster)
	if err != nil {
		return h, fmt.Errorf("roster refused: %w", err)
	}
	s.Roster = k
	return h, nil
}

func open(d *softdevice.Device, sess session, r softdevice.HubRequest) (softdevice.Opened, error) {
	k, ok := sess.Adapters[r.Adapter]
	if !ok {
		return softdevice.Opened{}, fmt.Errorf("adapter %s not pinned", r.Adapter)
	}
	raw, _ := protocol.UnB64(k)
	o, err := d.Read(r.Box, raw)
	if err != nil {
		return o, err
	}
	if o.Record.ID != r.ID || o.Record.Adapter != r.Adapter {
		return o, errors.New("hub listing does not match the signed record")
	}
	return o, nil
}

// pin adds adapter keys not seen before (trust on first use) and refuses changed ones.
func pin(ctx context.Context, c *softdevice.Client, s *session) error {
	ads, err := c.Adapters(ctx)
	if err != nil {
		return err
	}
	if s.Adapters == nil {
		s.Adapters = map[string]string{}
	}
	for _, a := range ads {
		old, ok := s.Adapters[a.ID]
		switch {
		case !ok:
			raw, _ := protocol.UnB64(a.Key)
			fmt.Fprintf(os.Stderr, "pinned adapter %s, key %s\n", a.ID, protocol.Fingerprint(raw))
			s.Adapters[a.ID] = a.Key
		case old != a.Key:
			fmt.Fprintf(os.Stderr, "WARNING: hub offers a different key for adapter %s; keeping the pinned one\n", a.ID)
		}
	}
	return nil
}

func waitAck(ctx context.Context, c *softdevice.Client, s session, adapter, id string) error {
	since := time.Now().Add(-5 * time.Second).Unix()
	for range 20 {
		acks, err := c.Acks(ctx, since)
		if err != nil {
			return err
		}
		for _, a := range acks {
			if a.Adapter == adapter && a.RequestID == id {
				printAck(s, a)
				return nil
			}
		}
		time.Sleep(time.Second)
	}
	fmt.Println("no ack yet (unconfirmed)")
	return nil
}

func printAck(s session, a softdevice.HubAck) {
	k, ok := s.Adapters[a.Adapter]
	raw, _ := protocol.UnB64(k)
	ack, err := softdevice.ReadAck(a.Ack, raw)
	if !ok || err != nil {
		fmt.Printf("%s  [%s]  UNCONFIRMED (ack does not verify)\n", a.RequestID, a.Adapter)
		return
	}
	fmt.Printf("%s  [%s]  %s: %s\n", a.RequestID, a.Adapter, ack.Outcome, ack.Detail)
}

func mustPub(d *softdevice.Device) []byte {
	b, _ := d.Approve.PublicKey.Bytes()
	return b
}

func loadSession(file string) session {
	var s session
	b, err := os.ReadFile(file + ".session")
	if err == nil {
		_ = json.Unmarshal(b, &s)
	}
	return s
}

func saveSession(file string, s session) error {
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(file+".session", b, 0o600)
}
