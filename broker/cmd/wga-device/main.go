// Command wga-device is a software stand-in for the iPhone, for testing the hub and adapters on a LAN without the
// app. Its private keys are in a file: it must never be trusted by an adapter guarding anything real.
//
//	wga-device init    -f dev.json -name "test device"
//	wga-device enroll  -f dev.json 'wga://enroll?hub=…&code=…'   (pins the hub's adapter keys, first use)
//	wga-device card    -f dev.json > card.json                   (for `wga-adapter trust add`)
//	wga-device list    -f dev.json
//	wga-device approve -f dev.json REQUEST_ID
//	wga-device deny    -f dev.json REQUEST_ID
//	wga-device acks    -f dev.json
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

	"warpgate-approver/broker/internal/protocol"
	"warpgate-approver/broker/internal/softdevice"
)

// session is what the device keeps besides its keys: the hub, its token and the pinned adapter keys.
type session struct {
	Hub      string            `json:"hub"`
	Token    string            `json:"token"`
	Adapters map[string]string `json:"adapters"` // id -> b64 Ed25519 key, pinned on first use
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wga-device init|enroll|card|list|approve|deny|acks -f dev.json …")
		os.Exit(2)
	}
	fs := flag.NewFlagSet(os.Args[1], flag.ExitOnError)
	file := fs.String("f", "dev.json", "device key file")
	name := fs.String("name", "wga-device", "device name (init)")
	_ = fs.Parse(os.Args[2:])
	if err := run(os.Args[1], *file, *name, fs.Args()); err != nil {
		fmt.Fprintln(os.Stderr, "wga-device:", err)
		os.Exit(1)
	}
}

func run(cmd, file, name string, args []string) error {
	ctx := context.Background()
	if cmd == "init" {
		if _, err := os.Stat(file); err == nil {
			return fmt.Errorf("%s exists", file)
		}
		d, err := softdevice.New(name)
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
	case "card":
		c, err := d.Card(time.Now())
		if err != nil {
			return err
		}
		return json.NewEncoder(os.Stdout).Encode(c)

	case "enroll":
		if len(args) != 1 {
			return errors.New("enroll needs the wga://enroll link")
		}
		u, err := url.Parse(args[0])
		if err != nil || u.Scheme != "wga" || u.Host != "enroll" {
			return errors.New("not a wga://enroll link")
		}
		client = &softdevice.Client{Base: u.Query().Get("hub")}
		c, err := d.Card(time.Now())
		if err != nil {
			return err
		}
		id, err := client.Enroll(ctx, u.Query().Get("code"), c)
		if err != nil {
			return err
		}
		sess = session{Hub: client.Base, Token: client.Token, Adapters: map[string]string{}}
		if err := pin(ctx, client, &sess); err != nil {
			return err
		}
		fmt.Printf("enrolled as %s; approve key fingerprint %s\n", id, protocol.Fingerprint(mustPub(d)))
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
			e, err := d.Decide(o, cmd, time.Now())
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
