// Command wga-adapter runs one clearing-house adapter next to the service it guards.
//
//	wga-adapter key   [-dir D]                 create the signing key if missing; print the public key to register at the hub
//	wga-adapter trust add [-dir D] CARD.json   trust a device (prints its fingerprint: compare with the phone)
//	wga-adapter trust remove [-dir D] DEVICE_ID
//	wga-adapter trust list [-dir D]
//	wga-adapter run -id ID -source demo|warpgate -hub URL [-dir D]
//
// The directory holds signing.key (0400), trusted-devices.json, hub-token (0400, from the hub's management UI),
// state.json and audit.jsonl. Warpgate source settings are the phase-1 broker's environment variables
// (WARPGATE_URL, WARPGATE_TOKEN_FILE, ALLOWED_REQUESTERS, MAX_DURATION_RW, MAX_DURATION_ADMIN, REQUEST_TTL).
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"warpgate-approver/broker/internal/adapter"
	"warpgate-approver/broker/internal/adapter/demo"
	"warpgate-approver/broker/internal/adapter/wgsource"
	"warpgate-approver/broker/internal/audit"
	"warpgate-approver/broker/internal/policy"
	"warpgate-approver/broker/internal/protocol"
	"warpgate-approver/broker/internal/warpgate"
)

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	var err error
	switch os.Args[1] {
	case "key":
		err = cmdKey(os.Args[2:])
	case "trust":
		err = cmdTrust(os.Args[2:])
	case "run":
		err = cmdRun(os.Args[2:])
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "wga-adapter:", err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, "usage: wga-adapter key [-dir D] | trust add [-dir D] CARD.json | trust remove [-dir D] ID | trust list [-dir D] | run [flags]  (flags before arguments)")
	os.Exit(2)
}

func loadOrCreateKey(dir string, create bool) (ed25519.PrivateKey, error) {
	p := filepath.Join(dir, "signing.key")
	b, err := os.ReadFile(p)
	if err == nil {
		seed, err := protocol.UnB64(strings.TrimSpace(string(b)))
		if err != nil || len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("%s is not a base64url Ed25519 seed", p)
		}
		return ed25519.NewKeyFromSeed(seed), nil
	}
	if !errors.Is(err, os.ErrNotExist) || !create {
		return nil, err
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	_, k, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	return k, os.WriteFile(p, []byte(protocol.B64(k.Seed())+"\n"), 0o400)
}

func cmdKey(args []string) error {
	fs := flag.NewFlagSet("key", flag.ExitOnError)
	dir := fs.String("dir", "adapter-data", "adapter directory")
	_ = fs.Parse(args)
	k, err := loadOrCreateKey(*dir, true)
	if err != nil {
		return err
	}
	pub := k.Public().(ed25519.PublicKey)
	fmt.Printf("public key:  %s\nfingerprint: %s\n", protocol.B64(pub), protocol.Fingerprint(pub))
	return nil
}

func cmdTrust(args []string) error {
	if len(args) < 1 {
		usage()
	}
	fs := flag.NewFlagSet("trust", flag.ExitOnError)
	dir := fs.String("dir", "adapter-data", "adapter directory")
	_ = fs.Parse(args[1:])
	path := filepath.Join(*dir, "trusted-devices.json")
	switch args[0] {
	case "add":
		if fs.NArg() != 1 {
			usage()
		}
		b, err := os.ReadFile(fs.Arg(0))
		if err != nil {
			return err
		}
		var e protocol.Envelope
		if err := json.Unmarshal(b, &e); err != nil {
			return err
		}
		if err := os.MkdirAll(*dir, 0o700); err != nil {
			return err
		}
		c, err := adapter.TrustAdd(path, e)
		if err != nil {
			return err
		}
		ak, _ := protocol.UnB64(c.ApproveKey)
		fmt.Printf("trusted %q (%s)\napprove key fingerprint: %s  <- must match the phone's Settings screen\n",
			c.Name, c.DeviceID, protocol.Fingerprint(ak))
	case "remove":
		if fs.NArg() != 1 {
			usage()
		}
		return adapter.TrustRemove(path, fs.Arg(0))
	case "list":
		t, err := adapter.LoadTrust(path)
		if err != nil {
			return err
		}
		for _, c := range t.Cards() {
			ak, _ := protocol.UnB64(c.ApproveKey)
			fmt.Printf("%s  %s  %q\n", c.DeviceID, protocol.Fingerprint(ak), c.Name)
		}
	default:
		usage()
	}
	return nil
}

func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dir := fs.String("dir", "adapter-data", "adapter directory")
	id := fs.String("id", "", "adapter id, as registered at the hub")
	source := fs.String("source", "demo", "demo | warpgate")
	hubURL := fs.String("hub", "http://127.0.0.1:8740", "hub API base URL")
	ttl := fs.Duration("ttl", 15*time.Minute, "how long a request stays answerable")
	poll := fs.Duration("poll", 3*time.Second, "how often to poll the service")
	demoAddr := fs.String("demo-listen", "127.0.0.1:8749", "demo source: where to accept test requests (loopback only)")
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("-id is required")
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("adapter", *id)
	key, err := loadOrCreateKey(*dir, false)
	if err != nil {
		return fmt.Errorf("signing key (run `wga-adapter key` first): %w", err)
	}
	tok, err := os.ReadFile(filepath.Join(*dir, "hub-token"))
	if err != nil {
		return fmt.Errorf("hub token (from the hub's management UI): %w", err)
	}
	trust, err := adapter.LoadTrust(filepath.Join(*dir, "trusted-devices.json"))
	if err != nil {
		return err
	}
	a, err := audit.Open(filepath.Join(*dir, "audit.jsonl"))
	if err != nil {
		return err
	}
	defer a.Close()

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	var src adapter.Source
	switch *source {
	case "demo":
		d := demo.New()
		host, _, _ := net.SplitHostPort(*demoAddr)
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return errors.New("-demo-listen must be a loopback address")
		}
		srv := &http.Server{Addr: *demoAddr, Handler: d.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("demo listener", "err", err)
				stop()
			}
		}()
		defer srv.Close()
		log.Info("demo source", "add-requests-at", "http://"+*demoAddr+"/requests")
		src = d
	case "warpgate":
		s, err := warpgateSource()
		if err != nil {
			return err
		}
		src = s
	default:
		return fmt.Errorf("unknown source %q", *source)
	}

	ad, err := adapter.New(adapter.Config{ID: *id, Key: key, StateFile: filepath.Join(*dir, "state.json"), TTL: *ttl, Poll: *poll},
		src, &adapter.HubClient{Base: *hubURL, Token: strings.TrimSpace(string(tok))}, trust, a, log)
	if err != nil {
		return err
	}
	pub := key.Public().(ed25519.PublicKey)
	log.Info("started", "source", *source, "hub", *hubURL, "key", protocol.Fingerprint(pub), "trusted_devices", len(trust.Cards()))
	ad.Run(ctx)
	log.Info("stopped")
	return nil
}

func warpgateSource() (*wgsource.Source, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}
	dur := func(k, def string) (time.Duration, error) { return time.ParseDuration(get(k, def)) }
	tok, err := os.ReadFile(get("WARPGATE_TOKEN_FILE", "/run/secrets/warpgate-token"))
	if err != nil {
		return nil, err
	}
	rw, err := dur("MAX_DURATION_RW", "2h")
	if err != nil {
		return nil, err
	}
	adm, err := dur("MAX_DURATION_ADMIN", "2h")
	if err != nil {
		return nil, err
	}
	ttl, err := dur("REQUEST_TTL", "15m")
	if err != nil {
		return nil, err
	}
	reqs := map[string]bool{}
	for _, r := range strings.Split(get("ALLOWED_REQUESTERS", "claude,helper"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			reqs[r] = true
		}
	}
	return &wgsource.Source{
		WG: warpgate.New(get("WARPGATE_URL", "https://bastion.home.example"), strings.TrimSpace(string(tok)), nil),
		Policy: policy.Policy{Requesters: reqs, TTL: ttl,
			MaxDuration: map[policy.Tier]time.Duration{policy.TierRW: rw, policy.TierAdmin: adm}},
	}, nil
}
