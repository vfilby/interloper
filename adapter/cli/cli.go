// Package cli is the command line every adapter binary shares. An adapter's main supplies its Source; the key, the
// trust list, the hub connection and the run loop are the same for all of them:
//
//	PROG key   [-dir D]                         create the signing key if missing; print the public key to register at the hub
//	PROG trust add-user [-dir D] USER ACCOUNT   trust a user's devices (ACCOUNT: their account fingerprint)
//	PROG trust remove-user [-dir D] USER
//	PROG trust list [-dir D]                    users, and the devices on their last verified roster
//	PROG run -id ID -hub URL [-source S] [-dir D] [source flags]
//
// The directory holds signing.key (0400), trusted-users.json, trusted-heads.json (verified rosters), hub-token (0400,
// from the hub's management UI), state.json and audit.jsonl.
package cli

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vfilby/interloper/adapter"
	"github.com/vfilby/interloper/internal/audit"
	"github.com/vfilby/interloper/internal/protocol"
)

// Source is one service an adapter binary can guard.
type Source struct {
	Name string
	// Flags registers the source's own flags on the run command, and returns what builds the source once they are
	// parsed. The constructor may start helpers that stop when ctx ends.
	Flags func(fs *flag.FlagSet) func(ctx context.Context, log *slog.Logger) (adapter.Source, error)
}

// Main runs the command line for prog and exits. The first source is the default for -source.
func Main(prog string, sources ...Source) {
	if len(sources) == 0 {
		panic("cli.Main: no sources")
	}
	c := &cmd{prog: prog, sources: sources}
	if len(os.Args) < 2 {
		c.usage()
	}
	var err error
	switch os.Args[1] {
	case "key":
		err = c.key(os.Args[2:])
	case "trust":
		err = c.trust(os.Args[2:])
	case "run":
		err = c.run(os.Args[2:])
	default:
		c.usage()
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		os.Exit(1)
	}
}

type cmd struct {
	prog    string
	sources []Source
}

func (c *cmd) usage() {
	fmt.Fprintf(os.Stderr, "usage: %s key [-dir D] | trust add-user [-dir D] USER ACCOUNT | trust remove-user [-dir D] USER | trust list [-dir D] | run [flags]  (flags before arguments)\n", c.prog)
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

func (c *cmd) key(args []string) error {
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

func (c *cmd) trust(args []string) error {
	if len(args) < 1 {
		c.usage()
	}
	fs := flag.NewFlagSet("trust", flag.ExitOnError)
	dir := fs.String("dir", "adapter-data", "adapter directory")
	_ = fs.Parse(args[1:])
	switch args[0] {
	case "add-user":
		if fs.NArg() != 2 {
			c.usage()
		}
		if err := os.MkdirAll(*dir, 0o700); err != nil {
			return err
		}
		if err := adapter.TrustAddUser(*dir, fs.Arg(0), fs.Arg(1)); err != nil {
			return err
		}
		fmt.Printf("trusting user %s, account %s\n(the running adapter picks it up on its next poll; check the account fingerprint against the phone)\n", fs.Arg(0), fs.Arg(1))
	case "remove-user":
		if fs.NArg() != 1 {
			c.usage()
		}
		return adapter.TrustRemoveUser(*dir, fs.Arg(0))
	case "list":
		t, err := adapter.LoadTrust(*dir)
		if err != nil {
			return err
		}
		pins, heads := t.Pins()
		for _, p := range pins {
			h, ok := heads[p.User]
			if !ok {
				fmt.Printf("%s  account %s  (roster not verified yet)\n", p.User, p.Account)
				continue
			}
			fmt.Printf("%s  account %s  roster v%d\n", p.User, p.Account, h.Roster.Seq)
			for _, c := range h.Devices {
				ak, _ := protocol.UnB64(c.ApproveKey)
				fmt.Printf("    %s  %q\n", protocol.Fingerprint(ak), c.Name)
			}
		}
	default:
		c.usage()
	}
	return nil
}

func (c *cmd) run(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	dir := fs.String("dir", "adapter-data", "adapter directory")
	id := fs.String("id", "", "adapter id, as registered at the hub")
	names := make([]string, len(c.sources))
	builders := map[string]func(context.Context, *slog.Logger) (adapter.Source, error){}
	for i, s := range c.sources {
		names[i] = s.Name
		builders[s.Name] = s.Flags(fs)
	}
	source := fs.String("source", c.sources[0].Name, strings.Join(names, " | "))
	hubURL := fs.String("hub", "http://127.0.0.1:8740", "hub API base URL")
	ttl := fs.Duration("ttl", 15*time.Minute, "how long a request stays answerable")
	poll := fs.Duration("poll", 3*time.Second, "how often to poll the service")
	_ = fs.Parse(args)
	if *id == "" {
		return errors.New("-id is required")
	}
	build, ok := builders[*source]
	if !ok {
		return fmt.Errorf("unknown source %q (this binary has: %s)", *source, strings.Join(names, ", "))
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil)).With("adapter", *id)
	key, err := loadOrCreateKey(*dir, false)
	if err != nil {
		return fmt.Errorf("signing key (run `%s key` first): %w", c.prog, err)
	}
	tok, err := os.ReadFile(filepath.Join(*dir, "hub-token"))
	if err != nil {
		return fmt.Errorf("hub token (from the hub's management UI): %w", err)
	}
	trust, err := adapter.LoadTrust(*dir)
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

	src, err := build(ctx, log)
	if err != nil {
		return err
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
