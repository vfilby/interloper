// Command wga-hub is the clearing house's relay: the device/adapter API and the management UI.
//
// It holds no key that can approve anything (docs/PROTOCOL.md). Two listeners:
//
//	-api   :8740            devices and adapters (LAN/VPN; later the off-network path)
//	-admin 127.0.0.1:8741   management UI
//	-url   http://…:8740    the API base URL devices should use; goes into the enrollment link
//	-state ./hub-data       state.json and audit.jsonl
//
// Sign-in to the management UI (and phone sign-in) is OIDC, e.g. Authelia (docs/runbooks/oidc.md):
//
//	-oidc-issuer        https://sso.home.example
//	-oidc-client-id     interloper
//	-oidc-secret-file   file holding the client secret
//	-oidc-redirect      https://<management UI host>/oidc/callback (registered at the provider)
//	-oidc-admin-group   interloper_admins
//	-session-key-file   32+ random bytes signing session cookies (made on first start if missing)
//
// Without -oidc-issuer there is no sign-in at all (everyone is an admin): the hub then refuses to start unless the
// management UI listens on loopback only.
package main

import (
	"context"
	"crypto/rand"
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

	"warpgate-approver/broker/internal/apns"
	"warpgate-approver/broker/internal/audit"
	"warpgate-approver/broker/internal/hub"
)

type config struct {
	apiAddr, adminAddr, hubURL, stateDir                        string
	issuer, clientID, secretFile, redirect, adminGroup, keyFile string
	apnsKeyFile, apnsKeyID, apnsTeamID, apnsTopic               string
}

func main() {
	var c config
	flag.StringVar(&c.apiAddr, "api", ":8740", "device and adapter API listen address")
	flag.StringVar(&c.adminAddr, "admin", "127.0.0.1:8741", "management UI listen address")
	flag.StringVar(&c.hubURL, "url", "http://127.0.0.1:8740", "API base URL as devices reach it")
	flag.StringVar(&c.stateDir, "state", "hub-data", "state directory")
	flag.StringVar(&c.issuer, "oidc-issuer", "", "OIDC issuer URL; empty: no sign-in (loopback only)")
	flag.StringVar(&c.clientID, "oidc-client-id", "interloper", "OIDC client id")
	flag.StringVar(&c.secretFile, "oidc-secret-file", "", "file holding the OIDC client secret")
	flag.StringVar(&c.redirect, "oidc-redirect", "", "OIDC redirect URL: https://<management UI host>/oidc/callback")
	flag.StringVar(&c.adminGroup, "oidc-admin-group", "interloper_admins", "group whose members are admins")
	flag.StringVar(&c.keyFile, "session-key-file", "", "session signing key file (default <state>/session.key)")
	flag.StringVar(&c.apnsKeyFile, "apns-key-file", "", "APNs auth key (.p8); empty: no push notifications")
	flag.StringVar(&c.apnsKeyID, "apns-key-id", "", "the APNs key's Key ID")
	flag.StringVar(&c.apnsTeamID, "apns-team-id", "43DNX2P3T6", "Apple developer team id")
	flag.StringVar(&c.apnsTopic, "apns-topic", "com.eff3.interloper", "the app's bundle id")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, c); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, c config) error {
	if err := os.MkdirAll(c.stateDir, 0o700); err != nil {
		return err
	}
	auth, err := setupAuth(c)
	if err != nil {
		return err
	}
	st, err := hub.Open(filepath.Join(c.stateDir, "state.json"))
	if err != nil {
		return err
	}
	auditPath := filepath.Join(c.stateDir, "audit.jsonl")
	a, err := audit.Open(auditPath)
	if err != nil {
		return err
	}
	defer a.Close()

	var push hub.Pusher
	if c.apnsKeyFile != "" {
		key, err := apns.LoadKey(c.apnsKeyFile)
		if err != nil {
			return err
		}
		if c.apnsKeyID == "" {
			return errors.New("-apns-key-id is required with -apns-key-file")
		}
		push = &apns.Client{KeyID: c.apnsKeyID, TeamID: c.apnsTeamID, Topic: c.apnsTopic, Key: key}
	}
	api := &http.Server{Addr: c.apiAddr, Handler: (&hub.API{Store: st, Audit: a, Log: log, Push: push}).Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	admin := &http.Server{Addr: c.adminAddr, ReadHeaderTimeout: 10 * time.Second,
		Handler: (&hub.Admin{Store: st, Audit: a, AuditPath: auditPath, HubURL: c.hubURL, Log: log, Auth: auth}).Handler()}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	errc := make(chan error, 2)
	for _, s := range []*http.Server{api, admin} {
		go func() {
			if err := s.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				errc <- err
			}
		}()
	}
	mode := "oidc " + c.issuer
	if auth.Local {
		mode = "local (no sign-in)"
	}
	log.Info("started", "api", c.apiAddr, "admin", c.adminAddr, "url", c.hubURL, "state", c.stateDir, "sign-in", mode,
		"push", push != nil)
	select {
	case <-ctx.Done():
	case err := <-errc:
		return err
	}
	sctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = api.Shutdown(sctx)
	_ = admin.Shutdown(sctx)
	log.Info("stopped")
	return nil
}

func setupAuth(c config) (*hub.Auth, error) {
	if c.issuer == "" {
		host, _, err := net.SplitHostPort(c.adminAddr)
		if ip := net.ParseIP(host); err != nil || ip == nil || !ip.IsLoopback() {
			return nil, fmt.Errorf("no -oidc-issuer: the management UI would have no sign-in, so -admin must be a loopback address (got %q)", c.adminAddr)
		}
		return hub.LocalAuth(), nil
	}
	if c.secretFile == "" || c.redirect == "" {
		return nil, errors.New("-oidc-issuer needs -oidc-secret-file and -oidc-redirect")
	}
	secret, err := os.ReadFile(c.secretFile)
	if err != nil {
		return nil, err
	}
	key, err := sessionKey(c)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	return hub.NewOIDC(ctx, c.issuer, c.clientID, strings.TrimSpace(string(secret)), c.redirect, c.adminGroup, key)
}

// sessionKey reads the cookie-signing key, making one on first start. Replacing it signs everyone out.
func sessionKey(c config) ([]byte, error) {
	path := c.keyFile
	if path == "" {
		path = filepath.Join(c.stateDir, "session.key")
	}
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		b = make([]byte, 32)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		return b, os.WriteFile(path, b, 0o600)
	}
	return b, err
}
