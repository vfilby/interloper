// Command interpose-hub is the clearing house's relay: the device/adapter API and the management UI.
//
// It holds no key that can approve anything (docs/PROTOCOL.md). Two listeners:
//
//	-api   127.0.0.1:8740   devices and adapters (LAN/VPN; later the off-network path)
//	-admin 127.0.0.1:8741   management UI
//	-url   https://…        the API base URL devices should use; goes into the enrollment link
//	-state ./hub-data       state.json and audit.jsonl
//
// Sign-in to the management UI (and phone sign-in) is OIDC, e.g. Authelia (docs/runbooks/oidc.md):
//
//	-oidc-issuer        https://sso.home.example
//	-oidc-client-id     interpose
//	-oidc-secret-file   file holding the client secret
//	-oidc-redirect      https://<management UI host>/oidc/callback (registered at the provider)
//	-oidc-admin-group   interpose_admins
//	-session-key-file   32+ random bytes signing session cookies (made on first start if missing)
//
// Without -oidc-issuer there is no sign-in at all (everyone is an admin): the hub then refuses to start unless the
// management UI listens on loopback only.
//
// The hub speaks plain HTTP; TLS is the reverse proxy's job. Tokens and enrollment codes must not cross a network in
// the clear, so the hub refuses to start with a non-loopback -api unless -url is https (that is, a proxy terminates
// TLS in front of it), and with an http -oidc-redirect unless it names a loopback host.
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
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/vfilby/interpose/broker/internal/apns"
	"github.com/vfilby/interpose/broker/internal/hub"
	"github.com/vfilby/interpose/internal/audit"
)

type config struct {
	apiAddr, adminAddr, hubURL, stateDir                        string
	issuer, clientID, secretFile, redirect, adminGroup, keyFile string
	apnsKeyFile, apnsKeyID, apnsTeamID, apnsTopic               string
}

func main() {
	var c config
	flag.StringVar(&c.apiAddr, "api", "127.0.0.1:8740", "device and adapter API listen address (non-loopback needs an https -url)")
	flag.StringVar(&c.adminAddr, "admin", "127.0.0.1:8741", "management UI listen address")
	flag.StringVar(&c.hubURL, "url", "http://127.0.0.1:8740", "API base URL as devices reach it (https unless -api is loopback)")
	flag.StringVar(&c.stateDir, "state", "hub-data", "state directory")
	flag.StringVar(&c.issuer, "oidc-issuer", "", "OIDC issuer URL; empty: no sign-in (loopback only)")
	flag.StringVar(&c.clientID, "oidc-client-id", "interpose", "OIDC client id")
	flag.StringVar(&c.secretFile, "oidc-secret-file", "", "file holding the OIDC client secret")
	flag.StringVar(&c.redirect, "oidc-redirect", "", "OIDC redirect URL: https://<management UI host>/oidc/callback")
	flag.StringVar(&c.adminGroup, "oidc-admin-group", "interpose_admins", "group whose members are admins")
	flag.StringVar(&c.keyFile, "session-key-file", "", "session signing key file (default <state>/session.key)")
	flag.StringVar(&c.apnsKeyFile, "apns-key-file", "", "APNs auth key (.p8); empty: no push notifications")
	flag.StringVar(&c.apnsKeyID, "apns-key-id", "", "the APNs key's Key ID")
	flag.StringVar(&c.apnsTeamID, "apns-team-id", "", "Apple developer team id (required with -apns-key-file)")
	flag.StringVar(&c.apnsTopic, "apns-topic", "com.eff3.interloper", "the app's bundle id")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, c); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, c config) error {
	if err := checkTransport(c); err != nil {
		return err
	}
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
		if c.apnsTeamID == "" {
			return errors.New("-apns-team-id is required with -apns-key-file")
		}
		push = &apns.Client{KeyID: c.apnsKeyID, TeamID: c.apnsTeamID, Topic: c.apnsTopic, Key: key}
	}
	// Timeouts bound how long a slow client can hold a connection (MaxBytesReader bounds only bytes). The API's
	// WriteTimeout leaves room for the decisions long-poll.
	apiHandler := &hub.API{Store: st, Audit: a, Log: log, Push: push}
	api := &http.Server{Addr: c.apiAddr, Handler: apiHandler.Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second,
		WriteTimeout: apiHandler.MaxWait + 30*time.Second, IdleTimeout: 2 * time.Minute}
	admin := &http.Server{Addr: c.adminAddr,
		Handler:           (&hub.Admin{Store: st, Audit: a, AuditPath: auditPath, HubURL: c.hubURL, Log: log, Auth: auth}).Handler(),
		ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: time.Minute,
		IdleTimeout: 2 * time.Minute}

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

// checkTransport refuses configurations that would carry bearer tokens, enrollment codes or session cookies over
// plain HTTP across a network: a non-loopback API whose devices are told an http URL, and an http OIDC redirect to a
// host other than loopback (the session cookie is Secure only over https).
func checkTransport(c config) error {
	u, err := url.Parse(c.hubURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("-url must be an http(s) URL (got %q)", c.hubURL)
	}
	if !loopbackAddr(c.apiAddr) && u.Scheme != "https" {
		return fmt.Errorf("-api %q is not loopback, so -url must be https (a reverse proxy terminating TLS in front of the hub); got %q", c.apiAddr, c.hubURL)
	}
	if c.redirect != "" {
		r, err := url.Parse(c.redirect)
		if err != nil || r.Host == "" {
			return fmt.Errorf("-oidc-redirect must be an absolute URL (got %q)", c.redirect)
		}
		if r.Scheme != "https" && !(r.Scheme == "http" && loopbackHost(r.Hostname())) {
			return fmt.Errorf("-oidc-redirect must be https unless it is on loopback (got %q)", c.redirect)
		}
	}
	return nil
}

// loopbackAddr reports whether a listen address binds loopback only (":8740" binds every interface).
func loopbackAddr(addr string) bool {
	host, _, err := net.SplitHostPort(addr)
	ip := net.ParseIP(host)
	return err == nil && ip != nil && ip.IsLoopback()
}

func loopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func setupAuth(c config) (*hub.Auth, error) {
	if c.issuer == "" {
		if !loopbackAddr(c.adminAddr) {
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
