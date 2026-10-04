// Command wga-hub is the clearing house's relay: the device/adapter API and the management UI.
//
// It holds no key that can approve anything (docs/PROTOCOL.md). Two listeners:
//
//	-api   :8740            devices and adapters (LAN/VPN; later the off-network path)
//	-admin 127.0.0.1:8741   management UI: no login of its own, publish it only behind Warpgate or Authelia
//	-url   http://…:8740    the API base URL devices should use; goes into the enrollment link
//	-state ./hub-data       state.json and audit.jsonl
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"warpgate-approver/broker/internal/audit"
	"warpgate-approver/broker/internal/hub"
)

func main() {
	apiAddr := flag.String("api", ":8740", "device and adapter API listen address")
	adminAddr := flag.String("admin", "127.0.0.1:8741", "management UI listen address (put an authenticating proxy in front)")
	hubURL := flag.String("url", "http://127.0.0.1:8740", "API base URL as devices reach it")
	stateDir := flag.String("state", "hub-data", "state directory")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, *apiAddr, *adminAddr, *hubURL, *stateDir); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, apiAddr, adminAddr, hubURL, stateDir string) error {
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return err
	}
	st, err := hub.Open(filepath.Join(stateDir, "state.json"))
	if err != nil {
		return err
	}
	auditPath := filepath.Join(stateDir, "audit.jsonl")
	a, err := audit.Open(auditPath)
	if err != nil {
		return err
	}
	defer a.Close()

	api := &http.Server{Addr: apiAddr, Handler: (&hub.API{Store: st, Audit: a, Log: log}).Handler(),
		ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	admin := &http.Server{Addr: adminAddr, Handler: (&hub.Admin{Store: st, Audit: a, AuditPath: auditPath, HubURL: hubURL, Log: log}).Handler(),
		ReadHeaderTimeout: 10 * time.Second}

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
	log.Info("started", "api", apiAddr, "admin", adminAddr, "url", hubURL, "state", stateDir)
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
