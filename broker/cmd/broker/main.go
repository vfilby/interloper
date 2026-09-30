// Command broker watches Warpgate for ticket requests (phase 1: notify via Pushover, optionally deny by policy).
//
// Configuration is environment only; secrets are files (mounted read-only), never environment values:
//
//	WARPGATE_URL          https://bastion.home.example
//	WARPGATE_TOKEN_FILE   /run/secrets/warpgate-token    the approver user's API token (bastion-apply --mint-token approver)
//	PUSHOVER_TOKEN_FILE   /run/secrets/pushover-token    Pushover application token
//	PUSHOVER_USER_FILE    /run/secrets/pushover-user     Pushover user key
//	STATE_DIR             /data                          state.json and audit.jsonl
//	POLICY_MODE           report                         report | enforce
//	ALLOWED_REQUESTERS    claude,helper
//	MAX_DURATION_RW       2h
//	MAX_DURATION_ADMIN    2h                             bastion-ssh asks for 2h on every tier; lower both together
//	REQUEST_TTL           15m                            enforce: unanswered longer than this is denied
//	POLL_INTERVAL         5s
//	NOTIFY_BURST          5                              request notifications per NOTIFY_WINDOW
//	NOTIFY_WINDOW         10m
//	ALERT_AFTER           5m                             Warpgate unreachable this long: alert
//	TOKEN_WARN            720h                           alert when the approver token expires within this
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
	_ "time/tzdata" // distroless has no zoneinfo; TZ comes from the environment

	"warpgate-approver/broker/internal/audit"
	"warpgate-approver/broker/internal/broker"
	"warpgate-approver/broker/internal/notify"
	"warpgate-approver/broker/internal/policy"
	"warpgate-approver/broker/internal/warpgate"
)

func main() {
	once := flag.Bool("once", false, "poll once and exit")
	check := flag.Bool("check-config", false, "validate configuration and secrets, then exit")
	flag.Parse()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	if err := run(log, *once, *check); err != nil {
		log.Error("fatal", "err", err)
		os.Exit(1)
	}
}

func run(log *slog.Logger, once, check bool) error {
	c := &env{}
	base := c.str("WARPGATE_URL", "https://bastion.home.example")
	wgToken := c.secret("WARPGATE_TOKEN_FILE", "/run/secrets/warpgate-token")
	poToken := c.secret("PUSHOVER_TOKEN_FILE", "/run/secrets/pushover-token")
	poUser := c.secret("PUSHOVER_USER_FILE", "/run/secrets/pushover-user")
	stateDir := c.str("STATE_DIR", "/data")
	mode := broker.Mode(c.str("POLICY_MODE", "report"))
	if mode != broker.ModeReport && mode != broker.ModeEnforce {
		c.fail("POLICY_MODE must be report or enforce, not %q", mode)
	}
	requesters := map[string]bool{}
	for _, r := range strings.Split(c.str("ALLOWED_REQUESTERS", "claude,helper"), ",") {
		if r = strings.TrimSpace(r); r != "" {
			requesters[r] = true
		}
	}
	cfg := broker.Config{
		Mode: mode,
		Policy: policy.Policy{
			Requesters: requesters,
			MaxDuration: map[policy.Tier]time.Duration{
				policy.TierRW:    c.dur("MAX_DURATION_RW", "2h"),
				policy.TierAdmin: c.dur("MAX_DURATION_ADMIN", "2h"),
			},
			TTL: c.dur("REQUEST_TTL", "15m"),
		},
		ApprovalURL:  strings.TrimRight(base, "/") + "/@warpgate/admin#/config/tickets",
		StateFile:    filepath.Join(stateDir, "state.json"),
		NotifyBurst:  c.int("NOTIFY_BURST", "5"),
		NotifyWindow: c.dur("NOTIFY_WINDOW", "10m"),
		AlertAfter:   c.dur("ALERT_AFTER", "5m"),
		TokenWarn:    c.dur("TOKEN_WARN", "720h"),
		RetryAfter:   30 * time.Second,
	}
	interval := c.dur("POLL_INTERVAL", "5s")
	if len(c.errs) > 0 {
		return fmt.Errorf("configuration:\n  %s", strings.Join(c.errs, "\n  "))
	}
	if check {
		fmt.Println("configuration ok")
		return nil
	}

	a, err := audit.Open(filepath.Join(stateDir, "audit.jsonl"))
	if err != nil {
		return err
	}
	defer a.Close()
	b, err := broker.New(cfg, warpgate.New(base, wgToken, nil), &notify.Pushover{Token: poToken, User: poUser}, a, log)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	log.Info("started", "mode", mode, "warpgate", base, "poll", interval.String(),
		"cap_rw", cfg.Policy.MaxDuration[policy.TierRW].String(), "cap_admin", cfg.Policy.MaxDuration[policy.TierAdmin].String(),
		"ttl", cfg.Policy.TTL.String())
	if once {
		if err := b.Tick(ctx, time.Now()); err != nil {
			return fmt.Errorf("poll failed: %w", err)
		}
		log.Info("poll ok")
		return nil
	}
	b.Run(ctx, interval)
	log.Info("stopped")
	return nil
}

// env collects every configuration error instead of stopping at the first.
type env struct{ errs []string }

func (c *env) fail(format string, a ...any) { c.errs = append(c.errs, fmt.Sprintf(format, a...)) }

func (c *env) str(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && strings.TrimSpace(v) != "" {
		return strings.TrimSpace(v)
	}
	return def
}

func (c *env) dur(key, def string) time.Duration {
	d, err := time.ParseDuration(c.str(key, def))
	if err != nil || d <= 0 {
		c.fail("%s: want a positive duration like 15m, got %q", key, c.str(key, def))
	}
	return d
}

func (c *env) int(key, def string) int {
	n, err := strconv.Atoi(c.str(key, def))
	if err != nil || n <= 0 {
		c.fail("%s: want a positive integer, got %q", key, c.str(key, def))
	}
	return n
}

func (c *env) secret(key, def string) string {
	path := c.str(key, def)
	b, err := os.ReadFile(path)
	if err != nil {
		c.fail("%s: %v", key, err)
		return ""
	}
	s := strings.TrimSpace(string(b))
	if s == "" {
		c.fail("%s: %s is empty", key, path)
	}
	return s
}
