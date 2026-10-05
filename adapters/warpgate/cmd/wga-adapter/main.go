// Command wga-adapter is the Warpgate adapter: the shared adapter command line (adapter/cli, `wga-adapter key | trust
// | run`) with the Warpgate Source. It runs beside Warpgate and holds a Warpgate token that can approve and deny
// ticket requests.
//
// Warpgate settings come from the environment: WARPGATE_URL, WARPGATE_TOKEN_FILE, ALLOWED_REQUESTERS,
// MAX_DURATION_RW, MAX_DURATION_ADMIN, REQUEST_TTL (deploy/adapter.env.default describes each).
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/adapter/cli"
	"github.com/vfilby/interpose/adapters/warpgate"
	"github.com/vfilby/interpose/adapters/warpgate/policy"
	"github.com/vfilby/interpose/adapters/warpgate/wgapi"
)

func main() {
	cli.Main("wga-adapter", cli.Source{Name: "warpgate", Flags: func(*flag.FlagSet) func(context.Context, *slog.Logger) (adapter.Source, error) {
		return func(context.Context, *slog.Logger) (adapter.Source, error) { return warpgateSource() }
	}})
}

func warpgateSource() (*warpgate.Source, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}
	dur := func(k, def string) (time.Duration, error) { return time.ParseDuration(get(k, def)) }
	base := get("WARPGATE_URL", "")
	if base == "" {
		return nil, errors.New("WARPGATE_URL is required (the Warpgate base URL, e.g. https://bastion.example)")
	}
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
	for _, r := range strings.Split(get("ALLOWED_REQUESTERS", ""), ",") {
		if r = strings.TrimSpace(r); r != "" {
			reqs[r] = true
		}
	}
	if len(reqs) == 0 {
		return nil, errors.New("ALLOWED_REQUESTERS is required: the Warpgate usernames that may ask for tickets, comma-separated")
	}
	return &warpgate.Source{
		WG: wgapi.New(base, strings.TrimSpace(string(tok)), nil),
		Policy: policy.Policy{Requesters: reqs, TTL: ttl,
			MaxDuration: map[policy.Tier]time.Duration{policy.TierRW: rw, policy.TierAdmin: adm}},
	}, nil
}
