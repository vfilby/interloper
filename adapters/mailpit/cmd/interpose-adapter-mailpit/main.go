// Command interpose-adapter-mailpit is the mail adapter: the shared adapter command line (adapter/cli,
// `interpose-adapter-mailpit key | trust | run`) with the Mailpit Source. It runs beside Mailpit and holds a Mailpit
// login, which can release held messages.
//
// Mailpit settings come from the environment: MAILPIT_URL, MAILPIT_USER, MAILPIT_PASSWORD_FILE, MAX_AGE
// (deploy/adapter.env.default describes each).
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
	"github.com/vfilby/interpose/adapters/mailpit"
	"github.com/vfilby/interpose/adapters/mailpit/mpapi"
)

func main() {
	cli.Main("interpose-adapter-mailpit", cli.Source{Name: "mailpit", Flags: func(*flag.FlagSet) func(context.Context, *slog.Logger) (adapter.Source, error) {
		return func(_ context.Context, log *slog.Logger) (adapter.Source, error) { return mailpitSource(log) }
	}})
}

func mailpitSource(log *slog.Logger) (*mailpit.Source, error) {
	get := func(k, def string) string {
		if v := strings.TrimSpace(os.Getenv(k)); v != "" {
			return v
		}
		return def
	}
	user := get("MAILPIT_USER", "")
	if user == "" {
		return nil, errors.New("MAILPIT_USER is required: the adapter's own login in Mailpit's ui-users file")
	}
	pass, err := os.ReadFile(get("MAILPIT_PASSWORD_FILE", "/run/secrets/mailpit-password"))
	if err != nil {
		return nil, err
	}
	maxAge, err := time.ParseDuration(get("MAX_AGE", "24h"))
	if err != nil {
		return nil, err
	}
	return &mailpit.Source{
		MP:     mpapi.New(get("MAILPIT_URL", "http://127.0.0.1:8025"), user, strings.TrimSpace(string(pass)), nil),
		MaxAge: maxAge,
		Log:    log,
	}, nil
}
