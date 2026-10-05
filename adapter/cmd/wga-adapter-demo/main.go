// Command wga-adapter-demo is the reference adapter: the shared adapter command line (adapter/cli) with the demo
// Source, which has no real service behind it. Requests are added over a loopback HTTP endpoint (-demo-listen) and
// "approving" only records the outcome. It is what the end-to-end tests run, and the shape to copy for a new adapter:
// a Source, and a main that hands it to cli.Main. See adapter/README.md.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/vfilby/interloper/adapter"
	"github.com/vfilby/interloper/adapter/cli"
	"github.com/vfilby/interloper/adapter/demo"
)

func main() {
	cli.Main("wga-adapter-demo", cli.Source{Name: "demo", Flags: demoFlags})
}

func demoFlags(fs *flag.FlagSet) func(context.Context, *slog.Logger) (adapter.Source, error) {
	addr := fs.String("demo-listen", "127.0.0.1:8749", "where to accept test requests (loopback only)")
	return func(ctx context.Context, log *slog.Logger) (adapter.Source, error) {
		host, _, _ := net.SplitHostPort(*addr)
		if ip := net.ParseIP(host); ip == nil || !ip.IsLoopback() {
			return nil, errors.New("-demo-listen must be a loopback address")
		}
		ln, err := net.Listen("tcp", *addr)
		if err != nil {
			return nil, err
		}
		d := demo.New()
		srv := &http.Server{Handler: d.Handler(), ReadHeaderTimeout: 10 * time.Second}
		go func() {
			if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Error("demo listener", "err", err)
			}
		}()
		go func() { <-ctx.Done(); srv.Close() }()
		log.Info("demo source", "add-requests-at", "http://"+*addr+"/requests")
		return d, nil
	}
}
