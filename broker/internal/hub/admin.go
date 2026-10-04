package hub

import (
	"bufio"
	"embed"
	"encoding/base64"
	"encoding/json"
	"html/template"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"rsc.io/qr"

	"warpgate-approver/broker/internal/audit"
	"warpgate-approver/broker/internal/protocol"
)

//go:embed templates/*.html
var templatesFS embed.FS

var tmpl = template.Must(template.New("").Funcs(template.FuncMap{
	"fp": func(b64 string) string {
		raw, err := protocol.UnB64(b64)
		if err != nil {
			return "?"
		}
		return protocol.Fingerprint(raw)
	},
	"cardfp": func(e protocol.Envelope) string {
		p, err := e.PayloadBytes()
		var c protocol.DeviceCard
		if err != nil || json.Unmarshal(p, &c) != nil {
			return "?"
		}
		raw, _ := protocol.UnB64(c.ApproveKey)
		return protocol.Fingerprint(raw)
	},
	"ago": func(t time.Time) string {
		if t.IsZero() {
			return "never"
		}
		return time.Since(t).Round(time.Second).String() + " ago"
	},
	"unix":    func(s int64) string { return time.Unix(s, 0).Local().Format("Jan 2 15:04:05") },
	"expired": func(s int64) bool { return time.Now().Unix() > s },
}).ParseFS(templatesFS, "templates/*.html"))

// Admin is the management UI. It must only be reachable from the LAN/VPN and only behind an authenticating proxy
// (a Warpgate HTTP target or Authelia): it has no login of its own. What it can do is bounded on purpose: enroll a
// device for transport, revoke, register an adapter for transport. None of that makes a device trusted by an
// adapter, so taking over this UI does not let anyone approve anything.
type Admin struct {
	Store     *Store
	Audit     *audit.Log
	AuditPath string
	HubURL    string // what devices use, put into the enrollment link
	Log       *slog.Logger
}

func (a *Admin) Handler() http.Handler {
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", a.index)
	m.HandleFunc("POST /enroll", a.enroll)
	m.HandleFunc("GET /devices/{id}/card.json", a.card)
	m.HandleFunc("POST /devices/{id}/revoke", a.revoke)
	m.HandleFunc("POST /adapters", a.addAdapter)
	m.HandleFunc("POST /adapters/{id}/remove", a.removeAdapter)
	m.HandleFunc("GET /audit", a.audit)
	return sameOrigin(securityHeaders(m))
}

// sameOrigin refuses cross-site form posts (CSRF): the proxy in front authenticates by cookie.
//
// Sec-Fetch-Site decides when present: every current browser sends it and a page cannot forge it. Origin is only the
// fallback for browsers without it. Origin is not compared first because it can be "null" for a genuine same-origin
// post (privacy settings, referrer policies), and behind a proxy the Host header may not be the name in the address bar.
func sameOrigin(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOriginRequest(r) {
			http.Error(w, "cross-site request refused", http.StatusForbidden)
			return
		}
		h.ServeHTTP(w, r)
	})
}

func sameOriginRequest(r *http.Request) bool {
	if s := r.Header.Get("Sec-Fetch-Site"); s != "" {
		return s == "same-origin" || s == "none"
	}
	switch o := r.Header.Get("Origin"); o {
	case "":
		return true // not a browser (curl, scripts): CSRF needs a browser carrying the person's cookie
	case "null":
		return false // a browser hiding its origin, without Sec-Fetch-Site to vouch for it
	default:
		u, err := url.Parse(o)
		return err == nil && u.Host == r.Host
	}
}

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; img-src data:; form-action 'self'; frame-ancestors 'none'")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin") // not no-referrer: that makes browsers send "Origin: null"
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

type page struct {
	Title    string
	Adapters []Adapter
	Devices  []Device
	Requests []Request
	Flash    string
	// enrollment
	Link   string
	QR     template.URL
	Expiry time.Time
	// adapter added
	NewAdapter, NewToken string
	// audit
	Lines []string
}

func (a *Admin) render(w http.ResponseWriter, name string, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, p); err != nil && a.Log != nil {
		a.Log.Error("template", "name", name, "err", err)
	}
}

func (a *Admin) overview(flash string) page {
	return page{Title: "Clearing house", Adapters: a.Store.Adapters(), Devices: a.Store.Devices(), Requests: a.Store.Requests(), Flash: flash}
}

func (a *Admin) index(w http.ResponseWriter, _ *http.Request) {
	a.render(w, "index.html", a.overview(""))
}

func (a *Admin) enroll(w http.ResponseWriter, _ *http.Request) {
	now := time.Now()
	code, err := a.Store.NewEnrollCode(now)
	if err != nil {
		a.render(w, "index.html", a.overview(err.Error()))
		return
	}
	link := "wga://enroll?hub=" + url.QueryEscape(a.HubURL) + "&code=" + url.QueryEscape(code)
	p := page{Title: "Enroll a device", Link: link, Expiry: now.Add(EnrollCodeTTL)}
	if c, err := qr.Encode(link, qr.M); err == nil {
		c.Scale = 6
		p.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG()))
	}
	a.write(audit.Event{Time: now, Event: "enroll-code-issued"})
	a.render(w, "enroll.html", p)
}

func (a *Admin) card(w http.ResponseWriter, r *http.Request) {
	d, ok := a.Store.Device(r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", `attachment; filename="device-`+d.ID+`.json"`)
	_ = json.NewEncoder(w).Encode(d.Card)
}

func (a *Admin) revoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	flash := "Revoked " + id + " at the hub. Also remove it from every adapter: wga-adapter trust remove " + id
	if err := a.Store.RevokeDevice(id); err != nil {
		flash = err.Error()
	} else {
		a.write(audit.Event{Time: time.Now(), Event: "device-revoked", Device: id})
	}
	a.render(w, "index.html", a.overview(flash))
}

func (a *Admin) addAdapter(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.FormValue("id"))
	key := strings.TrimSpace(r.FormValue("key"))
	tok, err := a.Store.AddAdapter(id, key, time.Now())
	if err != nil {
		a.render(w, "index.html", a.overview("Adding adapter: "+err.Error()))
		return
	}
	a.write(audit.Event{Time: time.Now(), Event: "adapter-added", Adapter: id, Detail: "key " + key})
	p := a.overview("")
	p.NewAdapter, p.NewToken = id, tok
	a.render(w, "index.html", p)
}

func (a *Admin) removeAdapter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	flash := "Removed adapter " + id
	if err := a.Store.RemoveAdapter(id); err != nil {
		flash = err.Error()
	} else {
		a.write(audit.Event{Time: time.Now(), Event: "adapter-removed", Adapter: id})
	}
	a.render(w, "index.html", a.overview(flash))
}

// audit shows the last 200 lines of the hub's audit log.
func (a *Admin) audit(w http.ResponseWriter, _ *http.Request) {
	p := page{Title: "Hub audit"}
	if f, err := os.Open(a.AuditPath); err == nil {
		defer f.Close()
		var lines []string
		sc := bufio.NewScanner(io.LimitReader(f, 16<<20))
		for sc.Scan() {
			lines = append(lines, sc.Text())
			if len(lines) > 400 {
				lines = lines[200:]
			}
		}
		if len(lines) > 200 {
			lines = lines[len(lines)-200:]
		}
		for i, j := 0, len(lines)-1; i < j; i, j = i+1, j-1 {
			lines[i], lines[j] = lines[j], lines[i]
		}
		p.Lines = lines
	}
	a.render(w, "audit.html", p)
}

func (a *Admin) write(e audit.Event) {
	if a.Audit == nil {
		return
	}
	if err := a.Audit.Write(e); err != nil && a.Log != nil {
		a.Log.Error("audit write failed", "event", e.Event, "err", err)
	}
}
