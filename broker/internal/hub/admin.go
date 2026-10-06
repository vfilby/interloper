package hub

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"rsc.io/qr"

	"github.com/vfilby/interpose/internal/audit"
	"github.com/vfilby/interpose/internal/protocol"
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

// Admin is the management UI, signed in through OIDC (Auth). Admins see and manage everything; everyone else sees
// their own account, issues codes for it and revokes their own devices. What it can do is bounded on purpose: hand
// out enrollment codes, revoke transport, register adapters for transport. None of that puts a device on anyone's
// roster, so taking over this UI does not let anyone approve anything.
type Admin struct {
	Store     *Store
	Audit     *audit.Log
	AuditPath string
	HubURL    string // what devices use, put into the enrollment link
	Log       *slog.Logger
	Auth      *Auth // nil: local mode (no sign-in; loopback only)

	linksMu sync.Mutex
	links   map[string]string // code id -> enrollment link, until used or expired (never written to disk)
}

func (a *Admin) Handler() http.Handler {
	if a.Auth == nil {
		a.Auth = LocalAuth()
	}
	m := http.NewServeMux()
	m.HandleFunc("GET /{$}", a.index)
	m.HandleFunc("POST /enroll", a.enroll)
	m.HandleFunc("GET /enroll/{id}", a.enrollPage)
	m.HandleFunc("GET /enroll/{id}/status", a.enrollStatus)
	m.HandleFunc("GET /app/hello", a.appHello)
	m.HandleFunc("GET /app/enroll", a.appEnroll)
	m.HandleFunc("POST /devices/{id}/revoke", a.revoke)
	m.HandleFunc("POST /devices/remove-revoked", a.admin(a.removeRevoked))
	m.HandleFunc("POST /users/{id}/delete", a.admin(a.deleteUser))
	m.HandleFunc("POST /adapters", a.admin(a.addAdapter))
	m.HandleFunc("POST /adapters/{id}/remove", a.admin(a.removeAdapter))
	m.HandleFunc("GET /audit", a.admin(a.audit))
	m.HandleFunc("GET /login", a.Auth.Login)
	m.HandleFunc("GET /oidc/callback", a.Auth.Callback)
	m.HandleFunc("POST /logout", a.Auth.Logout)
	return sameOrigin(securityHeaders(a.Auth.Middleware(m, "/login", "/oidc/callback", "/app/hello")))
}

// admin restricts a handler to admins (the admin group, or everyone in local mode).
func (a *Admin) admin(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !Who(r).Admin {
			http.Error(w, "admins only", http.StatusForbidden)
			return
		}
		h(w, r)
	}
}

// may reports whether the signed-in person may act for user: admins for anyone, others for themselves.
func may(r *http.Request, user string) bool {
	id := Who(r)
	return id.Admin || (id.User != "" && id.User == user)
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

// No scripts anywhere. Pages may frame only this site (the enroll page's status box); only that box may be framed,
// and only by this site.
const (
	cspPage  = "default-src 'none'; style-src 'unsafe-inline'; img-src data:; frame-src 'self'; form-action 'self'; frame-ancestors 'none'"
	cspFrame = "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'self'"
)

func securityHeaders(h http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Security-Policy", cspPage)
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "same-origin") // not no-referrer: that makes browsers send "Origin: null"
		w.Header().Set("Cache-Control", "no-store")
		h.ServeHTTP(w, r)
	})
}

type page struct {
	Title      string
	Me         Identity
	HasAccount bool // a non-admin who already has a user (offer "add a device", not "create")
	HasRevoked bool // an admin sees revoked devices it can remove from the list
	Users      []UserView
	Adapters   []Adapter
	Devices    []Device
	Requests   []Request
	Flash      string
	// enrollment
	Link     string
	QR       template.URL
	Expiry   time.Time
	CodeID   string // the enroll page frames /enroll/<id>/status, which reloads itself; the page does not
	CodeUser string
	CodeMode string
	Expired  bool
	Enrolled *Device // the device that used the code
	Active   bool    // that device is in its user's roster (a join was approved; a new user is active at once)
	Account  string  // the user's account fingerprint, once known
	// adapter added
	NewAdapter, NewAdapterFP, NewToken string
	// audit
	Lines []string
}

func (a *Admin) render(w http.ResponseWriter, name string, p page) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.ExecuteTemplate(w, name, p); err != nil && a.Log != nil {
		a.Log.Error("template", "name", name, "err", err)
	}
}

// overview is what the signed-in person may see: everything for admins; their own user and devices otherwise.
func (a *Admin) overview(r *http.Request, flash string) page {
	me := Who(r)
	p := page{Title: "Clearing house", Me: me, Flash: flash}
	if me.Admin {
		p.Users, p.Adapters, p.Devices, p.Requests = a.Store.Users(), a.Store.Adapters(), a.Store.Devices(), a.Store.Requests()
		for _, d := range p.Devices {
			p.HasRevoked = p.HasRevoked || d.Revoked
		}
		return p
	}
	for _, u := range a.Store.Users() {
		if u.ID == me.User {
			p.Users = append(p.Users, u)
		}
	}
	for _, d := range a.Store.Devices() {
		if d.User == me.User {
			p.Devices = append(p.Devices, d)
		}
	}
	p.HasAccount = len(p.Users) > 0
	return p
}

func (a *Admin) index(w http.ResponseWriter, r *http.Request) {
	a.render(w, "index.html", a.overview(r, ""))
}

// issue makes a code for user and mode and returns its id and enrollment link.
func (a *Admin) issue(user, mode, via string) (id, link string, err error) {
	now := time.Now()
	code, id, err := a.Store.NewEnrollCode(now, user, mode)
	if err != nil {
		return "", "", err
	}
	link = "interpose://enroll?hub=" + url.QueryEscape(a.HubURL) + "&code=" + url.QueryEscape(code) +
		"&user=" + url.QueryEscape(user) + "&mode=" + mode
	a.linksMu.Lock()
	if a.links == nil {
		a.links = map[string]string{}
	}
	a.links[id] = link // memory only: after a restart the page says to make a new code
	a.linksMu.Unlock()
	a.write(audit.Event{Time: now, Event: "enroll-code-issued", Requester: user, Detail: mode + " via " + via + " id " + id})
	return id, link, nil
}

// enroll issues a code for a user (form: user, mode new|join) and sends the browser to its own page, which follows
// it until a phone uses it. People who are not admins may only issue codes for themselves.
func (a *Admin) enroll(w http.ResponseWriter, r *http.Request) {
	user, mode := strings.ToLower(strings.TrimSpace(r.FormValue("user"))), r.FormValue("mode")
	if !may(r, user) {
		http.Error(w, "you may only enroll devices for yourself", http.StatusForbidden)
		return
	}
	id, _, err := a.issue(user, mode, "ui")
	if err != nil {
		a.render(w, "index.html", a.overview(r, err.Error()))
		return
	}
	http.Redirect(w, r, "/enroll/"+id, http.StatusSeeOther)
}

// appHello lets the app check, before anyone signs in, that an address is an Interpose server, and learn how to
// continue: "oidc" (sign in on the server) or "local" (development: no sign-in; the app asks for a user id). Public,
// and says nothing about anyone.
func (a *Admin) appHello(w http.ResponseWriter, _ *http.Request) {
	signin := "oidc"
	if a.Auth.Local {
		signin = "local"
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]any{"service": "interloper", "version": protocol.Version, "signin": signin, "api": a.HubURL})
}

// appEnroll is phone sign-in: the app opens it in a private browser session, the person signs in, and the hub
// answers with an enrollment link for them (interpose://enroll?…), which the app catches. New user if they have no
// account yet, otherwise a join that one of their existing phones must approve. In local mode (no sign-in) the user
// comes from ?user=.
//
// It is a GET with an effect (a code is issued) so that it works as a sign-in redirect target. A forged visit
// can only hand a code for the victim's own account to the victim's own app, and that code adds nothing until the
// victim approves the device on a phone they already have.
func (a *Admin) appEnroll(w http.ResponseWriter, r *http.Request) {
	user := Who(r).User
	if a.Auth.Local {
		user = strings.ToLower(r.URL.Query().Get("user"))
	}
	if !protocol.ValidUserID(user) {
		http.Error(w, "no usable user id", http.StatusBadRequest)
		return
	}
	mode := ModeNew
	if _, exists := a.Store.Chain(user); exists {
		mode = ModeJoin
	}
	_, link, err := a.issue(user, mode, "app")
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	http.Redirect(w, r, link, http.StatusSeeOther)
}

// enrollState fills in what the enroll page and its status box show for a code, if the signed-in person may see it.
func (a *Admin) enrollState(r *http.Request, id string) (page, bool) {
	s, ok := a.Store.EnrollStatus(id)
	if !ok || !may(r, s.User) {
		return page{}, false
	}
	p := page{Title: "Enroll a device", Me: Who(r), CodeID: id, Expiry: s.Expires, CodeUser: s.User, CodeMode: s.Mode}
	if s.Device != "" {
		if d, ok := a.Store.Device(s.Device); ok {
			p.Enrolled = &d
		}
		for _, u := range a.Store.Users() {
			if u.ID == s.User {
				p.Account = u.Head.Account
				_, p.Active = u.Head.Devices[s.Device]
			}
		}
		return p, true
	}
	p.Expired = time.Now().After(s.Expires)
	return p, true
}

// enrollPage shows the code (QR, link, simulator command) and a status box; once a phone has enrolled with it, it
// shows that device's name and fingerprint, to compare with the phone, and what to do next. The page itself never
// reloads (the link must stay selectable); the status box does.
func (a *Admin) enrollPage(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	p, ok := a.enrollState(r, id)
	if !ok {
		http.NotFound(w, r)
		return
	}
	if p.Enrolled != nil || p.Expired {
		if p.Enrolled != nil {
			p.Title = "Device enrolled"
		}
		a.forget(id)
		a.render(w, "enroll.html", p)
		return
	}
	a.linksMu.Lock()
	p.Link = a.links[id]
	a.linksMu.Unlock()
	if p.Link != "" {
		if c, err := qr.Encode(p.Link, qr.M); err == nil {
			c.Scale = 6
			p.QR = template.URL("data:image/png;base64," + base64.StdEncoding.EncodeToString(c.PNG()))
		}
	}
	a.render(w, "enroll.html", p)
}

// enrollStatus is the enroll page's status box: it reloads itself every 3 s until the device is in its user's
// roster (a join waits for approval on another of the user's phones) or the code expired.
func (a *Admin) enrollStatus(w http.ResponseWriter, r *http.Request) {
	p, ok := a.enrollState(r, r.PathValue("id"))
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Security-Policy", cspFrame)
	a.render(w, "enroll-status.html", p)
}

func (a *Admin) forget(id string) {
	a.linksMu.Lock()
	delete(a.links, id)
	a.linksMu.Unlock()
}

func (a *Admin) revoke(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if d, ok := a.Store.Device(id); !ok || !may(r, d.User) {
		http.Error(w, "you may only revoke your own devices", http.StatusForbidden)
		return
	}
	flash := "Revoked " + id + " at the hub: it gets nothing more from here. Adapters go by the user's roster: to take it off the " +
		"account for good, remove it on another of the user's phones (Device tab → Devices on this account)."
	if err := a.Store.RevokeDevice(id); err != nil {
		flash = err.Error()
	} else {
		a.write(audit.Event{Time: time.Now(), Event: "device-revoked", Device: id})
	}
	a.render(w, "index.html", a.overview(r, flash))
}

func (a *Admin) removeRevoked(w http.ResponseWriter, r *http.Request) {
	gone, err := a.Store.RemoveRevokedDevices()
	flash := fmt.Sprintf("Removed %d revoked device(s) from the hub.", len(gone))
	if err != nil {
		flash = err.Error()
	}
	for _, id := range gone {
		a.write(audit.Event{Time: time.Now(), Event: "device-removed", Device: id})
	}
	a.render(w, "index.html", a.overview(r, flash))
}

// deleteUser forgets an account at the hub. The form must repeat the user id, so a stray click cannot do it.
func (a *Admin) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if strings.TrimSpace(r.FormValue("confirm")) != id {
		a.render(w, "index.html", a.overview(r, "Not deleted: type the user id ("+id+") to confirm."))
		return
	}
	gone, err := a.Store.DeleteUser(id)
	if err != nil {
		a.render(w, "index.html", a.overview(r, "Deleting "+id+": "+err.Error()))
		return
	}
	a.write(audit.Event{Time: time.Now(), Event: "user-deleted", Target: id,
		Detail: fmt.Sprintf("%d device(s): %s", len(gone), strings.Join(gone, " "))})
	a.render(w, "index.html", a.overview(r, "Deleted account "+id+" and its "+fmt.Sprint(len(gone))+" device(s) at the hub. "+
		"Enrolling "+id+" again creates a new account with a new fingerprint: adapters must run trust add-user for it again."))
}

func (a *Admin) addAdapter(w http.ResponseWriter, r *http.Request) {
	id := strings.TrimSpace(r.FormValue("id"))
	key := strings.TrimSpace(r.FormValue("key"))
	tok, err := a.Store.AddAdapter(id, key, time.Now())
	if err != nil {
		a.render(w, "index.html", a.overview(r, "Adding adapter: "+err.Error()))
		return
	}
	a.write(audit.Event{Time: time.Now(), Event: "adapter-added", Adapter: id, Detail: "key " + key})
	// A page of its own, so the once-only token is the first thing on screen, not above the fold of the overview.
	p := page{Title: "Adapter registered", Me: Who(r), NewAdapter: id, NewToken: tok}
	if raw, err := protocol.UnB64(key); err == nil {
		p.NewAdapterFP = protocol.Fingerprint(raw)
	}
	w.Header().Set("Cache-Control", "no-store")
	a.render(w, "adapter-added.html", p)
}

func (a *Admin) removeAdapter(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	flash := "Removed adapter " + id
	if err := a.Store.RemoveAdapter(id); err != nil {
		flash = err.Error()
	} else {
		a.write(audit.Event{Time: time.Now(), Event: "adapter-removed", Adapter: id})
	}
	a.render(w, "index.html", a.overview(r, flash))
}

// audit shows the last 200 lines of the hub's audit log, read from the end of the file.
func (a *Admin) audit(w http.ResponseWriter, r *http.Request) {
	p := page{Title: "Hub audit", Me: Who(r)}
	lines, note, err := tailLines(a.AuditPath, auditPageLines, auditTailMax)
	switch {
	case err != nil && !errors.Is(err, fs.ErrNotExist):
		p.Flash = "Cannot read the audit log: " + err.Error()
	case note != "":
		p.Flash = note
	}
	slices.Reverse(lines)
	p.Lines = lines
	a.render(w, "audit.html", p)
}

const (
	auditPageLines = 200
	auditTailMax   = 16 << 20 // read at most this much of the end of the log
	auditLineMax   = 4 << 10  // longer lines are shown cut, with their length
)

// tailLines returns the last n lines of a file, oldest first, reading back from the end in growing chunks but no
// further than limit bytes. note says when that was not enough for n lines, so the page does not look complete.
func tailLines(path string, n int, limit int64) (lines []string, note string, err error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, "", err
	}
	defer f.Close()
	fi, err := f.Stat()
	if err != nil {
		return nil, "", err
	}
	size := fi.Size()
	var buf []byte
	for chunk := int64(64 << 10); ; chunk *= 4 {
		start := max(0, size-min(chunk, limit))
		buf = make([]byte, size-start)
		if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
			return nil, "", err
		}
		if start > 0 {
			// The first line may begin before the window; drop it unless the window holds nothing else.
			if i := bytes.IndexByte(buf, '\n'); i >= 0 {
				buf = buf[i+1:]
			} else {
				buf = nil
			}
		}
		if bytes.Count(buf, []byte{'\n'}) >= n || start == 0 {
			break
		}
		if size-start >= limit {
			note = fmt.Sprintf("Showing only the events in the last %d MB of the audit log.", limit>>20)
			break
		}
	}
	for l := range bytes.Lines(buf) {
		l = bytes.TrimSuffix(l, []byte{'\n'})
		if len(l) == 0 {
			continue
		}
		if len(l) > auditLineMax {
			lines = append(lines, fmt.Sprintf("%s… [line cut: %d bytes]", strings.ToValidUTF8(string(l[:auditLineMax]), ""), len(l)))
			continue
		}
		lines = append(lines, string(l))
	}
	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, note, nil
}

func (a *Admin) write(e audit.Event) {
	if a.Audit == nil {
		return
	}
	if err := a.Audit.Write(e); err != nil && a.Log != nil {
		a.Log.Error("audit write failed", "event", e.Event, "err", err)
	}
}
