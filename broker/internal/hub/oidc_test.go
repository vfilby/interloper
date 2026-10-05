package hub

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fakeIdP is a minimal OIDC provider: discovery, JWKS, an authorize endpoint that "signs in" whoever the test says,
// and a token endpoint that checks the client secret and the PKCE verifier and returns an RS256 ID token.
type fakeIdP struct {
	t      *testing.T
	srv    *httptest.Server
	key    *rsa.PrivateKey
	client string
	secret string

	mu       sync.Mutex
	user     string
	groups   []string
	codes    map[string]authz // code -> what /authorize saw
	tamper   func(claims map[string]any)
	badSigns bool   // sign ID tokens with a key not in the JWKS
	minimal  bool   // Authelia 4.39 style: no profile or groups claims in the ID token, only from userinfo
	uiSub    string // userinfo answers about this subject instead (an attack)
}

type authz struct{ nonce, challenge, redirect string }

func newIdP(t *testing.T) *fakeIdP {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	p := &fakeIdP{t: t, key: key, client: "interloper", secret: "s3cret", codes: map[string]authz{}}
	m := http.NewServeMux()
	m.HandleFunc("/.well-known/openid-configuration", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{
			"issuer": p.srv.URL, "authorization_endpoint": p.srv.URL + "/authorize", "token_endpoint": p.srv.URL + "/token",
			"jwks_uri": p.srv.URL + "/jwks", "userinfo_endpoint": p.srv.URL + "/userinfo", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	m.HandleFunc("/jwks", func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: &p.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"}}})
	})
	m.HandleFunc("/userinfo", func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer at" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		p.mu.Lock()
		defer p.mu.Unlock()
		sub := "sub-" + p.user
		if p.uiSub != "" {
			sub = p.uiSub
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"sub": sub, "preferred_username": p.user, "groups": p.groups, "name": p.user})
	})
	m.HandleFunc("/authorize", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		if q.Get("client_id") != p.client || q.Get("code_challenge_method") != "S256" || q.Get("code_challenge") == "" {
			http.Error(w, "bad authorize request", http.StatusBadRequest)
			return
		}
		code := random()
		p.mu.Lock()
		p.codes[code] = authz{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri")}
		p.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	m.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		id, sec, ok := r.BasicAuth()
		if !ok {
			id, sec = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
		}
		p.mu.Lock()
		az, known := p.codes[r.PostForm.Get("code")]
		delete(p.codes, r.PostForm.Get("code"))
		p.mu.Unlock()
		sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
		switch {
		case id != p.client || sec != p.secret:
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		case !known || az.redirect != r.PostForm.Get("redirect_uri"):
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		case base64.RawURLEncoding.EncodeToString(sum[:]) != az.challenge:
			http.Error(w, `{"error":"invalid_grant","error_description":"PKCE"}`, http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"access_token": "at", "token_type": "Bearer", "expires_in": 300,
			"id_token": p.idToken(az.nonce)})
	})
	p.srv = httptest.NewServer(m)
	t.Cleanup(p.srv.Close)
	return p
}

func (p *fakeIdP) as(user string, groups ...string) {
	p.mu.Lock()
	p.user, p.groups = user, groups
	p.mu.Unlock()
}

func (p *fakeIdP) idToken(nonce string) string {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()
	claims := map[string]any{"iss": p.srv.URL, "aud": p.client, "sub": "sub-" + p.user, "iat": now.Unix(),
		"exp": now.Add(5 * time.Minute).Unix(), "nonce": nonce, "preferred_username": p.user, "groups": p.groups, "name": p.user}
	if p.minimal {
		delete(claims, "preferred_username")
		delete(claims, "groups")
		delete(claims, "name")
	}
	if p.tamper != nil {
		p.tamper(claims)
	}
	key := p.key
	if p.badSigns {
		key, _ = rsa.GenerateKey(rand.Reader, 2048)
	}
	sig, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: key}, (&jose.SignerOptions{}).WithHeader("kid", "k1"))
	if err != nil {
		p.t.Fatal(err)
	}
	b, _ := json.Marshal(claims)
	jws, err := sig.Sign(b)
	if err != nil {
		p.t.Fatal(err)
	}
	s, _ := jws.CompactSerialize()
	return s
}

// hubWithIdP is a management UI behind OIDC, and a browser-like client (cookies; stops at interpose:// links).
func hubWithIdP(t *testing.T) (*fakeIdP, *httptest.Server, *Store, func() *http.Client) {
	idp := newIdP(t)
	st, err := Open(filepath.Join(t.TempDir(), "state.json"))
	if err != nil {
		t.Fatal(err)
	}
	adm := &Admin{Store: st, HubURL: "http://hub.test:8740"}
	ui := httptest.NewUnstartedServer(nil)
	ui.Start()
	t.Cleanup(ui.Close)
	auth, err := NewOIDC(context.Background(), idp.srv.URL, idp.client, idp.secret, ui.URL+"/oidc/callback", "interpose_admins",
		[]byte(strings.Repeat("k", 32)))
	if err != nil {
		t.Fatal(err)
	}
	adm.Auth = auth
	ui.Config.Handler = adm.Handler()
	browser := func() *http.Client {
		jar, _ := cookiejar.New(nil)
		return &http.Client{Jar: jar, CheckRedirect: func(req *http.Request, _ []*http.Request) error {
			if req.URL.Scheme == "interpose" {
				return http.ErrUseLastResponse
			}
			return nil
		}}
	}
	return idp, ui, st, browser
}

func signIn(t *testing.T, c *http.Client, ui string) string {
	t.Helper()
	resp, err := c.Get(ui + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 64<<10)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("sign-in ended with %d: %s", resp.StatusCode, b.String())
	}
	return b.String()
}

func post(t *testing.T, c *http.Client, u string, form url.Values) int {
	t.Helper()
	c2 := *c
	c2.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, err := c2.PostForm(u, form)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var b strings.Builder
	buf := make([]byte, 64<<10)
	for {
		n, err := resp.Body.Read(buf)
		b.Write(buf[:n])
		if err != nil {
			break
		}
	}
	return resp, b.String()
}

func TestOIDCSelfServiceAndAdmin(t *testing.T) {
	idp, ui, _, browser := hubWithIdP(t)

	// kim: an ordinary user.
	idp.as("Kim", "household_users")
	kim := browser()
	page := signIn(t, kim, ui.URL)
	for _, want := range []string{"Signed in as <strong>kim</strong>", "Your account", "Create it, and enroll my first phone"} {
		if !strings.Contains(page, want) {
			t.Fatalf("kim's overview lacks %q", want)
		}
	}
	for _, hidden := range []string{"Register an adapter", "Pending and recent requests", `href="/audit"`} {
		if strings.Contains(page, hidden) {
			t.Fatalf("kim's overview shows admin-only %q", hidden)
		}
	}
	if code := post(t, kim, ui.URL+"/enroll", url.Values{"user": {"kim"}, "mode": {"new"}}); code != http.StatusSeeOther {
		t.Fatalf("kim enrolling herself: %d", code)
	}
	if code := post(t, kim, ui.URL+"/enroll", url.Values{"user": {"vince"}, "mode": {"new"}}); code != http.StatusForbidden {
		t.Fatalf("kim enrolling for vince: %d", code)
	}
	if code := post(t, kim, ui.URL+"/adapters", url.Values{"id": {"x"}, "key": {"y"}}); code != http.StatusForbidden {
		t.Fatalf("kim registering an adapter: %d", code)
	}
	if code := post(t, kim, ui.URL+"/users/kim/delete", url.Values{"confirm": {"kim"}}); code != http.StatusForbidden {
		t.Fatalf("kim deleting her account (break glass is for admins): %d", code)
	}
	if code := post(t, kim, ui.URL+"/devices/remove-revoked", nil); code != http.StatusForbidden {
		t.Fatalf("kim removing revoked devices: %d", code)
	}
	if resp, _ := get(t, kim, ui.URL+"/audit"); resp.StatusCode != http.StatusForbidden {
		t.Fatalf("kim reading the audit log: %d", resp.StatusCode)
	}

	// Phone sign-in: the hub answers with an interpose:// link for the signed-in user, new until the account exists.
	resp, _ := get(t, kim, ui.URL+"/app/enroll")
	loc, _ := url.Parse(resp.Header.Get("Location"))
	if resp.StatusCode != http.StatusSeeOther || loc.Scheme != "interpose" || loc.Query().Get("user") != "kim" || loc.Query().Get("mode") != "new" {
		t.Fatalf("app enroll: %d %s", resp.StatusCode, loc)
	}

	// vince: an admin by group.
	idp.as("vince", "interpose_admins")
	vince := browser()
	page = signIn(t, vince, ui.URL)
	if !strings.Contains(page, "(admin)") || !strings.Contains(page, "Register an adapter") {
		t.Fatal("admin overview incomplete")
	}
	if code := post(t, vince, ui.URL+"/enroll", url.Values{"user": {"kim"}, "mode": {"new"}}); code != http.StatusSeeOther {
		t.Fatalf("admin enrolling for kim: %d", code)
	}
	if resp, _ := get(t, vince, ui.URL+"/audit"); resp.StatusCode != http.StatusOK {
		t.Fatalf("admin audit: %d", resp.StatusCode)
	}

	// Signed out, nothing is reachable.
	if code := post(t, vince, ui.URL+"/logout", nil); code != http.StatusSeeOther {
		t.Fatalf("logout: %d", code)
	}
	if code := post(t, vince, ui.URL+"/enroll", url.Values{"user": {"kim"}, "mode": {"new"}}); code != http.StatusUnauthorized {
		t.Fatalf("after logout: %d", code)
	}
}

func TestOIDCAttacks(t *testing.T) {
	idp, ui, _, browser := hubWithIdP(t)
	idp.as("kim")

	// Forged and expired session cookies are ignored: the browser is sent to sign in.
	noFollow := func(c *http.Client) *http.Client {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
		return c
	}
	c := noFollow(browser())
	u, _ := url.Parse(ui.URL)
	a := &Auth{key: []byte(strings.Repeat("x", 32))} // someone else's key
	c.Jar.SetCookies(u, []*http.Cookie{{Name: sessionCookie, Value: a.seal(session{Identity: Identity{User: "vince", Admin: true}, Exp: time.Now().Add(time.Hour).Unix()})}})
	if resp, _ := get(t, c, ui.URL+"/audit"); resp.StatusCode != http.StatusSeeOther || !strings.HasPrefix(resp.Header.Get("Location"), "/login") {
		t.Fatalf("forged session: %d %s", resp.StatusCode, resp.Header.Get("Location"))
	}

	// The callback without its login cookie, or with another state, fails.
	if resp, _ := get(t, browser(), ui.URL+"/oidc/callback?code=x&state=y"); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("callback without login: %d", resp.StatusCode)
	}
	c = noFollow(browser())
	resp, _ := get(t, c, ui.URL+"/login")
	authURL, _ := url.Parse(resp.Header.Get("Location"))
	resp, _ = get(t, c, authURL.String()) // the IdP redirects back with a code for this state
	cb, _ := url.Parse(resp.Header.Get("Location"))
	q := cb.Query()
	q.Set("state", "someone-elses")
	cb.RawQuery = q.Encode()
	if resp, _ := get(t, c, cb.String()); resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("state mismatch: %d", resp.StatusCode)
	}

	// ID tokens that are wrong in any way are refused.
	for name, setup := range map[string]func(){
		"wrong nonce":    func() { idp.tamper = func(c map[string]any) { c["nonce"] = "other" } },
		"wrong audience": func() { idp.tamper = func(c map[string]any) { c["aud"] = "someone-else" } },
		"wrong issuer":   func() { idp.tamper = func(c map[string]any) { c["iss"] = "https://evil.example" } },
		"expired":        func() { idp.tamper = func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() } },
		"unusable name":  func() { idp.tamper = func(c map[string]any) { c["preferred_username"] = "Kim O'Hara" } },
		"not signed by the IdP": func() {
			idp.tamper = nil
			idp.badSigns = true
		},
	} {
		setup()
		resp, body := get(t, browser(), ui.URL+"/")
		t.Logf("%s -> %d %s", name, resp.StatusCode, strings.TrimSpace(body))
		if resp.StatusCode != http.StatusForbidden {
			t.Errorf("%s: got %d, want 403 (%s)", name, resp.StatusCode, strings.TrimSpace(body))
		}
		idp.tamper, idp.badSigns = nil, false
	}

	// After sign-in, the browser only goes back to a path on this site.
	c = browser()
	resp, _ = get(t, c, ui.URL+"/login?next="+url.QueryEscape("//evil.example/x"))
	if resp.Request.URL.Host != u.Host || resp.Request.URL.Path != "/" {
		t.Fatalf("next led to %s", resp.Request.URL)
	}
}

// Authelia 4.39 without a claims policy: username and groups only from userinfo.
func TestOIDCUserinfoFallback(t *testing.T) {
	idp, ui, _, browser := hubWithIdP(t)
	idp.minimal = true
	idp.as("vince", "interpose_admins")
	page := signIn(t, browser(), ui.URL)
	if !strings.Contains(page, "Signed in as <strong>vince</strong> (admin)") {
		t.Fatal("userinfo fallback did not supply the username and groups")
	}
	idp.uiSub = "someone-else"
	if resp, body := get(t, browser(), ui.URL+"/"); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "another subject") {
		t.Fatalf("userinfo about another subject: %d %s", resp.StatusCode, body)
	}
}

func TestSafeNext(t *testing.T) {
	for in, want := range map[string]string{"/enroll/x": "/enroll/x", "//evil": "/", "https://evil": "/", `/\evil`: "/", "": "/"} {
		if got := safeNext(in); got != want {
			t.Errorf("safeNext(%q) = %q, want %q", in, got, want)
		}
	}
}

// /app/hello answers without a session, so the app can check a server before anyone signs in.
func TestAppHelloIsPublic(t *testing.T) {
	_, ui, _, browser := hubWithIdP(t)
	c := browser()
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	resp, body := get(t, c, ui.URL+"/app/hello")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"signin":"oidc"`) {
		t.Fatalf("hello behind OIDC: %d %s", resp.StatusCode, body)
	}
}
