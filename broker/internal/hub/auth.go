package hub

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/vfilby/interpose/internal/protocol"
)

// Identity is who is using the management UI.
type Identity struct {
	User  string `json:"u"` // hub user id; "" in local mode
	Name  string `json:"n,omitempty"`
	Admin bool   `json:"a,omitempty"`
}

// Auth signs people in to the management UI with OIDC (authorization code + PKCE, state, nonce; the ID token is
// verified by go-oidc against the issuer's keys: signature, issuer, audience, expiry). A user's id at the hub is
// their username claim; membership of AdminGroup makes them an admin.
//
// Signing in decides who may hand out enrollment codes and see what. It does not decide which devices can approve:
// that is each user's roster, signed by their own phones (docs/PROTOCOL.md). So a compromised identity provider can
// start enrollments, but a new phone still waits for approval on one of the user's existing phones.
//
// Local mode (no OIDC configured) has no login: everyone is an admin. The hub refuses it unless the UI listens on
// loopback only.
type Auth struct {
	Local      bool
	AdminGroup string
	UserClaim  string        // default "preferred_username"
	SessionTTL time.Duration // default 12h
	Secure     bool          // cookies only over https (set when the redirect URL is https)

	key      []byte // HMAC key for session and login cookies
	oauth    oauth2.Config
	provider *oidc.Provider
	verifier *oidc.IDTokenVerifier
	now      func() time.Time
}

const (
	sessionCookie = "interpose_session"
	loginCookie   = "interpose_login"
)

// NewOIDC discovers the issuer and returns an Auth. key signs cookies (32+ random bytes, kept in a file).
func NewOIDC(ctx context.Context, issuer, clientID, clientSecret, redirectURL, adminGroup string, key []byte) (*Auth, error) {
	if len(key) < 32 {
		return nil, errors.New("session key: need at least 32 bytes")
	}
	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("OIDC discovery for %s: %w", issuer, err)
	}
	return &Auth{
		AdminGroup: adminGroup,
		Secure:     strings.HasPrefix(redirectURL, "https://"),
		key:        key,
		oauth: oauth2.Config{ClientID: clientID, ClientSecret: clientSecret, RedirectURL: redirectURL,
			Endpoint: p.Endpoint(), Scopes: []string{oidc.ScopeOpenID, "profile", "email", "groups"}},
		verifier: p.Verifier(&oidc.Config{ClientID: clientID}),
		provider: p,
	}, nil
}

// LocalAuth is the no-login mode for development on loopback.
func LocalAuth() *Auth { return &Auth{Local: true} }

func (a *Auth) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

type ctxKey struct{}

// Who returns the identity the middleware attached to the request.
func Who(r *http.Request) Identity {
	id, _ := r.Context().Value(ctxKey{}).(Identity)
	return id
}

// Middleware attaches the signed-in identity, or sends the browser to sign in. paths in open are served without
// a session (the sign-in routes themselves).
func (a *Auth) Middleware(h http.Handler, open ...string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if a.Local {
			h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, Identity{Admin: true})))
			return
		}
		if slices.Contains(open, r.URL.Path) {
			h.ServeHTTP(w, r)
			return
		}
		var id Identity
		if c, err := r.Cookie(sessionCookie); err == nil && a.open(c.Value, &id) == nil && id.User != "" {
			h.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, id)))
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "sign in first", http.StatusUnauthorized)
			return
		}
		http.Redirect(w, r, "/login?next="+safeNext(r.URL.RequestURI()), http.StatusSeeOther)
	})
}

type loginState struct {
	State, Nonce, Verifier, Next string
	Exp                          int64
}

// Login starts the authorization code flow.
func (a *Auth) Login(w http.ResponseWriter, r *http.Request) {
	if a.Local {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	st := loginState{State: random(), Nonce: random(), Verifier: oauth2.GenerateVerifier(),
		Next: safeNext(r.URL.Query().Get("next")), Exp: a.clock().Add(10 * time.Minute).Unix()}
	a.setCookie(w, loginCookie, a.seal(st), 10*time.Minute)
	http.Redirect(w, r, a.oauth.AuthCodeURL(st.State, oidc.Nonce(st.Nonce), oauth2.S256ChallengeOption(st.Verifier)), http.StatusFound)
}

// Callback finishes it: state, code exchange with the PKCE verifier, ID token verification, nonce, claims.
func (a *Auth) Callback(w http.ResponseWriter, r *http.Request) {
	var st loginState
	c, err := r.Cookie(loginCookie)
	if err != nil || a.open(c.Value, &st) != nil || st.Exp < a.clock().Unix() {
		http.Error(w, "sign-in expired or started elsewhere: try again", http.StatusBadRequest)
		return
	}
	a.setCookie(w, loginCookie, "", -1)
	if e := r.URL.Query().Get("error"); e != "" {
		http.Error(w, "sign-in refused by the identity provider: "+e, http.StatusForbidden)
		return
	}
	if !hmac.Equal([]byte(r.URL.Query().Get("state")), []byte(st.State)) {
		http.Error(w, "sign-in state mismatch", http.StatusBadRequest)
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	tok, err := a.oauth.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(st.Verifier))
	if err != nil {
		http.Error(w, "code exchange failed", http.StatusBadGateway)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	idt, err := a.verifier.Verify(ctx, raw)
	if err != nil {
		http.Error(w, "ID token rejected: "+err.Error(), http.StatusForbidden)
		return
	}
	if !hmac.Equal([]byte(idt.Nonce), []byte(st.Nonce)) {
		http.Error(w, "ID token nonce mismatch", http.StatusForbidden)
		return
	}
	id, err := a.identity(ctx, idt, tok)
	if err != nil {
		http.Error(w, err.Error(), http.StatusForbidden)
		return
	}
	a.setCookie(w, sessionCookie, a.seal(session{Identity: id, Exp: a.clock().Add(a.ttl()).Unix()}), a.ttl())
	http.Redirect(w, r, st.Next, http.StatusSeeOther)
}

// identity reads the username, name and groups from the ID token, or, when the token does not carry the username
// (Authelia since 4.39 puts profile and groups claims in the ID token only if a claims policy says so), from the
// userinfo endpoint, whose subject must be the ID token's.
func (a *Auth) identity(ctx context.Context, idt *oidc.IDToken, tok *oauth2.Token) (Identity, error) {
	var claims map[string]any
	if err := idt.Claims(&claims); err != nil {
		return Identity{}, err
	}
	claim := a.UserClaim
	if claim == "" {
		claim = "preferred_username"
	}
	if _, ok := claims[claim].(string); !ok && a.provider != nil {
		ui, err := a.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return Identity{}, fmt.Errorf("the ID token has no %s claim and userinfo failed: %w", claim, err)
		}
		if ui.Subject != idt.Subject {
			return Identity{}, errors.New("userinfo is about another subject than the ID token")
		}
		if err := ui.Claims(&claims); err != nil {
			return Identity{}, err
		}
	}
	u, _ := claims[claim].(string)
	u = strings.ToLower(u)
	if !protocol.ValidUserID(u) {
		return Identity{}, fmt.Errorf("username %q (claim %s) is not usable as a hub user id (a-z 0-9 . _ -, up to 40)", u, claim)
	}
	id := Identity{User: u}
	id.Name, _ = claims["name"].(string)
	if gs, ok := claims["groups"].([]any); ok {
		for _, g := range gs {
			if s, _ := g.(string); s != "" && s == a.AdminGroup {
				id.Admin = true
			}
		}
	}
	return id, nil
}

// Logout clears the session (the identity provider's own session is left alone).
func (a *Auth) Logout(w http.ResponseWriter, r *http.Request) {
	a.setCookie(w, sessionCookie, "", -1)
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (a *Auth) ttl() time.Duration {
	if a.SessionTTL > 0 {
		return a.SessionTTL
	}
	return 12 * time.Hour
}

type session struct {
	Identity
	Exp int64 `json:"e"`
}

// seal and open: base64url(JSON) "." base64url(HMAC-SHA256). Signed, not encrypted: nothing secret is inside.
func (a *Auth) seal(v any) string {
	b, _ := json.Marshal(v)
	p := protocol.B64(b)
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(p))
	return p + "." + protocol.B64(m.Sum(nil))
}

func (a *Auth) open(s string, v any) error {
	p, sig, ok := strings.Cut(s, ".")
	if !ok {
		return errors.New("malformed")
	}
	m := hmac.New(sha256.New, a.key)
	m.Write([]byte(p))
	want := protocol.B64(m.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(want)) {
		return errors.New("bad signature")
	}
	b, err := protocol.UnB64(p)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(b, v); err != nil {
		return err
	}
	if s, ok := v.(*session); ok && s.Exp < a.clock().Unix() {
		return errors.New("expired")
	}
	return nil
}

func (a *Auth) setCookie(w http.ResponseWriter, name, value string, ttl time.Duration) {
	c := &http.Cookie{Name: name, Value: value, Path: "/", HttpOnly: true, Secure: a.Secure, SameSite: http.SameSiteLaxMode}
	if ttl < 0 {
		c.MaxAge = -1
	} else {
		c.MaxAge = int(ttl.Seconds())
	}
	http.SetCookie(w, c)
}

// safeNext keeps a post-login redirect on this site: a path, never a scheme or another host.
func safeNext(s string) string {
	if !strings.HasPrefix(s, "/") || strings.HasPrefix(s, "//") || strings.HasPrefix(s, "/\\") {
		return "/"
	}
	return s
}

func random() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return protocol.B64(b)
}
