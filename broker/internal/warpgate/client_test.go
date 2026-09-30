package warpgate

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestClient(t *testing.T) {
	var denyBody map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Warpgate-Token") != "tok" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		switch r.Method + " " + r.URL.RequestURI() {
		case "GET /@warpgate/admin/api/ticket-requests?status=Pending":
			io.WriteString(w, `[{"id":"r1","user_id":"u1","target_id":"t1","requested_duration_seconds":7200,
				"description":"fix x","status":"Pending","created":"2026-09-30T19:00:00.123456789Z"},
				{"id":"r2","user_id":"u1","target_id":"t1","description":"old","status":"Approved","created":"2026-09-30T18:00:00Z"}]`)
		case "GET /@warpgate/admin/api/users":
			io.WriteString(w, `[{"id":"u1","username":"claude","description":"x"}]`)
		case "GET /@warpgate/admin/api/targets":
			io.WriteString(w, `[{"id":"t1","name":"build-01-rw","options":{}}]`)
		case "POST /@warpgate/admin/api/ticket-requests/r1/deny":
			json.NewDecoder(r.Body).Decode(&denyBody)
			io.WriteString(w, `{}`)
		case "POST /@warpgate/admin/api/ticket-requests/gone/deny":
			w.WriteHeader(http.StatusNotFound)
		case "GET /@warpgate/api/profile/api-tokens":
			io.WriteString(w, `[{"id":"a","label":"l","created":"2026-09-30T00:00:00Z","expiry":"2027-09-30T00:00:00Z"}]`)
		default:
			t.Errorf("unexpected %s %s", r.Method, r.URL.RequestURI())
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	defer srv.Close()
	ctx := context.Background()
	c := New(srv.URL+"/", "tok", nil)

	reqs, err := c.PendingRequests(ctx)
	if err != nil || len(reqs) != 1 || reqs[0].ID != "r1" || *reqs[0].RequestedDurationSeconds != 7200 || reqs[0].Created.IsZero() {
		t.Fatalf("PendingRequests = %+v, %v (non-Pending rows must be dropped)", reqs, err)
	}
	if u, err := c.Usernames(ctx); err != nil || u["u1"] != "claude" {
		t.Fatalf("Usernames = %v, %v", u, err)
	}
	if tg, err := c.TargetNames(ctx); err != nil || tg["t1"] != "build-01-rw" {
		t.Fatalf("TargetNames = %v, %v", tg, err)
	}
	if err := c.Deny(ctx, "r1", "because"); err != nil || denyBody["reason"] != "because" {
		t.Fatalf("Deny = %v, body %v", err, denyBody)
	}
	if err := c.Deny(ctx, "gone", "x"); !errors.Is(err, ErrNotPending) {
		t.Fatalf("Deny(gone) = %v, want ErrNotPending", err)
	}
	if exps, err := c.TokenExpiries(ctx); err != nil || len(exps) != 1 || exps[0].Year() != 2027 {
		t.Fatalf("TokenExpiries = %v, %v", exps, err)
	}
	if _, err := New(srv.URL, "wrong", nil).PendingRequests(ctx); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("bad token: %v, want ErrUnauthorized", err)
	}
}
