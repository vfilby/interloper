package mailpit

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/adapters/mailpit/mpapi"
	"github.com/vfilby/interpose/internal/protocol"
)

// fakeMailpit is the part of Mailpit's API the client uses, over real HTTP.
type fakeMailpit struct {
	t        *testing.T
	mu       sync.Mutex
	msgs     []mpapi.Message
	raw      map[string]string
	released map[string][]string
	failSend bool
	reads    int // GET /message/{id} would mark read; it must never happen
}

func (f *fakeMailpit) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if u, p, _ := r.BasicAuth(); u != "adapter" || p != "pw" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	path := r.URL.Path
	switch {
	case r.Method == "GET" && path == "/api/v1/search":
		tag := strings.TrimPrefix(r.URL.Query().Get("query"), "tag:")
		var out []mpapi.Message
		for _, m := range f.msgs {
			if m.HasTag(tag) || tag == "*" {
				out = append(out, m)
			}
		}
		json.NewEncoder(w).Encode(map[string]any{"messages": out})
	case r.Method == "GET" && strings.HasSuffix(path, "/raw"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/message/"), "/raw")
		raw, ok := f.raw[id]
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, raw)
	case r.Method == "PUT" && path == "/api/v1/tags":
		var b struct{ IDs, Tags []string }
		json.NewDecoder(r.Body).Decode(&b)
		for i := range f.msgs {
			if slices.Contains(b.IDs, f.msgs[i].ID) {
				f.msgs[i].Tags = b.Tags
			}
		}
		io.WriteString(w, "ok")
	case r.Method == "POST" && strings.HasSuffix(path, "/release"):
		id := strings.TrimSuffix(strings.TrimPrefix(path, "/api/v1/message/"), "/release")
		var b struct{ To []string }
		json.NewDecoder(r.Body).Decode(&b)
		if f.failSend {
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, "relay said no")
			return
		}
		f.released[id] = b.To
		io.WriteString(w, "ok")
	case r.Method == "GET" && strings.HasPrefix(path, "/api/v1/message/"):
		f.reads++
		w.WriteHeader(http.StatusTeapot)
	default:
		f.t.Errorf("unexpected %s %s", r.Method, r.URL)
		w.WriteHeader(http.StatusTeapot)
	}
}

func (f *fakeMailpit) tags(id string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, m := range f.msgs {
		if m.ID == id {
			return m.Tags
		}
	}
	return nil
}

const withPDF = "From: Agent <agent@example.org>\r\nTo: bob@example.com\r\nSubject: Report\r\nMIME-Version: 1.0\r\n" +
	"Content-Type: multipart/mixed; boundary=b1\r\n\r\n" +
	"--b1\r\nContent-Type: multipart/alternative; boundary=b2\r\n\r\n" +
	"--b2\r\nContent-Type: text/plain\r\n\r\nHello Bob\r\n" +
	"--b2\r\nContent-Type: text/html\r\n\r\n<p>Hello Bob</p>\r\n--b2--\r\n" +
	"--b1\r\nContent-Type: application/pdf; name=\"x.pdf\"\r\nContent-Disposition: attachment; filename=\"=?UTF-8?Q?r=C3=A9sum=C3=A9.pdf?=\"\r\n" +
	"Content-Transfer-Encoding: base64\r\n\r\nSGVsbG8g\r\nV29ybGQh\r\n--b1--\r\n"

const plain = "From: agent@example.org\r\nTo: bob@example.com\r\nSubject: Hi\r\n\r\nJust text.\r\n"

func setup(t *testing.T) (*Source, *fakeMailpit, time.Time) {
	now := time.Date(2026, 10, 6, 12, 0, 0, 0, time.UTC)
	f := &fakeMailpit{t: t, released: map[string][]string{}, raw: map[string]string{"m1": withPDF, "m2": plain, "old": plain,
		"auto": plain, "cc": plain}}
	from := &mpapi.Address{Name: "Agent", Address: "Agent@Example.org"}
	f.msgs = []mpapi.Message{
		{ID: "m1", From: from, To: []mpapi.Address{{Address: "Bob@Example.com"}}, Cc: []mpapi.Address{{Name: "Carol", Address: "carol@example.net"}},
			Subject: "Report", Created: now.Add(-time.Minute), Tags: []string{TagHeld}, Size: 2048, Attachments: 1, Snippet: "Hello Bob"},
		{ID: "m2", From: from, To: []mpapi.Address{{Address: "bob@example.com"}}, Bcc: []mpapi.Address{{Address: "eve@example.com"}},
			Subject: "Hi", Created: now.Add(-time.Hour), Tags: []string{TagHeld}},
		{ID: "old", From: from, To: []mpapi.Address{{Address: "bob@example.com"}}, Created: now.Add(-48 * time.Hour), Tags: []string{TagHeld}},
		{ID: "auto", From: from, To: []mpapi.Address{{Address: "me@example.com"}}, Created: now, Tags: []string{"auto-sent"}},
		{ID: "done", From: from, To: []mpapi.Address{{Address: "bob@example.com"}}, Created: now, Tags: []string{TagDenied, TagHeld}},
	}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return &Source{MP: mpapi.New(srv.URL+"/", "adapter", "pw", nil), MaxAge: 24 * time.Hour, Now: func() time.Time { return now }}, f, now
}

func TestPendingDescribesHeldMail(t *testing.T) {
	s, f, _ := setup(t)
	items, err := s.Pending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].Key != "m1" || items[1].Key != "m2" {
		t.Fatalf("pending = %+v; want m1, m2 only (not auto-sent, already denied, or older than MaxAge)", items)
	}
	m1 := items[0]
	if m1.Kind != "mail.release" || m1.Shape != protocol.ShapeOnce || m1.Risk != protocol.RiskElevated ||
		m1.Requester != "agent@example.org" || m1.Title != "Email bob@example.com and 1 more" || m1.Reason != "" {
		t.Errorf("m1 = %+v", m1)
	}
	want := []protocol.Fact{
		{Label: "From", Value: "Agent <Agent@Example.org>"},
		{Label: "To", Value: "Bob@Example.com"},
		{Label: "Cc", Value: "Carol <carol@example.net>"},
		{Label: "Subject", Value: "Report"},
		{Label: "Attachment", Value: "résumé.pdf (application/pdf, 12 B)", Level: "warn"},
		{Label: "Body", Value: "Hello Bob"},
		{Label: "Size", Value: "2 KB"},
	}
	if !slices.Equal(m1.Facts, want) {
		t.Errorf("m1 facts:\n got %+v\nwant %+v", m1.Facts, want)
	}
	if items[1].Risk != protocol.RiskNormal || !slices.Contains(items[1].Facts, protocol.Fact{Label: "Bcc", Value: "eve@example.com"}) {
		t.Errorf("m2 = %+v; Bcc (envelope-only) recipients must be shown", items[1])
	}
	if f.reads != 0 {
		t.Error("read a message through GET /message/{id}, which marks it read")
	}

	cur, ok, err := s.Current(context.Background(), "m1")
	if err != nil || !ok {
		t.Fatalf("Current = %v, %v", ok, err)
	}
	b1, _ := json.Marshal(cur)
	b2, _ := json.Marshal(m1)
	if string(b1) != string(b2) {
		t.Errorf("Current differs from Pending for an unchanged message:\n%s\n%s", b1, b2)
	}
	if _, ok, _ := s.Current(context.Background(), "done"); ok {
		t.Error("a denied message is still current")
	}
}

func TestApproveReleasesToExactlyTheRecipientsShown(t *testing.T) {
	s, f, _ := setup(t)
	ctx := context.Background()
	if err := s.Approve(ctx, "m2"); err != nil {
		t.Fatal(err)
	}
	if got := f.released["m2"]; !slices.Equal(got, []string{"bob@example.com", "eve@example.com"}) {
		t.Errorf("released to %v", got)
	}
	if got := f.tags("m2"); !slices.Equal(got, []string{TagSent, TagHeld}) {
		t.Errorf("tags after release = %v", got)
	}
	if err := s.Approve(ctx, "m2"); !errors.Is(err, adapter.ErrGone) {
		t.Errorf("second approve = %v, want ErrGone (never sent twice)", err)
	}
	if err := s.Approve(ctx, "nope"); !errors.Is(err, adapter.ErrGone) {
		t.Errorf("approve unknown = %v, want ErrGone", err)
	}
	items, _ := s.Pending(ctx)
	if len(items) != 1 || items[0].Key != "m1" {
		t.Errorf("pending after approve = %+v", items)
	}
}

func TestFailedReleaseIsNotRetried(t *testing.T) {
	s, f, _ := setup(t)
	f.failSend = true
	err := s.Approve(context.Background(), "m2")
	if err == nil || !strings.Contains(err.Error(), "relay said no") {
		t.Fatalf("approve = %v, want the relay's error", err)
	}
	if got := f.tags("m2"); !slices.Equal(got, []string{TagHeld, TagFailed}) {
		t.Errorf("tags = %v", got)
	}
	if _, ok, _ := s.Current(context.Background(), "m2"); ok {
		t.Error("a failed release is still pending; it would be asked about again")
	}
}

func TestDenyTagsAndKeeps(t *testing.T) {
	s, f, _ := setup(t)
	if err := s.Deny(context.Background(), "m1", "no"); err != nil {
		t.Fatal(err)
	}
	if got := f.tags("m1"); !slices.Equal(got, []string{TagDenied, TagHeld}) {
		t.Errorf("tags = %v", got)
	}
	if len(f.released) != 0 {
		t.Error("deny released something")
	}
	if err := s.Deny(context.Background(), "m1", "no"); !errors.Is(err, adapter.ErrGone) {
		t.Errorf("second deny = %v, want ErrGone", err)
	}
}

func TestUnclearMessageDeniedUnasked(t *testing.T) {
	s, f, now := setup(t)
	f.msgs = append(f.msgs, mpapi.Message{ID: "bad", To: []mpapi.Address{{Address: "a@b.com, c@d.com"}}, Created: now, Tags: []string{TagHeld}})
	items, err := s.Pending(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range items {
		if it.Key == "bad" {
			t.Error("asked about a message whose recipients are unclear")
		}
	}
	if got := f.tags("bad"); !slices.Contains(got, TagDenied) {
		t.Errorf("tags = %v, want denied", got)
	}
}

func TestReadErrorIsNotADenial(t *testing.T) {
	s, f, _ := setup(t)
	delete(f.raw, "m1") // Mailpit answers 404 for the body: a read failure, not an unclear message
	if _, err := s.Pending(context.Background()); err == nil {
		t.Fatal("Pending hid a read error")
	}
	if slices.Contains(f.tags("m1"), TagDenied) {
		t.Error("a read error became a denial")
	}
	s.MP = mpapi.New("http://127.0.0.1:1", "adapter", "pw", nil)
	if _, err := s.Pending(context.Background()); err == nil {
		t.Error("Pending with Mailpit down returned no error")
	}
}

func TestAttachments(t *testing.T) {
	atts, err := Attachments([]byte(plain))
	if err != nil || len(atts) != 0 {
		t.Errorf("plain: %v, %v", atts, err)
	}
	inline := "Content-Type: multipart/related; boundary=x\r\n\r\n--x\r\nContent-Type: text/html\r\n\r\n<img src=cid:a>\r\n" +
		"--x\r\nContent-Type: image/png\r\nContent-ID: <a>\r\n\r\nPNGDATA\r\n--x--\r\n"
	atts, err = Attachments([]byte(inline))
	if err != nil || len(atts) != 1 || atts[0].Name != "(unnamed)" || atts[0].Type != "image/png" || atts[0].Size != 7 {
		t.Errorf("inline image: %+v, %v", atts, err)
	}
	if _, err := Attachments([]byte("Content-Type: multipart/mixed; boundary=z\r\n\r\n--z\r\nContent-Type: text/plain\r\n\r\nunterminated")); err == nil {
		t.Error("broken MIME parsed without error")
	}
}
