//go:build mailpitlive

// The Source against a real Mailpit, which relays to a second one. Not part of `go test ./...`:
//
//	mailpit --smtp 127.0.0.1:2025 --listen 127.0.0.1:9025 --database sink.db                       # the "upstream"
//	echo "interpose-adapter:$(openssl passwd -apr1 pw)" > ui-users
//	printf 'host: 127.0.0.1\nport: 2025\nstarttls: false\nallow-insecure: true\nauth: none\n' > relay.yml
//	mailpit --smtp 127.0.0.1:1125 --listen 127.0.0.1:8125 --database held.db --ui-auth-file ui-users --smtp-relay-config relay.yml
//	go test -tags mailpitlive -run Live -v ./adapters/mailpit/
package mailpit

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/smtp"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/adapters/mailpit/mpapi"
)

const (
	liveSMTP = "127.0.0.1:1125"
	liveAPI  = "http://127.0.0.1:8125"
	sinkAPI  = "http://127.0.0.1:9025"
)

func liveSend(t *testing.T, subject string, to []string, body string) {
	msg := "From: Agent <agent@example.org>\r\nTo: " + to[0] + "\r\nCc: " + strings.Join(to[1:], ", ") + "\r\nSubject: " + subject +
		"\r\nMIME-Version: 1.0\r\n" + body
	if err := smtp.SendMail(liveSMTP, nil, "agent@example.org", append(to, "hidden@example.com"), []byte(msg)); err != nil {
		t.Fatal(err)
	}
}

func liveFind(t *testing.T, c *mpapi.Client, subject string) mpapi.Message {
	ms, err := c.Tagged(context.Background(), TagHeld)
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range ms {
		if m.Subject == subject {
			return m
		}
	}
	t.Fatalf("%q not held", subject)
	return mpapi.Message{}
}

func TestLive(t *testing.T) {
	ctx := context.Background()
	c := mpapi.New(liveAPI, "interpose-adapter", "pw", nil)
	stamp := time.Now().Format("150405.000")
	subjA, subjB := "approve me "+stamp, "deny me "+stamp
	liveSend(t, subjA, []string{"bob@example.com", "carol@example.net"}, "Content-Type: multipart/mixed; boundary=b\r\n\r\n"+
		"--b\r\nContent-Type: text/plain\r\n\r\nHello Bob, the report.\r\n"+
		"--b\r\nContent-Type: application/pdf\r\nContent-Disposition: attachment; filename=report.pdf\r\nContent-Transfer-Encoding: base64\r\n\r\nSGVsbG8gV29ybGQh\r\n--b--\r\n")
	liveSend(t, subjB, []string{"mallory@example.com"}, "Content-Type: text/plain\r\n\r\nplain\r\n")
	time.Sleep(500 * time.Millisecond)

	// What the gate does with a message it will not send: tag it held.
	var res struct{ Messages []mpapi.Message }
	req, _ := http.NewRequest("GET", liveAPI+"/api/v1/messages?limit=50", nil)
	req.SetBasicAuth("interpose-adapter", "pw")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	json.NewDecoder(resp.Body).Decode(&res)
	resp.Body.Close()
	for _, m := range res.Messages {
		if m.Subject == subjA || m.Subject == subjB {
			if err := c.SetTags(ctx, m.ID, []string{TagHeld}); err != nil {
				t.Fatal(err)
			}
		}
	}

	s := &Source{MP: c, MaxAge: time.Hour}
	items, err := s.Pending(ctx)
	if err != nil {
		t.Fatal(err)
	}
	a, b := liveFind(t, c, subjA), liveFind(t, c, subjB)
	var ia adapter.Item
	for _, it := range items {
		if it.Key == a.ID {
			ia = it
		}
	}
	j, _ := json.MarshalIndent(ia, "", "  ")
	t.Logf("item as the phone sees it:\n%s", j)
	if ia.Key == "" || ia.Risk != "elevated" || !strings.Contains(string(j), "report.pdf (application/pdf, 12 B)") ||
		!strings.Contains(string(j), `"Bcc"`) || !strings.Contains(string(j), "hidden@example.com") {
		t.Fatalf("item for A is wrong")
	}
	if a.Read || b.Read {
		t.Error("Pending marked a message read")
	}
	cur, ok, err := s.Current(ctx, a.ID)
	cj, _ := json.MarshalIndent(cur, "", "  ")
	if err != nil || !ok || string(cj) != string(j) {
		t.Fatalf("Current differs: %v %v\n%s", ok, err, cj)
	}

	if err := s.Approve(ctx, a.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(ctx, a.ID); !errors.Is(err, adapter.ErrGone) {
		t.Errorf("second approve = %v", err)
	}
	if err := s.Deny(ctx, b.ID, "no"); err != nil {
		t.Fatal(err)
	}
	if err := s.Approve(ctx, b.ID); !errors.Is(err, adapter.ErrGone) {
		t.Errorf("approve after deny = %v", err)
	}
	if got := liveFind(t, c, subjA).Tags; !slices.Equal(got, []string{TagSent, TagHeld}) {
		t.Errorf("A tags = %v", got)
	}
	if got := liveFind(t, c, subjB).Tags; !slices.Equal(got, []string{TagDenied, TagHeld}) {
		t.Errorf("B tags = %v", got)
	}

	// The upstream got A, addressed to exactly the three recipients shown, and never B.
	time.Sleep(500 * time.Millisecond)
	resp, err = http.Get(sinkAPI + "/api/v1/messages?limit=50")
	if err != nil {
		t.Fatal(err)
	}
	var sink struct{ Messages []mpapi.Message }
	json.NewDecoder(resp.Body).Decode(&sink)
	resp.Body.Close()
	var gotA int
	for _, m := range sink.Messages {
		switch m.Subject {
		case subjA:
			gotA++
			var rc []string
			for _, l := range [][]mpapi.Address{m.To, m.Cc, m.Bcc} {
				for _, x := range l {
					rc = append(rc, strings.ToLower(x.Address))
				}
			}
			slices.Sort(rc)
			if !slices.Equal(rc, []string{"bob@example.com", "carol@example.net", "hidden@example.com"}) {
				t.Errorf("upstream recipients = %v", rc)
			}
		case subjB:
			t.Error("the denied message reached the upstream")
		}
	}
	if gotA != 1 {
		t.Errorf("upstream has %d copies of A, want 1", gotA)
	}
}
