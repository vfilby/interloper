// Package mailpit is the Source of the mail adapter: messages a Mailpit instance is holding for a person become
// records, and a verified approval releases the message to exactly the recipients the person was shown.
//
// It works behind an auto-release gate that sits on Mailpit's webhook. The gate sends at once what its own allow-list
// covers and tags everything else `held`; this source asks about the `held` messages only. Each outcome is a tag on
// the message, so the Mailpit UI shows what happened and a message is never asked about (or sent) twice:
//
//	held                     waiting: the gate's tag, the only thing that makes a message pending here
//	held, approving          approved on a phone, release under way (set BEFORE the release: a crash cannot re-send)
//	held, approved-sent      released to the recipients shown
//	held, send-failed        the release failed; Release in the UI to retry
//	held, denied             denied on a phone, or unanswered until the record expired
//
// Denying does not delete: the message stays in Mailpit, and the person can still release it by hand in the UI.
package mailpit

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net/mail"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/vfilby/interpose/adapter"
	"github.com/vfilby/interpose/adapters/mailpit/mpapi"
	"github.com/vfilby/interpose/internal/protocol"
)

const (
	TagHeld      = "held"
	TagApproving = "approving"
	TagSent      = "approved-sent"
	TagFailed    = "send-failed"
	TagDenied    = "denied"
)

// errUnclear: the message cannot be described exactly (recipients or MIME structure), so it is denied unasked.
var errUnclear = errors.New("cannot describe the message exactly")

// decided: tags that take a held message out of the queue for good.
var decided = []string{TagApproving, TagSent, TagFailed, TagDenied}

// Mailpit is what the source needs from mpapi.Client.
type Mailpit interface {
	Tagged(ctx context.Context, tag string) ([]mpapi.Message, error)
	Raw(ctx context.Context, id string) ([]byte, error)
	SetTags(ctx context.Context, id string, tags []string) error
	Release(ctx context.Context, id string, to []string) error
}

type Source struct {
	MP Mailpit
	// MaxAge: held messages older than this are left alone (still held, never asked about), so turning the adapter
	// on does not send the whole backlog to the phone. Zero: no limit.
	MaxAge time.Duration
	Now    func() time.Time
	Log    *slog.Logger

	mu    sync.Mutex
	parts map[string][]attachment // by message id: a stored message never changes, so Pending need not re-read it
}

func (s *Source) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *Source) log() *slog.Logger {
	if s.Log != nil {
		return s.Log
	}
	return slog.Default()
}

func pending(m mpapi.Message) bool {
	if !m.HasTag(TagHeld) {
		return false
	}
	for _, t := range decided {
		if m.HasTag(t) {
			return false
		}
	}
	return true
}

func (s *Source) Pending(ctx context.Context) ([]adapter.Item, error) {
	ms, err := s.MP.Tagged(ctx, TagHeld)
	if err != nil {
		return nil, err
	}
	now := s.now()
	seen := map[string]bool{}
	var out []adapter.Item
	for _, m := range ms {
		if !pending(m) || (s.MaxAge > 0 && now.Sub(m.Created) > s.MaxAge) {
			continue
		}
		seen[m.ID] = true
		s.mu.Lock()
		atts, ok := s.parts[m.ID]
		s.mu.Unlock()
		var why error
		if _, why = recipients(m); why == nil && !ok {
			atts, why = s.attachments(ctx, m.ID)
		}
		if why != nil && !errors.Is(why, errUnclear) {
			return nil, why // could not read Mailpit: try again next poll, never a denial
		}
		if why != nil {
			// Policy: a message that cannot be described exactly cannot be approved as shown.
			if err := s.tag(ctx, m, TagDenied); err != nil {
				return nil, fmt.Errorf("denying %s (%v): %w", m.ID, why, err)
			}
			s.log().Warn("denied without asking", "message", m.ID, "why", why)
			continue
		}
		out = append(out, s.item(m, atts))
	}
	s.mu.Lock()
	for id := range s.parts {
		if !seen[id] {
			delete(s.parts, id)
		}
	}
	s.mu.Unlock()
	return out, nil
}

// find re-reads one message from Mailpit. ok false: no longer held and undecided.
func (s *Source) find(ctx context.Context, key string) (mpapi.Message, bool, error) {
	ms, err := s.MP.Tagged(ctx, TagHeld)
	if err != nil {
		return mpapi.Message{}, false, err
	}
	for _, m := range ms {
		if m.ID == key {
			return m, pending(m), nil
		}
	}
	return mpapi.Message{}, false, nil
}

func (s *Source) Current(ctx context.Context, key string) (adapter.Item, bool, error) {
	m, ok, err := s.find(ctx, key)
	if err != nil || !ok {
		return adapter.Item{}, false, err
	}
	if _, err := recipients(m); err != nil {
		return adapter.Item{}, false, nil
	}
	atts, err := s.attachments(ctx, key) // from Mailpit, not the cache
	switch {
	case errors.Is(err, errUnclear):
		return adapter.Item{}, false, nil // Pending denies it on the next poll
	case err != nil:
		return adapter.Item{}, false, err
	}
	return s.item(m, atts), true, nil
}

func (s *Source) Approve(ctx context.Context, key string) error {
	m, ok, err := s.find(ctx, key)
	switch {
	case err != nil:
		return err
	case !ok:
		return adapter.ErrGone
	}
	to, err := recipients(m)
	if err != nil {
		return err
	}
	// Marked first: whatever happens next, this message is never released by the adapter again.
	if err := s.tag(ctx, m, TagApproving); err != nil {
		return gone(err)
	}
	if err := s.MP.Release(ctx, key, to); err != nil {
		if terr := s.tag(ctx, m, TagFailed); terr != nil {
			s.log().Error("tagging a failed release", "message", key, "err", terr)
		}
		return fmt.Errorf("release to %s: %w", strings.Join(to, ", "), err)
	}
	if err := s.tag(ctx, m, TagSent); err != nil {
		// Sent, and still tagged approving: nothing will send it again. Only the UI's label is behind.
		s.log().Error("tagging a sent message", "message", key, "err", err)
	}
	s.log().Info("released", "message", key, "to", strings.Join(to, ", "))
	return nil
}

func (s *Source) Deny(ctx context.Context, key, reason string) error {
	m, ok, err := s.find(ctx, key)
	switch {
	case err != nil:
		return err
	case !ok:
		return adapter.ErrGone
	}
	if err := s.tag(ctx, m, TagDenied); err != nil {
		return gone(err)
	}
	s.log().Info("denied; the message stays held in Mailpit", "message", key, "reason", reason)
	return nil
}

// tag sets the message's tags to what it had, minus approving, plus t.
func (s *Source) tag(ctx context.Context, m mpapi.Message, t string) error {
	tags := []string{t}
	for _, old := range m.Tags {
		if old != TagApproving && old != t {
			tags = append(tags, old)
		}
	}
	slices.Sort(tags)
	return s.MP.SetTags(ctx, m.ID, tags)
}

func gone(err error) error {
	if errors.Is(err, mpapi.ErrNotFound) {
		return adapter.ErrGone
	}
	return err
}

// recipients is everyone a release sends to: To, Cc and Bcc (Mailpit puts envelope-only recipients in Bcc),
// lowercased, sorted, once each. The same set the gate checks against its allow-list.
func recipients(m mpapi.Message) ([]string, error) {
	set := map[string]bool{}
	for _, l := range [][]mpapi.Address{m.To, m.Cc, m.Bcc} {
		for _, a := range l {
			addr := strings.ToLower(strings.TrimSpace(a.Address))
			if addr == "" || strings.ContainsAny(addr, " ,;<>\r\n") || strings.Count(addr, "@") != 1 {
				return nil, fmt.Errorf("%w: unparsable recipient %q", errUnclear, a.Address)
			}
			set[addr] = true
		}
	}
	if len(set) == 0 {
		return nil, fmt.Errorf("%w: no recipients", errUnclear)
	}
	out := make([]string, 0, len(set))
	for a := range set {
		out = append(out, a)
	}
	slices.Sort(out)
	return out, nil
}

// item describes a held message from Mailpit's own copy. Everything in it is what would be sent; the agent's
// explanation, if any, is in the mail itself, so Reason stays empty.
func (s *Source) item(m mpapi.Message, atts []attachment) adapter.Item {
	from := ""
	if m.From != nil {
		from = strings.ToLower(m.From.Address)
	}
	to, _ := recipients(m)
	who := to[0]
	if len(to) > 1 {
		who = fmt.Sprintf("%s and %d more", to[0], len(to)-1)
	}
	it := adapter.Item{
		Key:       m.ID,
		Kind:      "mail.release",
		Shape:     protocol.ShapeOnce,
		Risk:      protocol.RiskNormal,
		Title:     fmt.Sprintf("Email %s", who),
		Requester: from,
		Facts:     []protocol.Fact{{Label: "From", Value: addr(m.From)}},
	}
	for _, h := range []struct {
		label string
		l     []mpapi.Address
	}{{"To", m.To}, {"Cc", m.Cc}, {"Bcc", m.Bcc}} {
		for _, a := range h.l {
			it.Facts = append(it.Facts, protocol.Fact{Label: h.label, Value: addr(&a)})
		}
	}
	for _, a := range m.ReplyTo {
		it.Facts = append(it.Facts, protocol.Fact{Label: "Reply-To", Value: addr(&a)})
	}
	subj := m.Subject
	if subj == "" {
		subj = "(no subject)"
	}
	it.Facts = append(it.Facts, protocol.Fact{Label: "Subject", Value: subj})
	for _, a := range atts {
		it.Facts = append(it.Facts, protocol.Fact{Label: "Attachment", Value: a.String(), Level: "warn"})
	}
	if len(atts) > 0 {
		it.Risk = protocol.RiskElevated
	}
	if b := strings.TrimSpace(m.Snippet); b != "" {
		it.Facts = append(it.Facts, protocol.Fact{Label: "Body", Value: b})
	}
	it.Facts = append(it.Facts, protocol.Fact{Label: "Size", Value: human(m.Size)})
	return it
}

func addr(a *mpapi.Address) string {
	if a == nil || a.Address == "" {
		return "(none)"
	}
	if a.Name == "" || strings.EqualFold(a.Name, a.Address) {
		return a.Address
	}
	return fmt.Sprintf("%s <%s>", a.Name, a.Address)
}

func human(n int64) string {
	switch {
	case n >= 1<<20:
		return fmt.Sprintf("%.1f MB", float64(n)/(1<<20))
	case n >= 1<<10:
		return fmt.Sprintf("%.0f KB", float64(n)/(1<<10))
	}
	return fmt.Sprintf("%d B", n)
}

type attachment struct {
	Name, Type string
	Size       int64
}

func (a attachment) String() string { return fmt.Sprintf("%s (%s, %s)", a.Name, a.Type, human(a.Size)) }

// attachments reads the message source and lists its attachments with decoded sizes, and caches the list.
func (s *Source) attachments(ctx context.Context, id string) ([]attachment, error) {
	raw, err := s.MP.Raw(ctx, id)
	if err != nil {
		return nil, err
	}
	atts, err := Attachments(raw)
	if err != nil {
		return nil, fmt.Errorf("%w: message %s: %v", errUnclear, id, err)
	}
	s.mu.Lock()
	if s.parts == nil {
		s.parts = map[string][]attachment{}
	}
	s.parts[id] = atts
	s.mu.Unlock()
	return atts, nil
}

// Attachments lists every part of a MIME message that is not the message text: anything with a file name, marked
// as an attachment, or not text at all (inline images count: they are sent too). Exported for tests.
func Attachments(raw []byte) ([]attachment, error) {
	msg, err := mail.ReadMessage(bytes.NewReader(raw))
	if err != nil {
		return nil, fmt.Errorf("parsing message: %w", err)
	}
	var out []attachment
	err = walk(msg.Header, msg.Body, 0, &out)
	return out, err
}

type header interface{ Get(string) string }

var dec = new(mime.WordDecoder)

func walk(h header, body io.Reader, depth int, out *[]attachment) error {
	if depth > 20 {
		return errors.New("MIME nesting too deep")
	}
	ct, params, err := mime.ParseMediaType(h.Get("Content-Type"))
	if err != nil {
		ct, params = "text/plain", nil
	}
	if strings.HasPrefix(ct, "multipart/") {
		mr := multipart.NewReader(body, params["boundary"])
		for {
			p, err := mr.NextRawPart()
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return fmt.Errorf("reading %s: %w", ct, err)
			}
			if err := walk(p.Header, p, depth+1, out); err != nil {
				return err
			}
		}
	}
	disp, dparams, _ := mime.ParseMediaType(h.Get("Content-Disposition"))
	name := dparams["filename"]
	if name == "" {
		name = params["name"]
	}
	if n, err := dec.DecodeHeader(name); err == nil {
		name = n
	}
	textBody := strings.HasPrefix(ct, "text/") && name == "" && disp != "attachment"
	if textBody || ct == "message/delivery-status" {
		return nil
	}
	if name == "" {
		name = "(unnamed)"
	}
	n, err := io.Copy(io.Discard, decode(h.Get("Content-Transfer-Encoding"), body))
	if err != nil {
		return fmt.Errorf("reading attachment %q: %w", name, err)
	}
	*out = append(*out, attachment{Name: name, Type: ct, Size: n})
	return nil
}

func decode(cte string, r io.Reader) io.Reader {
	switch strings.ToLower(strings.TrimSpace(cte)) {
	case "base64":
		return base64.NewDecoder(base64.StdEncoding, r) // skips the line breaks itself
	case "quoted-printable":
		return quotedprintable.NewReader(r)
	}
	return r
}
