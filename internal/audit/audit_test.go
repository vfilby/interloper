package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func lines(t *testing.T, path string) []Event {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	var out []Event
	s := bufio.NewScanner(f)
	for s.Scan() {
		var e Event
		if err := json.Unmarshal(s.Bytes(), &e); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		out = append(out, e)
	}
	return out
}

func TestRotationBoundsTheLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := OpenRotating(path, 1000, 2)
	if err != nil {
		t.Fatal(err)
	}
	ts := time.Unix(1790000000, 0).UTC()
	for i := range 200 {
		if err := l.Write(Event{Time: ts, Event: "record", Detail: string(rune('a' + i%26))}); err != nil {
			t.Fatal(err)
		}
	}
	if err := l.Close(); err != nil {
		t.Fatal(err)
	}
	total := 0
	for _, p := range []string{path, path + ".1", path + ".2"} {
		st, err := os.Stat(p)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() > 1000 {
			t.Errorf("%s is %d bytes, over the 1000 limit", p, st.Size())
		}
		total += len(lines(t, p))
	}
	if _, err := os.Stat(path + ".3"); !os.IsNotExist(err) {
		t.Errorf("kept more than 2 rotated files: %v", err)
	}
	if total == 0 || total >= 200 {
		t.Errorf("%d events across the kept files; want some, and the oldest gone", total)
	}
	// The newest event is in the live file.
	if ev := lines(t, path); len(ev) == 0 || ev[len(ev)-1].Detail != string(rune('a'+199%26)) {
		t.Errorf("live file does not end with the last event: %+v", ev)
	}
}

func TestReopenCountsExistingSize(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	if err := os.WriteFile(path, make([]byte, 990), 0o600); err != nil {
		t.Fatal(err)
	}
	l, err := OpenRotating(path, 1000, 1)
	if err != nil {
		t.Fatal(err)
	}
	if err := l.Write(Event{Time: time.Now(), Event: "record", Detail: "pushes it past the limit"}); err != nil {
		t.Fatal(err)
	}
	l.Close()
	if st, _ := os.Stat(path + ".1"); st == nil || st.Size() != 990 {
		t.Fatalf("the existing 990 bytes were not rotated out: %v", st)
	}
	if n := len(lines(t, path)); n != 1 {
		t.Fatalf("live file has %d events, want 1", n)
	}
}

func TestOpenNeverRotates(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	l, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	for range 50 {
		_ = l.Write(Event{Time: time.Now(), Event: "record"})
	}
	l.Close()
	if _, err := os.Stat(path + ".1"); !os.IsNotExist(err) {
		t.Fatal("Open rotated")
	}
}
