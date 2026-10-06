// Package audit is the broker's append-only decision log: one JSON object per line, synced on every write.
package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"
)

type Event struct {
	Time        time.Time `json:"ts"`
	Event       string    `json:"event"`
	RequestID   string    `json:"request_id,omitempty"`
	Requester   string    `json:"requester,omitempty"`
	Target      string    `json:"target,omitempty"`
	DurationS   *int64    `json:"duration_s,omitempty"`
	Description string    `json:"description,omitempty"`
	Detail      string    `json:"detail,omitempty"`
	Adapter     string    `json:"adapter,omitempty"` // hub and adapters
	Device      string    `json:"device,omitempty"`
	Unverified  bool      `json:"unverified,omitempty"` // Device is only what an unverified message claimed
}

type Log struct {
	mu   sync.Mutex
	f    *os.File
	path string
	max  int64 // rotate before a write would take the file past this; 0: never
	keep int   // rotated files kept: path.1 (newest) … path.keep
	size int64
}

// Open opens path for appending and never rotates it.
func Open(path string) (*Log, error) { return OpenRotating(path, 0, 0) }

// OpenRotating opens path for appending. Before a write would take it past maxBytes, the file is renamed to path.1
// (path.1 to path.2, and so on) and a new one started; at most keep rotated files are kept, so the log never takes more
// than about (keep+1)*maxBytes. maxBytes 0 never rotates.
func OpenRotating(path string, maxBytes int64, keep int) (*Log, error) {
	if maxBytes > 0 && keep < 1 {
		return nil, fmt.Errorf("audit: rotating %s needs at least one rotated file to keep", path)
	}
	l := &Log{path: path, max: maxBytes, keep: keep}
	if err := l.open(); err != nil {
		return nil, err
	}
	return l, nil
}

func (l *Log) open() error {
	f, err := os.OpenFile(l.path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return err
	}
	st, err := f.Stat()
	if err != nil {
		f.Close()
		return err
	}
	l.f, l.size = f, st.Size()
	return nil
}

func (l *Log) rotate() error {
	if err := l.f.Close(); err != nil {
		return err
	}
	for i := l.keep - 1; i >= 1; i-- {
		if err := os.Rename(fmt.Sprintf("%s.%d", l.path, i), fmt.Sprintf("%s.%d", l.path, i+1)); err != nil && !os.IsNotExist(err) {
			return err
		}
	}
	if err := os.Rename(l.path, l.path+".1"); err != nil {
		return err
	}
	return l.open()
}

func (l *Log) Write(e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	b = append(b, '\n')
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.max > 0 && l.size > 0 && l.size+int64(len(b)) > l.max {
		if err := l.rotate(); err != nil {
			return fmt.Errorf("audit: rotating %s: %w", l.path, err)
		}
	}
	n, err := l.f.Write(b)
	l.size += int64(n)
	if err != nil {
		return err
	}
	return l.f.Sync()
}

func (l *Log) Close() error { return l.f.Close() }
