// Package audit is the broker's append-only decision log: one JSON object per line, synced on every write.
package audit

import (
	"encoding/json"
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
}

type Log struct {
	mu sync.Mutex
	f  *os.File
}

func Open(path string) (*Log, error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, err
	}
	return &Log{f: f}, nil
}

func (l *Log) Write(e Event) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if _, err := l.f.Write(append(b, '\n')); err != nil {
		return err
	}
	return l.f.Sync()
}

func (l *Log) Close() error { return l.f.Close() }
