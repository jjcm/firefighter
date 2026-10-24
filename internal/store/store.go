// Package store owns durable cursors, incident state, outbox, and audit records.
package store

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/jjcm/firefighter/internal/intel"
	"github.com/jjcm/firefighter/internal/memory"
	"github.com/jjcm/firefighter/internal/protocol"
)

type SourceState struct {
	Fingerprint string    `json:"fingerprint,omitempty"`
	Cursor      string    `json:"cursor"`
	NextPoll    time.Time `json:"next_poll"`
	LastSuccess time.Time `json:"last_success"`
	LastError   string    `json:"last_error,omitempty"`
	Failures    int       `json:"failures"`
}
type Incident struct {
	ID            string          `json:"id"`
	Item          intel.Item      `json:"item"`
	Status        string          `json:"status"`
	UpdatedAt     time.Time       `json:"updated_at"`
	NextAttempt   time.Time       `json:"next_attempt"`
	Attempts      int             `json:"attempts"`
	History       []protocol.Turn `json:"history"`
	RecoveryNotes []string        `json:"recovery_notes,omitempty"`
	LastError     string          `json:"last_error,omitempty"`
}
type Delivery struct {
	Event       protocol.Event `json:"event"`
	Attempts    int            `json:"attempts"`
	NextAttempt time.Time      `json:"next_attempt"`
}
type State struct {
	Version        int                    `json:"version"`
	Sources        map[string]SourceState `json:"sources"`
	Incidents      map[string]*Incident   `json:"incidents"`
	Outbox         []Delivery             `json:"outbox"`
	LastHostReview time.Time              `json:"last_host_review"`
	Memory         memory.State           `json:"memory"`
}
type Record struct {
	Time       time.Time       `json:"time"`
	Type       string          `json:"type"`
	IncidentID string          `json:"incident_id,omitempty"`
	Data       json.RawMessage `json:"data"`
	Previous   string          `json:"previous"`
	Hash       string          `json:"hash"`
}
type Store struct {
	dir      string
	lock     *os.File
	audit    *os.File
	previous string
}

func Open(dir string) (*Store, *State, error) {
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, nil, err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return nil, nil, err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return nil, nil, errors.New("state directory must be a real directory")
	}
	if err = os.Chmod(dir, 0700); err != nil {
		return nil, nil, err
	}
	lock, err := privateOpen(filepath.Join(dir, "lock"), os.O_CREATE|os.O_RDWR)
	if err != nil {
		return nil, nil, err
	}
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		lock.Close()
		return nil, nil, errors.New("another firefighter process owns this state directory")
	}
	s := &Store{dir: dir, lock: lock}
	fail := func(e error) (*Store, *State, error) { s.Close(); return nil, nil, e }
	st := &State{Version: 1, Sources: map[string]SourceState{}, Incidents: map[string]*Incident{}}
	statePath := filepath.Join(dir, "state.json")
	if fi, err = os.Lstat(statePath); err == nil {
		if !fi.Mode().IsRegular() {
			return fail(errors.New("state file must be regular"))
		}
		b, e := os.ReadFile(statePath)
		if e != nil {
			return fail(e)
		}
		if e = json.Unmarshal(b, st); e != nil {
			return fail(fmt.Errorf("read durable state: %w", e))
		}
	} else if !os.IsNotExist(err) {
		return fail(err)
	}
	if st.Version != 1 || st.Sources == nil || st.Incidents == nil {
		return fail(errors.New("unsupported or incomplete durable state"))
	}
	// Persisted observations remain useful context, but a process restart may
	// follow a reboot or an interrupted host mutation. Refresh the inventory.
	now := time.Now().UTC()
	st.Memory.Invalidate("process restarted; refresh host inventory before relying on cached state", now)
	st.Memory.Prune(now)
	s.audit, err = privateOpen(filepath.Join(dir, "audit.jsonl"), os.O_CREATE|os.O_RDWR|os.O_APPEND)
	if err != nil {
		return fail(err)
	}
	tailPath, err := s.recoverTail()
	if err != nil {
		return fail(err)
	}
	queued := map[string]protocol.Event{}
	scanner := bufio.NewScanner(s.audit)
	scanner.Buffer(make([]byte, 65536), 16<<20)
	for scanner.Scan() {
		var r Record
		if err = json.Unmarshal(scanner.Bytes(), &r); err != nil {
			return fail(fmt.Errorf("invalid audit record: %w", err))
		}
		h := r.Hash
		r.Hash = ""
		b, _ := json.Marshal(r)
		digest := sha256.Sum256(b)
		if r.Previous != s.previous || h != hex.EncodeToString(digest[:]) {
			return fail(errors.New("audit hash chain is invalid"))
		}
		s.previous = h
		switch r.Type {
		case "report_queued":
			var event protocol.Event
			if err := json.Unmarshal(r.Data, &event); err != nil || event.ID == "" {
				return fail(errors.New("invalid queued report in audit"))
			}
			queued[event.ID] = event
		case "report_delivered":
			var ack struct {
				ID string `json:"id"`
			}
			if err := json.Unmarshal(r.Data, &ack); err != nil || ack.ID == "" {
				return fail(errors.New("invalid report acknowledgement in audit"))
			}
			delete(queued, ack.ID)
		}
	}
	if err = scanner.Err(); err != nil {
		return fail(err)
	}
	// Replay the durable outbox across the audit/state crash window. Preserve retry
	// scheduling from state, while the audit determines delivery completion.
	var outbox []Delivery
	for _, delivery := range st.Outbox {
		if event, ok := queued[delivery.Event.ID]; ok {
			delivery.Event = event
			outbox = append(outbox, delivery)
			delete(queued, delivery.Event.ID)
		}
	}
	for _, event := range queued {
		outbox = append(outbox, Delivery{Event: event})
	}
	st.Outbox = outbox
	sort.SliceStable(st.Outbox, func(i, j int) bool { return st.Outbox[i].Event.Time.Before(st.Outbox[j].Event.Time) })
	if tailPath != "" {
		if err := s.Append("audit_tail_recovered", "", map[string]string{"evidence_path": tailPath, "note": "Incomplete trailing audit write preserved; prior running incidents require reassessment"}); err != nil {
			return fail(err)
		}
	}
	// An interrupted incident must be reassessed; never replay a saved command.
	for _, in := range st.Incidents {
		if in == nil {
			return fail(errors.New("nil incident in durable state"))
		}
		if in.Status == "running" {
			in.Status = "pending"
			in.NextAttempt = time.Time{}
			in.RecoveryNotes = append(in.RecoveryNotes, "The daemon stopped during this incident. Previously planned commands may have executed even if their result is absent. Inspect current state and audit evidence before making changes; do not blindly replay commands.")
		}
	}
	return s, st, nil
}

// A power loss can tear the last append. Preserve those bytes before dropping
// only the incomplete final record; complete records and their chain still have
// to verify. This cannot detect a malicious root rewriting the entire journal.
func (s *Store) recoverTail() (string, error) {
	fi, err := s.audit.Stat()
	if err != nil {
		return "", err
	}
	if fi.Size() == 0 {
		return "", nil
	}
	size := min(fi.Size(), int64(16<<20))
	b := make([]byte, int(size))
	if _, err = s.audit.ReadAt(b, fi.Size()-size); err != nil {
		return "", err
	}
	if b[len(b)-1] == '\n' {
		return "", nil
	}
	last := bytes.LastIndexByte(b, '\n')
	if last < 0 && fi.Size() > size {
		return "", errors.New("oversized incomplete audit record")
	}
	cut := fi.Size() - size + int64(last+1)
	tail := b[last+1:]
	path := filepath.Join(s.dir, fmt.Sprintf("audit-interrupted-%d.jsonpart", time.Now().UnixNano()))
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", err
	}
	_, writeErr := f.Write(tail)
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return "", writeErr
	}
	if closeErr != nil {
		return "", closeErr
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return "", err
	}
	err = d.Sync()
	d.Close()
	if err != nil {
		return "", err
	}
	if err = s.audit.Truncate(cut); err != nil {
		return "", err
	}
	if err = s.audit.Sync(); err != nil {
		return "", err
	}
	return path, nil
}
func privateOpen(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("state path must be a regular file")
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func (s *Store) Close() error {
	if s.audit != nil {
		s.audit.Close()
	}
	if s.lock != nil {
		syscall.Flock(int(s.lock.Fd()), syscall.LOCK_UN)
		return s.lock.Close()
	}
	return nil
}
func (s *Store) Save(st *State) error {
	b, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(s.dir, ".state-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(append(b, '\n')); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, filepath.Join(s.dir, "state.json")); err != nil {
		return err
	}
	d, err := os.Open(s.dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (s *Store) Append(typ, incident string, data interface{}) error {
	raw, err := json.Marshal(data)
	if err != nil {
		return err
	}
	r := Record{Time: time.Now().UTC(), Type: typ, IncidentID: incident, Data: raw, Previous: s.previous}
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(b)
	r.Hash = hex.EncodeToString(sum[:])
	b, err = json.Marshal(r)
	if err != nil {
		return err
	}
	n, err := s.audit.Write(append(b, '\n'))
	if err != nil {
		return err
	}
	if n != len(b)+1 {
		return io.ErrShortWrite
	}
	if err = s.audit.Sync(); err != nil {
		return err
	}
	s.previous = r.Hash
	return nil
}
func Key(item intel.Item) string {
	b, _ := json.Marshal(item)
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:16])
}
