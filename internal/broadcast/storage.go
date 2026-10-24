package broadcast

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

type sourceState struct {
	Fingerprint string    `json:"fingerprint"`
	Cursor      string    `json:"cursor"`
	LastAttempt time.Time `json:"last_attempt"`
	LastSuccess time.Time `json:"last_success"`
	NextPoll    time.Time `json:"next_poll"`
	Failures    int       `json:"failures"`
	Published   uint64    `json:"published_notices"`
	ErrorCode   string    `json:"error_code"`
}
type storedNotice struct {
	Notice    Notice `json:"notice"`
	Hash      string `json:"hash"`
	Withdrawn bool   `json:"withdrawn,omitempty"`
}
type diskState struct {
	Version     int                     `json:"version"`
	Sequence    uint64                  `json:"sequence"`
	Sources     map[string]sourceState  `json:"sources"`
	Notices     []storedNotice          `json:"notices"`
	CVEStatuses map[string]cveLifecycle `json:"cve_statuses,omitempty"`
}

const maxStateBytes = 128 << 20

func hash(b []byte) string { sum := sha256.Sum256(b); return hex.EncodeToString(sum[:]) }

func secureDir(dir string) error {
	if !filepath.IsAbs(dir) {
		return errors.New("hub state directory must be absolute")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	fi, err := os.Lstat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() || fi.Mode()&os.ModeSymlink != 0 {
		return errors.New("hub state directory must be a real directory")
	}
	return os.Chmod(dir, 0700)
}
func privateFile(path string, flags int) (*os.File, error) {
	fd, err := syscall.Open(path, flags|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	f := os.NewFile(uintptr(fd), path)
	fi, err := f.Stat()
	if err != nil || !fi.Mode().IsRegular() {
		f.Close()
		return nil, errors.New("hub state path must be a regular file")
	}
	if err = f.Chmod(0600); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}
func syncDir(dir string) error {
	f, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer f.Close()
	return f.Sync()
}

// InitKey creates a new private signing key and refuses to replace an existing
// one. Losing/replacing the key requires redistributing a new public pin.
func InitKey(dir string) (ed25519.PublicKey, error) {
	if err := secureDir(dir); err != nil {
		return nil, err
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	f, err := privateFile(filepath.Join(dir, "signing.key"), os.O_WRONLY|os.O_CREATE|os.O_EXCL)
	if err != nil {
		return nil, err
	}
	_, writeErr := f.WriteString(base64.StdEncoding.EncodeToString(private) + "\n")
	if writeErr == nil {
		writeErr = f.Sync()
	}
	closeErr := f.Close()
	if writeErr != nil {
		return nil, writeErr
	}
	if closeErr != nil {
		return nil, closeErr
	}
	if err = syncDir(dir); err != nil {
		return nil, err
	}
	return public, nil
}
func readKey(dir string) (ed25519.PrivateKey, error) {
	f, err := privateFile(filepath.Join(dir, "signing.key"), os.O_RDONLY)
	if err != nil {
		return nil, errors.New("hub signing key unavailable; run init-key before starting the hub")
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, 1025))
	if err != nil || len(b) > 1024 {
		return nil, errors.New("invalid hub signing key file")
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(b)))
	if err != nil || len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("invalid hub signing key file")
	}
	derived := ed25519.NewKeyFromSeed(decoded[:ed25519.SeedSize])
	if !derived.Equal(ed25519.PrivateKey(decoded)) {
		return nil, errors.New("inconsistent hub signing key file")
	}
	return ed25519.PrivateKey(decoded), nil
}
func PublicKey(dir string) (ed25519.PublicKey, error) {
	key, err := readKey(dir)
	if err != nil {
		return nil, err
	}
	return key.Public().(ed25519.PublicKey), nil
}

func readState(dir string) (diskState, error) {
	s := diskState{Version: 1, Sources: map[string]sourceState{}, Notices: []storedNotice{}}
	f, err := privateFile(filepath.Join(dir, "hubstate.json"), os.O_RDONLY)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	defer f.Close()
	dec := json.NewDecoder(io.LimitReader(f, maxStateBytes+1))
	dec.DisallowUnknownFields()
	if err = dec.Decode(&s); err != nil {
		return s, errors.New("invalid durable hub state")
	}
	if err = dec.Decode(new(any)); err != io.EOF {
		return s, errors.New("trailing durable hub state content")
	}
	if s.Version != 1 || s.Sources == nil || s.Sequence == ^uint64(0) {
		return s, errors.New("unsupported durable hub state")
	}
	for id, status := range s.CVEStatuses {
		if !validCVEID(id) || status.ModifiedAt.IsZero() {
			return s, errors.New("invalid stored CVE lifecycle")
		}
	}
	for i, entry := range s.Notices {
		if entry.Notice.Seq == 0 || entry.Notice.Seq > s.Sequence || !entry.Notice.Untrusted || entry.Hash == "" {
			return s, errors.New("invalid stored notice")
		}
		if i > 0 && entry.Notice.Seq != s.Notices[i-1].Notice.Seq+1 {
			return s, errors.New("durable hub notice sequence has a gap")
		}
	}
	if len(s.Notices) > 0 && s.Notices[len(s.Notices)-1].Notice.Seq != s.Sequence {
		return s, errors.New("durable hub sequence does not match notices")
	}
	return s, nil
}

// Count and age limits are not sufficient when JSON escaping expands advisory
// text. A byte budget also prevents writing a checkpoint the loader cannot read.
func boundedState(s *diskState, limit int) ([]byte, error) {
	b, err := json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(b)+1 <= limit {
		return b, nil
	}
	remaining := len(b)
	remove := 0
	for remove < len(s.Notices) && remaining+1 > limit {
		entry, err := json.Marshal(s.Notices[remove])
		if err != nil {
			return nil, err
		}
		remaining -= len(entry) + 1
		remove++
	}
	if remove > 0 {
		s.Notices = append([]storedNotice(nil), s.Notices[remove:]...)
		pruneCVEStatuses(s)
	}
	b, err = json.Marshal(s)
	if err != nil {
		return nil, err
	}
	if len(b)+1 > limit {
		return nil, errors.New("hub cursor metadata exceeds checkpoint byte budget")
	}
	return b, nil
}
func writeState(dir string, s *diskState) error {
	b, err := boundedState(s, maxStateBytes)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, ".hubstate-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err == nil {
		_, err = f.WriteString("\n")
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err = os.Rename(name, filepath.Join(dir, "hubstate.json")); err != nil {
		return err
	}
	return syncDir(dir)
}
