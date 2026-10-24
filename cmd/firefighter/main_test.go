package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jjcm/firefighter/internal/config"
)

func TestInitDoesNotOverwriteOperatorConfiguration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.json")
	if err := run([]string{"init", "--config", path}); err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = config.Load(path); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"init", "--config", path}); err == nil {
		t.Fatal("existing config overwritten")
	}
	current, _ := os.ReadFile(path)
	if string(current) != string(original) {
		t.Fatal("operator config changed")
	}
}

func TestBroadcastOnlyClientNeedsNoXCredentials(t *testing.T) {
	t.Setenv("X_BEARER_TOKEN", "")
	c := config.Default()
	c.Observe = true
	c.LLM.Backend = "command"
	c.LLM.Command = []string{"/usr/bin/true"}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{1}, 32)).Public().(ed25519.PublicKey)
	c.Sources = []config.Source{{Name: "central", Type: "broadcast", URL: "https://example.com", PublicKey: base64.StdEncoding.EncodeToString(key), IntervalSeconds: 15}}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	sources, err := buildSources(c)
	if err != nil || len(sources) != 1 || sources[0].Source.Name() != "central" {
		t.Fatalf("broadcast source configuration failed: %+v %v", sources, err)
	}
	output := filepath.Join(t.TempDir(), "doctor-output")
	f, err := os.Create(output)
	if err != nil {
		t.Fatal(err)
	}
	previous := os.Stdout
	os.Stdout = f
	_ = doctor(c) // Linux-host check may fail on the development machine.
	os.Stdout = previous
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatal(err)
	}
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "X credential:") || !strings.Contains(string(data), "OK X/Twitter source or signed central broadcast configured") {
		t.Fatalf("doctor required per-client X access: %s", data)
	}
}

func TestMissingXTokenStillValidatesEndpoint(t *testing.T) {
	t.Setenv("FIREFIGHTER_TEST_X_TOKEN", "")
	c := config.Default()
	c.Sources = []config.Source{{Name: "x", Type: "x", URL: "http://untrusted.example/search", TokenEnv: "FIREFIGHTER_TEST_X_TOKEN", IntervalSeconds: 60}}
	if _, err := buildSources(c); err == nil {
		t.Fatal("invalid X endpoint passed validation with missing token")
	}
}
