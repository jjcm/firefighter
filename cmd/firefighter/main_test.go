package main

import (
	"os"
	"path/filepath"
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

func TestMissingXTokenStillValidatesEndpoint(t *testing.T) {
	t.Setenv("FIREFIGHTER_TEST_X_TOKEN", "")
	c := config.Default()
	c.Sources = []config.Source{{Name: "x", Type: "x", URL: "http://untrusted.example/search", TokenEnv: "FIREFIGHTER_TEST_X_TOKEN", IntervalSeconds: 60}}
	if _, err := buildSources(c); err == nil {
		t.Fatal("invalid X endpoint passed validation with missing token")
	}
}
