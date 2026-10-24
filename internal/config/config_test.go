package config

import (
	"bytes"
	"encoding/base64"
	"strings"
	"testing"
)

func TestBroadcastSourceRequiresPublisherPinAndAbsoluteCA(t *testing.T) {
	c := Default()
	s := Source{Name: "central", Type: "broadcast", URL: "https://hub.example.com/api/v1/notices", IntervalSeconds: 15, PublicKey: base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{1}, 32)), CAFile: "/etc/firefighter/hub-ca.pem"}
	c.Sources = []Source{s}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Source){func(s *Source) { s.PublicKey = "" }, func(s *Source) { s.PublicKey = "malformed" }, func(s *Source) { s.CAFile = "relative.pem" }, func(s *Source) { s.URL = "" }} {
		bad := s
		mutate(&bad)
		c.Sources = []Source{bad}
		if err := c.Validate(); err == nil {
			t.Fatalf("invalid broadcast configuration accepted: %+v", bad)
		}
	}
}

func TestExternalSourcesCannotUseInternalHostReviewName(t *testing.T) {
	for _, sourceType := range []string{"rss", "broadcast", "kev", "nvd", "x"} {
		for _, name := range []string{"local-host", "LOCAL-HOST", " local-host\t"} {
			t.Run(sourceType+"/"+name, func(t *testing.T) {
				c := Default()
				c.Sources = []Source{{Name: name, Type: sourceType, IntervalSeconds: 60}}
				if err := c.Validate(); err == nil || !strings.Contains(err.Error(), "reserved for internal host reviews") {
					t.Fatalf("reserved source identity was accepted or failed for unrelated reasons: %v", err)
				}
			})
		}
	}
	for _, name := range []string{"ubuntu-usn", "firefighter-central", "local-host-advisories"} {
		if err := ValidateSourceName(name); err != nil {
			t.Fatalf("ordinary external source name %q rejected: %v", name, err)
		}
	}
}
