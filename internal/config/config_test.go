package config

import (
	"bytes"
	"encoding/base64"
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
