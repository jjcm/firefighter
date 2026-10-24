package protocol

import (
	"strings"
	"testing"
)

func TestValidateNoticeDisposition(t *testing.T) {
	valid := func() Decision {
		return Decision{Assessment: "not_a_notice", Done: true, Applicability: &Applicability{Status: "unknown"}, Evidence: []string{"The source advertises a conference and makes no vulnerability or exploitation claim."}}
	}
	if err := ValidateNoticeDisposition(valid()); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*Decision){
		"unfinished":            func(d *Decision) { d.Done = false },
		"action":                func(d *Decision) { d.Actions = []Action{{Argv: []string{"/bin/true"}}} },
		"memory":                func(d *Decision) { d.MemoryUpdates = []MemoryUpdate{{Key: "unsupported-host-fact"}} },
		"missing applicability": func(d *Decision) { d.Applicability = nil },
		"affected":              func(d *Decision) { d.Applicability.Status = "affected" },
		"not affected":          func(d *Decision) { d.Applicability.Status = "not_affected" },
		"missing evidence":      func(d *Decision) { d.Evidence = nil },
		"empty evidence":        func(d *Decision) { d.Evidence = []string{" "} },
		"long evidence":         func(d *Decision) { d.Evidence = []string{strings.Repeat("x", 2001)} },
		"too much evidence":     func(d *Decision) { d.Evidence = make([]string, 17) },
	} {
		t.Run(name, func(t *testing.T) {
			d := valid()
			change(&d)
			if err := ValidateNoticeDisposition(d); err == nil {
				t.Fatal("accepted invalid non-notice disposition")
			}
		})
	}
	if err := ValidateNoticeDisposition(Decision{Assessment: "unknown"}); err != nil {
		t.Fatalf("changed existing unknown contract: %v", err)
	}
}
