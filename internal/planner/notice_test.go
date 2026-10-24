package planner

import (
	"strings"
	"testing"
)

func TestParseExplicitNonNotice(t *testing.T) {
	body := `{"summary":"Source is conference promotion","assessment":"not_a_notice","applicability":{"status":"unknown","product":"","condition":"","evidence":[]},"evidence":["The text promotes a conference and contains no vulnerability or exploitation claim."],"actions":[],"done":true,"memory_updates":[]}`
	if _, err := ParseDecision([]byte(body), 8); err != nil {
		t.Fatal(err)
	}
	for _, invalid := range []string{
		strings.Replace(body, `"done":true`, `"done":false`, 1),
		strings.Replace(body, `"actions":[]`, `"actions":[{"id":"probe","kind":"command","argv":["/bin/true"],"reason":"probe","mutates":false}]`, 1),
		strings.Replace(body, `"The text promotes a conference and contains no vulnerability or exploitation claim."`, `""`, 1),
	} {
		if _, err := ParseDecision([]byte(invalid), 8); err == nil {
			t.Fatal("parser accepted invalid non-notice")
		}
	}
}
