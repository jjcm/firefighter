package protocol

import (
	"strings"
	"testing"
)

func TestValidateApplicability(t *testing.T) {
	for _, tc := range []struct {
		name  string
		claim *Applicability
		valid bool
	}{
		{"legacy omission", nil, true},
		{"unknown", &Applicability{Status: "unknown"}, true},
		{"affected version", &Applicability{Status: "affected", Product: "example", Condition: "installed 1.2 is within affected versions 1.0 through 1.3", Evidence: []string{"installed package inventory at current collection time: example 1.2"}}, true},
		{"absent prerequisite", &Applicability{Status: "not_affected", Product: "WordPress plugin", Condition: "WordPress deployment prerequisite absent in inventoried deployment scope", Evidence: []string{"current deployment inventory and recent complete scoped application check found no WordPress"}}, true},
		{"invalid status", &Applicability{Status: "clean"}, false},
		{"empty status", &Applicability{}, false},
		{"affected lacks product", &Applicability{Status: "affected", Condition: "affected version", Evidence: []string{"current local version"}}, false},
		{"affected lacks condition", &Applicability{Status: "affected", Product: "example", Evidence: []string{"current local version"}}, false},
		{"affected lacks evidence", &Applicability{Status: "affected", Product: "example", Condition: "affected version"}, false},
		{"absent lacks evidence", &Applicability{Status: "not_affected", Product: "example", Condition: "not installed"}, false},
		{"whitespace condition", &Applicability{Status: "not_affected", Product: "example", Condition: " \n", Evidence: []string{"scoped absence"}}, false},
		{"blank evidence", &Applicability{Status: "affected", Product: "example", Condition: "affected version", Evidence: []string{" \n"}}, false},
		{"overlong unknown product", &Applicability{Status: "unknown", Product: strings.Repeat("x", 501)}, false},
		{"overlong condition", &Applicability{Status: "unknown", Condition: strings.Repeat("x", 2001)}, false},
		{"too many evidence entries", &Applicability{Status: "unknown", Evidence: make([]string, 17)}, false},
		{"overlong evidence", &Applicability{Status: "unknown", Evidence: []string{strings.Repeat("x", 2001)}}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := ValidateApplicability(tc.claim); (err == nil) != tc.valid {
				t.Fatalf("valid=%t, validation error=%v", tc.valid, err)
			}
		})
	}
}
