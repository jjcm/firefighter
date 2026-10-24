package broadcast

import (
	"encoding/json"
	"math"
	"strings"
)

// CVSS is source-provided display metadata, not an assessment of this host or
// a client instruction. It is deliberately absent from the signed Notice type.
type CVSS struct {
	Score   float64 `json:"score"`
	Version string  `json:"version"`
	Source  string  `json:"source"`
}

func validCVSS(score *CVSS) bool {
	if score == nil || math.IsNaN(score.Score) || math.IsInf(score.Score, 0) || score.Score < 0 || score.Score > 10 {
		return false
	}
	switch score.Version {
	case "4.0", "3.1", "3.0", "2.0":
	default:
		return false
	}
	return score.Source != "" && strings.TrimSpace(score.Source) == score.Source && bounded(score.Source, 256) == score.Source
}

// nvdCVSS reads only a complete, matching NVD CVE record. In particular it does
// not recover numbers from truncated summaries, descriptions, or vector prose.
// The arrays and their Primary/Secondary type come from NVD's CVE API schema:
// https://csrc.nist.gov/schema/nvd/api/2.0/cve_api_json_2.0.schema
func nvdCVSS(id, body string) *CVSS {
	if !validCVEID(id) {
		return nil
	}
	var record struct {
		ID      string                     `json:"id"`
		Metrics map[string]json.RawMessage `json:"metrics"`
	}
	if json.Unmarshal([]byte(body), &record) != nil || record.ID != id {
		return nil
	}
	for _, family := range []struct{ key, version string }{
		{"cvssMetricV40", "4.0"},
		{"cvssMetricV31", "3.1"},
		{"cvssMetricV30", "3.0"},
		{"cvssMetricV2", "2.0"},
	} {
		var entries []json.RawMessage
		if json.Unmarshal(record.Metrics[family.key], &entries) != nil {
			continue
		}
		var selected *CVSS
		selectedPrimary := false
		for _, raw := range entries {
			var metric struct {
				Source string `json:"source"`
				Type   string `json:"type"`
				Data   struct {
					Version string   `json:"version"`
					Score   *float64 `json:"baseScore"`
				} `json:"cvssData"`
			}
			if json.Unmarshal(raw, &metric) != nil || metric.Data.Score == nil || metric.Data.Version != family.version ||
				(metric.Type != "Primary" && metric.Type != "Secondary") {
				continue
			}
			candidate := &CVSS{Score: *metric.Data.Score, Version: metric.Data.Version, Source: metric.Source}
			if !validCVSS(candidate) {
				continue
			}
			primary := metric.Type == "Primary"
			// Prefer the primary assessment within the newest supported version,
			// then source name, never the highest score across scoring authorities.
			// Duplicate assessments from the same source keep upstream ordering.
			if selected == nil || (primary && !selectedPrimary) || (primary == selectedPrimary && candidate.Source < selected.Source) {
				selected, selectedPrimary = candidate, primary
			}
		}
		if selected != nil {
			return selected
		}
	}
	return nil
}

// Older checkpoints retain only the bounded Notice summary. Seed metadata where
// it still contains complete NVD JSON; otherwise leave the display score absent.
// The next overlapping poll can populate metadata from the full upstream body.
func seedCVSS(state *diskState, cfg Config) {
	for i := range state.Notices {
		entry := &state.Notices[i]
		if !isNVDSource(cfg, entry.Notice.Source) {
			entry.CVSS = nil
			continue
		}
		if !validCVSS(entry.CVSS) {
			entry.CVSS = nvdCVSS(entry.Notice.ID, entry.Notice.Summary)
		}
	}
}
