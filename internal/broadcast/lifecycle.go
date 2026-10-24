package broadcast

import (
	"encoding/json"
	"strings"
	"time"

	"github.com/jjcm/firefighter/internal/intel"
)

// Lifecycle is private board metadata. Retraction notices still pass through the
// unchanged signed feed, letting clients reassess earlier vulnerability claims.
type cveLifecycle struct {
	Withdrawn  bool      `json:"withdrawn"`
	ModifiedAt time.Time `json:"modified_at"`
}

func validCVEID(id string) bool {
	cves := intel.ExtractCVEs(id)
	return len(cves) == 1 && cves[0] == id
}

func isNVDSource(cfg Config, name string) bool {
	for _, source := range cfg.Sources {
		if source.Name == name {
			return source.Type == "nvd"
		}
	}
	return false
}

func nvdLifecycle(id, title, body string, modified time.Time) (cveLifecycle, bool) {
	if !validCVEID(id) {
		return cveLifecycle{}, false
	}
	var record struct {
		ID           string `json:"id"`
		Status       string `json:"vulnStatus"`
		LastModified string `json:"lastModified"`
	}
	parsed := json.Unmarshal([]byte(body), &record) == nil && record.ID == id
	status := ""
	if parsed {
		status = strings.ToLower(strings.TrimSpace(record.Status))
		for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999999"} {
			if date, err := time.Parse(layout, record.LastModified); err == nil {
				modified = date.UTC()
				break
			}
		}
	}
	if modified.IsZero() {
		return cveLifecycle{}, false
	}
	// Before lifecycle metadata existed, only bounded NVD summaries were stored.
	// An explicit NVD rejection prefix also works when that JSON was truncated.
	// Ordinary prose containing "rejected" is deliberately not a lifecycle signal.
	description := strings.TrimSpace(strings.TrimPrefix(title, id+":"))
	description = strings.ToLower(description)
	legacyRejected := strings.HasPrefix(title, id+":") &&
		(strings.HasPrefix(description, "rejected reason:") ||
			strings.HasPrefix(description, "** reject **") ||
			strings.HasPrefix(description, "**reject**") ||
			strings.HasPrefix(description, "** rejected **") ||
			strings.HasPrefix(description, "**rejected**"))
	switch status {
	case "rejected", "withdrawn", "revoked":
		return cveLifecycle{Withdrawn: true, ModifiedAt: modified.UTC()}, true
	case "received", "awaiting analysis", "undergoing analysis", "analyzed", "modified", "deferred":
		return cveLifecycle{Withdrawn: legacyRejected, ModifiedAt: modified.UTC()}, true
	default:
		if legacyRejected {
			return cveLifecycle{Withdrawn: true, ModifiedAt: modified.UTC()}, true
		}
		return cveLifecycle{}, false
	}
}

func updateCVEStatus(statuses map[string]cveLifecycle, id string, candidate cveLifecycle) {
	previous, exists := statuses[id]
	// Overlapping polls may contain older versions. At equal timestamps favor
	// rejection; reinstatement requires a strictly newer official record.
	if !exists || candidate.ModifiedAt.After(previous.ModifiedAt) ||
		(candidate.ModifiedAt.Equal(previous.ModifiedAt) && candidate.Withdrawn) {
		statuses[id] = candidate
	}
}

func seedCVEStatuses(state *diskState, cfg Config) {
	if state.CVEStatuses == nil {
		state.CVEStatuses = make(map[string]cveLifecycle)
	}
	known := make(map[string]bool, len(state.CVEStatuses))
	for id := range state.CVEStatuses {
		known[id] = true
	}
	for i, entry := range state.Notices {
		n := entry.Notice
		if isNVDSource(cfg, n.Source) {
			if status, ok := nvdLifecycle(n.ID, n.Title, n.Summary, n.ObservedAt); ok {
				state.Notices[i].Withdrawn = state.Notices[i].Withdrawn || status.Withdrawn
				if !known[n.ID] {
					updateCVEStatus(state.CVEStatuses, n.ID, status)
				}
			}
		}
	}
}

func noticeWithdrawn(notice Notice, statuses map[string]cveLifecycle) bool {
	for _, id := range notice.CVEs {
		if statuses[id].Withdrawn {
			return true
		}
	}
	return false
}

func pruneCVEStatuses(state *diskState) {
	referenced := make(map[string]bool)
	for _, entry := range state.Notices {
		for _, id := range entry.Notice.CVEs {
			referenced[id] = true
		}
	}
	for id, status := range state.CVEStatuses {
		// Remember retractions after notice retention expires: a later vendor
		// mention must not put a known withdrawn CVE back on the public board.
		if !status.Withdrawn && !referenced[id] {
			delete(state.CVEStatuses, id)
		}
	}
}
