package host

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

type Package struct {
	Name         string `json:"name"`
	Version      string `json:"version"`
	Architecture string `json:"architecture,omitempty"`
	Manager      string `json:"manager"`
}

type Problem struct {
	Probe  string `json:"probe"`
	Kind   string `json:"kind"`
	Detail string `json:"detail"`
}

type ProbeStatus struct {
	Name      string `json:"name"`
	ExitCode  int    `json:"exit_code"`
	Error     string `json:"error,omitempty"`
	Truncated bool   `json:"truncated,omitempty"`
	TimedOut  bool   `json:"timed_out,omitempty"`
}

type ToolStatus struct {
	Name      string `json:"name"`
	Available bool   `json:"available"`
	Path      string `json:"path,omitempty"`
}

// Snapshot is evidence, not an attestation that the host is uncompromised.
// Missing permissions, tools, failed probes, and truncated output are explicit.
// Process inventory includes executable names only, never command arguments or
// environments. Application dependencies require incident-specific follow-up.
type Snapshot struct {
	CollectedAt      time.Time         `json:"collected_at"`
	Hostname         string            `json:"hostname"`
	Platform         string            `json:"platform"`
	Architecture     string            `json:"architecture"`
	EffectiveUID     int               `json:"effective_uid"`
	IsRoot           bool              `json:"is_root"`
	OSRelease        map[string]string `json:"os_release,omitempty"`
	Kernel           string            `json:"kernel,omitempty"`
	PackageManager   string            `json:"package_manager,omitempty"`
	Packages         []Package         `json:"packages,omitempty"`
	PackageUpdates   string            `json:"package_updates_from_local_cache,omitempty"`
	Scanners         []ToolStatus      `json:"scanners,omitempty"`
	Processes        string            `json:"processes,omitempty"`
	ListeningSockets string            `json:"listening_sockets,omitempty"`
	Services         string            `json:"services,omitempty"`
	Containers       string            `json:"containers,omitempty"`
	Probes           []ProbeStatus     `json:"probes"`
	Problems         []Problem         `json:"problems"`
}

type inventoryProbe struct {
	name     string
	argv     []string
	maxBytes int
}

// Collect performs fixed Linux observation probes with ten-second command
// limits and bounded output. Partial inventory is returned successfully with
// Problems; only context cancellation returns an error. It does not invoke
// container clients, install tools, access process environments, or inspect
// container secrets. Container workload coverage remains explicitly incomplete.
func Collect(ctx context.Context) (Snapshot, error) {
	return collectInventory(ctx, runtime.GOOS, resolveExecutable, runInventoryProbe)
}

func collectInventory(ctx context.Context, platform string, resolve func(string) (string, error), run func(context.Context, inventoryProbe) protocol.ActionResult) (Snapshot, error) {
	snapshot := Snapshot{
		CollectedAt: time.Now().UTC(), Platform: platform,
		Architecture: runtime.GOARCH, EffectiveUID: os.Geteuid(),
		IsRoot: os.Geteuid() == 0, Probes: []ProbeStatus{}, Problems: []Problem{},
	}
	var err error
	snapshot.Hostname, err = os.Hostname()
	if err != nil {
		snapshot.Problems = append(snapshot.Problems, Problem{"hostname", "read_failed", err.Error()})
	}
	if err := ctx.Err(); err != nil {
		return snapshot, err
	}
	if platform != "linux" {
		snapshot.Problems = append(snapshot.Problems, Problem{"platform", "unsupported", "host inventory requires Linux; no platform probes were executed"})
		return snapshot, nil
	}
	if !snapshot.IsRoot {
		snapshot.Problems = append(snapshot.Problems, Problem{"permissions", "limited_permissions", "not running as root; process, socket, service, and container visibility may be incomplete"})
	}
	release, err := readBoundedFile("/etc/os-release", 64<<10)
	if err != nil {
		snapshot.Problems = append(snapshot.Problems, Problem{"os_release", "read_failed", err.Error()})
	}
	snapshot.OSRelease = parseOSRelease(release)
	for _, name := range []string{"trivy", "grype", "clamscan", "debsums", "needrestart"} {
		path, err := resolve(name)
		snapshot.Scanners = append(snapshot.Scanners, ToolStatus{Name: name, Available: err == nil, Path: path})
	}
	// A runtime client's "list" command can trigger an installer or socket
	// activation, and its saved context can point off-host. Keep discovery
	// passive; targeted runtime inspection belongs to an evidenced model action.
	snapshot.Problems = append(snapshot.Problems, Problem{"containers", "not_collected", "Container workloads were not enumerated: automatic runtime client calls can install software, activate daemons, or use remote contexts. Package, process, and service observations remain available; container absence is not established."})
	probes := []inventoryProbe{
		{"kernel", []string{"uname", "-sr"}, 4 << 10},
		{"processes", []string{"ps", "-eo", "pid,ppid,user,comm"}, 256 << 10},
		{"listeners", []string{"ss", "-lntup"}, 256 << 10},
		{"services", []string{"systemctl", "list-units", "--type=service", "--all", "--no-pager", "--plain"}, 256 << 10},
	}
	if _, err := resolve("ss"); err != nil {
		if _, netstatErr := resolve("netstat"); netstatErr == nil {
			probes[2].argv = []string{"netstat", "-lntup"}
		}
	}
	manager, packageArgs := selectPackageManager(resolve)
	snapshot.PackageManager = manager
	if manager == "" {
		snapshot.Problems = append(snapshot.Problems, Problem{"packages", "tool_unavailable", "no supported package inventory tool found (dpkg-query, rpm, apk)"})
	} else {
		probes = append(probes, inventoryProbe{"packages", packageArgs, 256 << 10})
		if manager == "dpkg" {
			// This is only the locally cached view. Refreshing repository metadata
			// is an explicit action for the engine, not an inventory side effect.
			probes = append(probes, inventoryProbe{"package_updates", []string{"apt", "list", "--upgradable"}, 64 << 10})
		}
	}
	results := make([]protocol.ActionResult, len(probes))
	var wg sync.WaitGroup
	for i, probe := range probes {
		wg.Add(1)
		go func(i int, probe inventoryProbe) {
			defer wg.Done()
			results[i] = run(ctx, probe)
		}(i, probe)
	}
	wg.Wait()
	for i, result := range results {
		probe := probes[i]
		snapshot.Probes = append(snapshot.Probes, ProbeStatus{probe.name, result.ExitCode, result.Error, result.Truncated, result.TimedOut})
		if result.Error != "" || result.ExitCode != 0 {
			detail := result.Error
			if result.Output != "" {
				detail += ": " + validPrefix(result.Output, min(len(result.Output), 2048))
			}
			kind := "probe_failed"
			if result.Skipped {
				kind = "tool_unavailable"
			}
			snapshot.Problems = append(snapshot.Problems, Problem{probe.name, kind, detail})
		}
		if result.Truncated {
			snapshot.Problems = append(snapshot.Problems, Problem{probe.name, "truncated", fmt.Sprintf("probe exceeded %d bytes; inventory is incomplete", probe.maxBytes)})
		}
		switch probe.name {
		case "kernel":
			snapshot.Kernel = strings.TrimSpace(result.Output)
		case "processes":
			snapshot.Processes = result.Output
		case "listeners":
			snapshot.ListeningSockets = result.Output
		case "services":
			snapshot.Services = result.Output
		case "packages":
			if result.ExitCode == 0 {
				snapshot.Packages = parsePackages(manager, result.Output, result.Truncated)
			}
		case "package_updates":
			snapshot.PackageUpdates = result.Output
		}
	}
	return snapshot, ctx.Err()
}

func runInventoryProbe(ctx context.Context, probe inventoryProbe) protocol.ActionResult {
	runner := NewRunner(Config{MaxTimeout: 10 * time.Second, MaxOutputBytes: probe.maxBytes})
	return runner.Run(ctx, protocol.Action{ID: "inventory-" + probe.name, Kind: "command", Argv: probe.argv, TimeoutSeconds: 10, Reason: "read-only host inventory"})
}

func selectPackageManager(resolve func(string) (string, error)) (string, []string) {
	for _, candidate := range []struct {
		name string
		argv []string
	}{
		{"dpkg", []string{"dpkg-query", "-W", "-f=${binary:Package}\t${Version}\t${Architecture}\t${db:Status-Status}\n"}},
		{"rpm", []string{"rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\t%{ARCH}\n"}},
		{"apk", []string{"apk", "info", "-v"}},
	} {
		if _, err := resolve(candidate.argv[0]); err == nil {
			return candidate.name, candidate.argv
		}
	}
	return "", nil
}

func readBoundedFile(path string, limit int64) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if int64(len(data)) > limit {
		return string(data[:limit]), fmt.Errorf("%s exceeds %d bytes; content truncated", path, limit)
	}
	return string(data), err
}

func parseOSRelease(raw string) map[string]string {
	values := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(raw))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		value = strings.TrimSpace(value)
		if len(value) >= 2 && ((value[0] == '"' && value[len(value)-1] == '"') || (value[0] == '\'' && value[len(value)-1] == '\'')) {
			value = value[1 : len(value)-1]
		}
		values[strings.TrimSpace(key)] = value
	}
	return values
}

func parsePackages(manager, raw string, truncated bool) []Package {
	// An incomplete trailing record is not reliable package-version evidence.
	if truncated && !strings.HasSuffix(raw, "\n") {
		if end := strings.LastIndexByte(raw, '\n'); end >= 0 {
			raw = raw[:end+1]
		} else {
			raw = ""
		}
	}
	packages := []Package{}
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if manager == "apk" {
			for i := len(line) - 2; i > 0; i-- {
				if line[i] == '-' && line[i+1] >= '0' && line[i+1] <= '9' {
					packages = append(packages, Package{Name: line[:i], Version: line[i+1:], Manager: manager})
					break
				}
			}
			continue
		}
		parts := strings.Split(line, "\t")
		if manager == "dpkg" {
			if len(parts) != 4 || parts[3] != "installed" {
				continue
			}
		} else if len(parts) != 3 {
			continue
		}
		if parts[0] == "" || parts[1] == "" {
			continue
		}
		packages = append(packages, Package{Name: parts[0], Version: parts[1], Architecture: parts[2], Manager: manager})
	}
	return packages
}
