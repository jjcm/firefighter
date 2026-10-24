// Package host collects bounded host evidence and executes explicitly planned
// commands. It is an execution mechanism, not an approval or policy layer.
// Callers must durably journal an action before passing it to Runner.Run.
package host

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

const TrustedPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

// Config bounds command execution. Redact must be safe for concurrent calls and
// remove configured credentials from both output and error messages. The runner
// never inherits the daemon's environment, including provider or report tokens.
type Config struct {
	MaxTimeout     time.Duration
	MaxOutputBytes int
	Redact         func(string) string
}

type Runner struct {
	config Config
}

func NewRunner(config Config) *Runner {
	if config.MaxTimeout <= 0 {
		config.MaxTimeout = 5 * time.Minute
	}
	if config.MaxOutputBytes <= 0 {
		config.MaxOutputBytes = 64 << 10
	}
	if config.Redact == nil {
		config.Redact = func(s string) string { return s }
	}
	return &Runner{config: config}
}

// Validate checks action syntax without executing it. Executables must be
// absolute paths or simple names resolved using TrustedPath, without whitespace
// or control characters. Relative paths and relative working directories are
// rejected. Shell syntax is interpreted only when an action explicitly invokes
// a shell, for example /bin/sh -c.
func Validate(action protocol.Action) error {
	if action.Kind != "command" {
		return fmt.Errorf("unsupported action kind %q", action.Kind)
	}
	if strings.TrimSpace(action.ID) == "" || strings.ContainsRune(action.ID, '\x00') {
		return errors.New("action id must be nonempty and contain no NUL bytes")
	}
	if len(action.Argv) == 0 {
		return errors.New("command argv must include an executable")
	}
	if err := protocol.ValidateExecutable(action.Argv[0]); err != nil {
		return err
	}
	for _, arg := range action.Argv {
		if strings.ContainsRune(arg, '\x00') {
			return errors.New("command arguments must not contain NUL bytes")
		}
	}
	if action.Dir != "" && (!filepath.IsAbs(action.Dir) || strings.ContainsRune(action.Dir, '\x00')) {
		return errors.New("working directory must be an absolute path without NUL bytes")
	}
	if action.TimeoutSeconds < 0 {
		return errors.New("timeout_seconds must not be negative")
	}
	return nil
}

func (r *Runner) Validate(action protocol.Action) error {
	if err := Validate(action); err != nil {
		return err
	}
	if action.TimeoutSeconds > 0 && int64(action.TimeoutSeconds) > int64(r.config.MaxTimeout/time.Second) {
		return fmt.Errorf("requested timeout exceeds configured maximum %s", r.config.MaxTimeout)
	}
	return nil
}

// Run executes one command without approval prompts. The working directory
// defaults to /, and the environment contains only a fixed PATH, HOME, locale,
// and noninteractive package-manager setting. On Linux and macOS a timeout or
// cancellation kills the command's process group, including ordinary child
// processes. A deliberately detached process can escape a Unix process group;
// this is not an isolation sandbox. The daemon's service cgroup is the outer
// lifecycle boundary. Rollback and Verify are engine-owned follow-up commands.
func (r *Runner) Run(ctx context.Context, action protocol.Action) (result protocol.ActionResult) {
	result = protocol.ActionResult{ActionID: action.ID, StartedAt: time.Now().UTC(), ExitCode: -1}
	defer func() {
		result.FinishedAt = time.Now().UTC()
		result.Error = r.config.Redact(result.Error)
	}()
	if err := r.Validate(action); err != nil {
		result.Error = err.Error()
		result.Skipped = true
		return
	}
	if err := ctx.Err(); err != nil {
		result.Error = err.Error()
		result.TimedOut = errors.Is(err, context.DeadlineExceeded)
		result.Skipped = true
		return
	}
	executable, err := resolveExecutable(action.Argv[0])
	if err != nil {
		result.Error = err.Error()
		result.Skipped = true
		return
	}
	timeout := min(time.Minute, r.config.MaxTimeout)
	if action.TimeoutSeconds > 0 {
		timeout = time.Duration(action.TimeoutSeconds) * time.Second
	}
	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.Command(executable, action.Argv[1:]...)
	cmd.Dir = action.Dir
	if cmd.Dir == "" {
		cmd.Dir = "/"
	}
	home := "/"
	if os.Geteuid() == 0 {
		home = "/root"
	}
	cmd.Env = []string{"PATH=" + TrustedPath, "HOME=" + home, "LANG=C", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	if err := configureProcessGroup(cmd); err != nil {
		result.Error = err.Error()
		result.Skipped = true
		return
	}
	// Bound inherited-pipe waits as well as process runtime. A command that
	// backgrounds a child while retaining its output pipe cannot hang the agent.
	cmd.WaitDelay = time.Second
	output := &boundedOutput{limit: r.config.MaxOutputBytes}
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		result.Error = fmt.Sprintf("start command: %v", err)
		result.Skipped = true
		return
	}
	waited := make(chan error, 1)
	go func() { waited <- cmd.Wait() }()
	select {
	case err = <-waited:
		if errors.Is(err, exec.ErrWaitDelay) {
			_ = killProcessGroup(cmd)
		}
	case <-runCtx.Done():
		killErr := killProcessGroup(cmd)
		err = <-waited
		result.TimedOut = errors.Is(runCtx.Err(), context.DeadlineExceeded)
		result.Error = runCtx.Err().Error()
		if killErr != nil {
			result.Error += "; kill process group: " + killErr.Error()
		}
	}
	if cmd.ProcessState != nil {
		result.ExitCode = cmd.ProcessState.ExitCode()
	}
	if err != nil && result.Error == "" {
		result.Error = err.Error()
	}
	raw, truncated := output.snapshot()
	result.Output = strings.ToValidUTF8(r.config.Redact(raw), "\uFFFD")
	result.Truncated = truncated
	if len(result.Output) > r.config.MaxOutputBytes {
		result.Output = validPrefix(result.Output, r.config.MaxOutputBytes)
		result.Truncated = true
	}
	return
}

// resolveExecutable deliberately does not consult the caller's PATH or cwd.
func resolveExecutable(name string) (string, error) {
	if filepath.IsAbs(name) {
		return name, nil // Start supplies accurate missing-file/permission errors.
	}
	for _, dir := range strings.Split(TrustedPath, ":") {
		candidate := filepath.Join(dir, name)
		info, err := os.Stat(candidate)
		if err == nil && !info.IsDir() && info.Mode().Perm()&0111 != 0 {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("executable %q not found on trusted PATH", name)
}

type boundedOutput struct {
	mu        sync.Mutex
	data      []byte
	limit     int
	truncated bool
}

func (b *boundedOutput) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	n := len(p)
	remaining := b.limit - len(b.data)
	if len(p) > remaining {
		b.truncated = true
		p = p[:remaining]
	}
	b.data = append(b.data, p...)
	return n, nil // Always drain the child, including bytes beyond the limit.
}

func (b *boundedOutput) snapshot() (string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return string(b.data), b.truncated
}

func validPrefix(s string, n int) string {
	return strings.ToValidUTF8(s[:n], "")
}
