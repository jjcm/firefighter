//go:build linux || darwin

package host

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jjcm/firefighter/internal/protocol"
)

func command(args ...string) protocol.Action {
	return protocol.Action{ID: "test-action", Kind: "command", Argv: args}
}

func TestValidateRejectsMalformedActions(t *testing.T) {
	cases := []struct {
		name   string
		action protocol.Action
	}{
		{"unknown kind", protocol.Action{ID: "test", Kind: "download", Argv: []string{"true"}}},
		{"missing id", protocol.Action{Kind: "command", Argv: []string{"true"}}},
		{"missing executable", command()},
		{"empty executable", command("")},
		{"relative executable", command("./tool")},
		{"relative path", command("bin/tool")},
		{"NUL executable", command("/bin/tr\x00ue")},
		{"NUL argument", command("/bin/echo", "a\x00b")},
		{"relative cwd", protocol.Action{ID: "test", Kind: "command", Argv: []string{"true"}, Dir: "here"}},
		{"NUL cwd", protocol.Action{ID: "test", Kind: "command", Argv: []string{"true"}, Dir: "/tmp\x00"}},
		{"negative timeout", protocol.Action{ID: "test", Kind: "command", Argv: []string{"true"}, TimeoutSeconds: -1}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := Validate(tc.action); err == nil {
				t.Fatal("expected validation failure")
			}
		})
	}
	if err := Validate(command("/bin/echo", "")); err != nil {
		t.Fatalf("empty non-executable argument is valid: %v", err)
	}
}

func TestRunnerCapsAndRedactsCombinedOutput(t *testing.T) {
	secret := "test-only-sensitive-value"
	runner := NewRunner(Config{MaxOutputBytes: 64, Redact: func(s string) string { return strings.ReplaceAll(s, secret, "[REDACTED]") }})
	result := runner.Run(context.Background(), command("/bin/sh", "-c", "printf '%s\\n' '"+secret+"'; printf 'stderr\\n' >&2; printf '%0200d' 1"))
	if result.ExitCode != 0 || result.Error != "" {
		t.Fatalf("unexpected command failure: %+v", result)
	}
	if !result.Truncated || len(result.Output) > 64 {
		t.Fatalf("output not bounded: %+v", result)
	}
	if strings.Contains(result.Output, secret) || !strings.Contains(result.Output, "[REDACTED]") {
		t.Fatalf("secret not redacted: %q", result.Output)
	}
	if !strings.Contains(result.Output, "stderr") {
		t.Fatalf("stderr was not captured: %q", result.Output)
	}
}

func TestRunnerRedactsErrors(t *testing.T) {
	runner := NewRunner(Config{Redact: func(s string) string { return strings.ReplaceAll(s, "secret-filename", "[REDACTED]") }})
	result := runner.Run(context.Background(), command("/does-not-exist/secret-filename"))
	if !result.Skipped || result.ExitCode != -1 || strings.Contains(result.Error, "secret-filename") || !strings.Contains(result.Error, "[REDACTED]") {
		t.Fatalf("bad redaction/error result: %+v", result)
	}
}

func TestRunnerDoesNotInheritSecretsOrWorkingDirectory(t *testing.T) {
	t.Setenv("OPENAI_API_KEY", "test-parent-secret")
	t.Setenv("FIREFIGHTER_REPORT_TOKEN", "test-report-secret")
	t.Setenv("HOME", "/parent/home")
	t.Setenv("PATH", t.TempDir())
	runner := NewRunner(Config{})
	result := runner.Run(context.Background(), command("sh", "-c", "printf '%s\\n' \"${OPENAI_API_KEY-unset}\" \"${FIREFIGHTER_REPORT_TOKEN-unset}\" \"$PATH\" \"$HOME\"; pwd"))
	if result.Error != "" || result.ExitCode != 0 {
		t.Fatalf("command failed: %+v", result)
	}
	if strings.Contains(result.Output, "secret") || strings.Contains(result.Output, "/parent/home") {
		t.Fatalf("inherited sensitive environment: %q", result.Output)
	}
	wantHome := "/"
	if os.Geteuid() == 0 {
		wantHome = "/root"
	}
	if want := "unset\nunset\n" + TrustedPath + "\n" + wantHome + "\n/\n"; result.Output != want {
		t.Fatalf("environment or cwd mismatch: got %q, want %q", result.Output, want)
	}
}

func TestRunnerHonorsCWDAndArgvWithoutImplicitShell(t *testing.T) {
	dir := t.TempDir()
	resolvedDir, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	action := command("/bin/sh", "-c", "printf '%s\\n' \"$PWD\" \"$1\"", "test", "hello; exit 19")
	action.Dir = dir
	result := NewRunner(Config{}).Run(context.Background(), action)
	if result.Error != "" || result.ExitCode != 0 || result.Output != resolvedDir+"\nhello; exit 19\n" {
		t.Fatalf("unexpected command handling: %+v", result)
	}
}

func TestRunnerExitAndStartFailures(t *testing.T) {
	runner := NewRunner(Config{})
	result := runner.Run(context.Background(), command("/bin/sh", "-c", "printf 'failed\\n' >&2; exit 23"))
	if result.ExitCode != 23 || result.Error == "" || result.Output != "failed\n" || result.Skipped {
		t.Fatalf("nonzero exit was not preserved: %+v", result)
	}
	result = runner.Run(context.Background(), command("firefighter-no-such-executable"))
	if !result.Skipped || result.Error == "" || result.ExitCode != -1 {
		t.Fatalf("missing executable was not explicit: %+v", result)
	}
	if result.StartedAt.IsZero() || result.FinishedAt.Before(result.StartedAt) {
		t.Fatalf("invalid execution timestamps: %+v", result)
	}
}

func TestRunnerTimeoutKillsChildProcesses(t *testing.T) {
	dir := t.TempDir()
	pidPath := filepath.Join(dir, "child.pid")
	result := NewRunner(Config{MaxTimeout: 250 * time.Millisecond}).Run(context.Background(), command("/bin/sh", "-c", "sleep 30 & child=$!; printf '%s' \"$child\" > \"$1\"; wait", "test", pidPath))
	if !result.TimedOut || result.Error == "" || result.Skipped {
		t.Fatalf("expected timeout: %+v", result)
	}
	data, err := os.ReadFile(pidPath)
	if err != nil {
		t.Fatal(err)
	}
	pid, err := strconv.Atoi(string(data))
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		if syscall.Kill(pid, 0) != nil {
			return
		}
		// An orphan can briefly remain a zombie until PID 1 reaps it. It has
		// already terminated, so is not a surviving child execution.
		state, _ := exec.Command("/bin/ps", "-o", "stat=", "-p", strconv.Itoa(pid)).Output()
		if strings.HasPrefix(strings.TrimSpace(string(state)), "Z") {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	_ = syscall.Kill(pid, syscall.SIGKILL)
	t.Fatalf("child process %d survived group timeout", pid)
}

func TestRunnerCancellationAndTimeoutValidation(t *testing.T) {
	runner := NewRunner(Config{MaxTimeout: 2 * time.Second})
	action := command("/bin/sh", "-c", "exit 0")
	action.TimeoutSeconds = 3
	if result := runner.Run(context.Background(), action); !result.Skipped || result.Error == "" {
		t.Fatalf("excessive timeout was accepted: %+v", result)
	}
	action.TimeoutSeconds = int(^uint(0) >> 1)
	if err := runner.Validate(action); err == nil {
		t.Fatal("overflow-sized timeout accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	result := runner.Run(ctx, command("/bin/sh", "-c", "exit 0"))
	if !result.Skipped || result.TimedOut || result.Error != context.Canceled.Error() {
		t.Fatalf("bad cancellation result: %+v", result)
	}
}

func TestRunnerCancelsRunningCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() {
		time.Sleep(50 * time.Millisecond)
		cancel()
	}()
	result := NewRunner(Config{}).Run(ctx, command("/bin/sh", "-c", "sleep 30"))
	if result.Skipped || result.TimedOut || result.Error != context.Canceled.Error() {
		t.Fatalf("running cancellation not preserved: %+v", result)
	}
	if result.FinishedAt.Sub(result.StartedAt) > 2*time.Second {
		t.Fatalf("cancellation took too long: %+v", result)
	}
}

func TestRunnerBoundsRedactionExpansionAndUTF8(t *testing.T) {
	runner := NewRunner(Config{MaxOutputBytes: 4, Redact: func(string) string { return "\u20ac\u20ac" }})
	result := runner.Run(context.Background(), command("/bin/sh", "-c", "printf 'x'"))
	if !result.Truncated || len(result.Output) > 4 || !utf8.ValidString(result.Output) {
		t.Fatalf("redacted output is invalid or unbounded: %+v", result)
	}
}

func TestBoundedOutputAlwaysDrains(t *testing.T) {
	b := &boundedOutput{limit: 4}
	if n, err := b.Write([]byte("123456")); err != nil || n != 6 {
		t.Fatalf("short write would interfere with child: n=%d err=%v", n, err)
	}
	if n, err := b.Write([]byte("789")); err != nil || n != 3 {
		t.Fatalf("write after cap failed: n=%d err=%v", n, err)
	}
	if got, truncated := b.snapshot(); got != "1234" || !truncated {
		t.Fatalf("bad capped output: %q %v", got, truncated)
	}
}
