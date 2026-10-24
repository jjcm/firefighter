package planner

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

type CommandConfig struct {
	Argv             []string
	Dir              string
	Timeout          time.Duration
	MaxActions       int
	MaxResponseBytes int
	// Env explicitly supplies variables needed by the adapter (for example a local
	// inference endpoint). The ambient environment is NOT inherited in full.
	Env []string
}

type Command struct{ config CommandConfig }

func NewCommand(cfg CommandConfig) (*Command, error) {
	if err := validateArgv(cfg.Argv); err != nil {
		return nil, err
	}
	if !filepath.IsAbs(cfg.Argv[0]) {
		return nil, errors.New("command planner executable must use an absolute path")
	}
	if cfg.Dir != "" && !filepath.IsAbs(cfg.Dir) {
		return nil, errors.New("command planner dir must use an absolute path")
	}
	var err error
	cfg.MaxActions, cfg.MaxResponseBytes, err = limits(cfg.MaxActions, cfg.MaxResponseBytes)
	if err != nil {
		return nil, err
	}
	if cfg.Timeout == 0 {
		cfg.Timeout = 2 * time.Minute
	}
	if cfg.Timeout < time.Millisecond || cfg.Timeout > 30*time.Minute {
		return nil, errors.New("planner timeout must be positive and at most 30 minutes")
	}
	for _, v := range cfg.Env {
		if !strings.Contains(v, "=") || strings.ContainsRune(v, 0) {
			return nil, errors.New("invalid command planner environment")
		}
	}
	return &Command{config: cfg}, nil
}

// Decide writes one Request on stdin. Instructions contains the immutable agent
// policy plus operator instructions. Adapters must return only Decision JSON on
// stdout; stderr is deliberately discarded to avoid leaking provider secrets.
func (c *Command) Decide(ctx context.Context, request protocol.Request) (protocol.Decision, error) {
	var zero protocol.Decision
	request.Instructions = SystemPrompt + fmt.Sprintf("\nMaximum actions: %d. Decision schema: %s\nOPERATOR POLICY:\n", c.config.MaxActions, mustSchemaJSON()) + request.Instructions
	body, err := json.Marshal(request)
	if err != nil {
		return zero, errors.New("cannot encode command planner request")
	}
	if len(body) > 4<<20 {
		return zero, errors.New("planner observations exceed 4 MiB")
	}
	ctx, cancel := context.WithTimeout(ctx, c.config.Timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, c.config.Argv[0], c.config.Argv[1:]...)
	cmd.Dir = c.config.Dir
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", "LANG=C.UTF-8", "LC_ALL=C.UTF-8"}
	if value := os.Getenv("HOME"); value != "" {
		cmd.Env = append(cmd.Env, "HOME="+value)
	}
	cmd.Env = append(cmd.Env, c.config.Env...)
	cmd.Stdin = bytes.NewReader(body)
	out := &boundedWriter{max: c.config.MaxResponseBytes, onLimit: cancel}
	cmd.Stdout = out
	cmd.Stderr = io.Discard
	cmd.WaitDelay = time.Second
	configureCancellation(cmd)
	err = cmd.Run()
	if out.exceeded {
		return zero, errors.New("command planner response exceeded byte limit")
	}
	if ctx.Err() != nil {
		return zero, fmt.Errorf("command planner interrupted: %w", ctx.Err())
	}
	if err != nil {
		return zero, errors.New("command planner failed; inspect adapter locally without exposing credentials")
	}
	return ParseDecision(out.buf.Bytes(), c.config.MaxActions)
}

type boundedWriter struct {
	buf      bytes.Buffer
	max      int
	exceeded bool
	onLimit  func()
}

func (w *boundedWriter) Write(p []byte) (int, error) {
	n := len(p)
	if remaining := w.max - w.buf.Len(); len(p) > remaining {
		p = p[:remaining]
		w.exceeded = true
	}
	_, _ = w.buf.Write(p)
	if w.exceeded && w.onLimit != nil {
		w.onLimit()
	}
	return n, nil
}
