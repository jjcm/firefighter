package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"syscall"
	"time"

	"github.com/jjcm/firefighter/internal/config"
	"github.com/jjcm/firefighter/internal/engine"
	"github.com/jjcm/firefighter/internal/host"
	"github.com/jjcm/firefighter/internal/intel"
	"github.com/jjcm/firefighter/internal/planner"
	"github.com/jjcm/firefighter/internal/report"
	"github.com/jjcm/firefighter/internal/store"
)

var version = "dev"

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "firefighter:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	if args[0] == "version" {
		fmt.Println(version)
		return nil
	}
	if args[0] == "help" || args[0] == "--help" {
		usage()
		return nil
	}
	command := args[0]
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("config", "/etc/firefighter/config.json", "configuration file")
	observe := flags.Bool("observe", false, "collect inventory and plans, execute no model-generated command")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if command == "init" {
		if err := os.MkdirAll(filepath.Dir(*path), 0700); err != nil {
			return err
		}
		f, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			return err
		}
		defer f.Close()
		encoder := json.NewEncoder(f)
		encoder.SetIndent("", "  ")
		if err = encoder.Encode(config.Default()); err != nil {
			return err
		}
		fmt.Println("Created", *path)
		return nil
	}
	if command != "run" && command != "once" && command != "doctor" && command != "status" {
		return fmt.Errorf("unknown command %q", command)
	}
	c, err := config.Load(*path)
	if err != nil {
		return err
	}
	if *observe {
		c.Observe = true
	}
	if command == "status" {
		return status(c)
	}
	if command == "doctor" {
		return doctor(c)
	}
	if !c.Observe && runtime.GOOS != "linux" {
		return errors.New("autonomous execution requires Linux; use --observe for development")
	}
	if c.RequireRoot && !c.Observe && os.Geteuid() != 0 {
		return errors.New("autonomous mode requires root with this configuration")
	}
	p, err := buildPlanner(c)
	if err != nil {
		return err
	}
	sources, err := buildSources(c)
	if err != nil {
		return err
	}
	var sender report.Sender
	if c.Report.URL != "" {
		sender, err = report.New(c.Report.URL, os.Getenv(c.Report.SecretEnv), os.Getenv(c.Report.BearerTokenEnv))
		if err != nil {
			return err
		}
	}
	secrets := []string{os.Getenv(c.LLM.APIKeyEnv), os.Getenv(c.Report.SecretEnv), os.Getenv(c.Report.BearerTokenEnv)}
	for _, s := range c.Sources {
		secrets = append(secrets, os.Getenv(s.TokenEnv))
	}
	redact := report.Redactor(secrets...)
	disk, state, err := store.Open(c.StateDir)
	if err != nil {
		return err
	}
	defer disk.Close()
	// An endpoint or query change starts a new cursor namespace.
	for _, source := range c.Sources {
		b, _ := json.Marshal(source)
		sum := sha256.Sum256(b)
		fingerprint := hex.EncodeToString(sum[:])
		ss := state.Sources[source.Name]
		if ss.Fingerprint != fingerprint {
			ss.Cursor = ""
			ss.NextPoll = time.Time{}
			ss.Fingerprint = fingerprint
			state.Sources[source.Name] = ss
		}
	}
	if err = disk.Save(state); err != nil {
		return err
	}
	hostname, _ := os.Hostname()
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	app := &engine.Engine{Config: c, Store: disk, State: state, Planner: p, Runner: host.NewRunner(host.Config{MaxTimeout: config.Seconds(c.CommandTimeoutSeconds), MaxOutputBytes: c.MaxOutputBytes, Redact: redact}), Sources: sources, Reporter: sender, Redact: redact, Log: logger, Hostname: hostname}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if command == "once" {
		return app.Once(ctx)
	}
	return app.Run(ctx)
}
func buildPlanner(c config.Config) (engine.Planner, error) {
	if c.LLM.Backend == "command" {
		return planner.NewCommand(planner.CommandConfig{Argv: c.LLM.Command, Dir: c.LLM.Dir, Timeout: config.Seconds(c.LLM.TimeoutSeconds), MaxActions: c.MaxActionsPerRound, MaxResponseBytes: 1 << 20})
	}
	key := os.Getenv(c.LLM.APIKeyEnv)
	if key == "" {
		return nil, fmt.Errorf("LLM credential environment variable %s is not set", c.LLM.APIKeyEnv)
	}
	return planner.NewAPI(planner.APIConfig{BaseURL: c.LLM.BaseURL, Model: c.LLM.Model, APIKey: key, Timeout: config.Seconds(c.LLM.TimeoutSeconds), MaxActions: c.MaxActionsPerRound, MaxResponseBytes: 1 << 20, JSONMode: c.LLM.JSONMode})
}
func buildSources(c config.Config) ([]engine.ScheduledSource, error) {
	var result []engine.ScheduledSource
	for _, s := range c.Sources {
		var source intel.Source
		var err error
		lookback := time.Duration(s.LookbackHours) * time.Hour
		switch s.Type {
		case "kev":
			source, err = intel.NewKEV(intel.KEVConfig{URL: s.URL, Lookback: lookback})
		case "nvd":
			source, err = intel.NewNVD(intel.NVDConfig{URL: s.URL, APIKey: os.Getenv(s.TokenEnv), Lookback: lookback})
		case "x":
			token := os.Getenv(s.TokenEnv)
			validationToken := token
			if validationToken == "" {
				validationToken = "offline-config-check"
			}
			source, err = intel.NewX(intel.XConfig{URL: s.URL, BearerToken: validationToken, Query: s.Query, Lookback: lookback})
			if token == "" {
				source = engine.MissingSource{SourceName: s.Name, Problem: "X monitoring unavailable: set " + s.TokenEnv + " with X API recent-search access"}
			}
		case "rss":
			source, err = intel.NewFeed(intel.FeedConfig{Name: s.Name, URL: s.URL, Trust: s.Trust})
		case "broadcast":
			source, err = intel.NewBroadcast(intel.BroadcastConfig{Name: s.Name, URL: s.URL, PublicKey: s.PublicKey, CAFile: s.CAFile})
		}
		if err != nil {
			return nil, fmt.Errorf("source %s: %w", s.Name, err)
		}
		result = append(result, engine.ScheduledSource{Name: s.Name, Every: config.Seconds(s.IntervalSeconds), Source: source})
	}
	return result, nil
}
func doctor(c config.Config) error {
	failures := 0
	check := func(ok bool, label string) {
		status := "OK"
		if !ok {
			status = "MISSING"
			failures++
		}
		fmt.Printf("%s %s\n", status, label)
	}
	check(runtime.GOOS == "linux", "Linux host (Ubuntu is the primary target)")
	check(c.Observe || !c.RequireRoot || os.Geteuid() == 0, "root execution or observation mode")
	if c.LLM.Backend == "api" {
		check(os.Getenv(c.LLM.APIKeyEnv) != "", "LLM credential: "+c.LLM.APIKeyEnv)
		_, err := planner.NewAPI(planner.APIConfig{BaseURL: c.LLM.BaseURL, Model: c.LLM.Model, APIKey: "offline-config-check", Timeout: config.Seconds(c.LLM.TimeoutSeconds), MaxActions: c.MaxActionsPerRound})
		check(err == nil, "API endpoint and planner configuration")
	} else {
		_, err := buildPlanner(c)
		check(err == nil, "command planner configuration")
	}
	_, sourceErr := buildSources(c)
	check(sourceErr == nil, "intelligence source configuration")
	x, broadcast := false, false
	for _, s := range c.Sources {
		if s.Type == "x" {
			x = true
			check(os.Getenv(s.TokenEnv) != "", "X credential: "+s.TokenEnv)
		}
		if s.Type == "broadcast" {
			broadcast = true
		}
	}
	check(x || broadcast, "X/Twitter source or signed central broadcast configured")
	if c.Report.URL != "" {
		_, err := report.New(c.Report.URL, os.Getenv(c.Report.SecretEnv), os.Getenv(c.Report.BearerTokenEnv))
		check(err == nil, "signed reporting destination")
	} else {
		fmt.Println("INFO external reporting is not configured; local audit and journal only")
	}
	if len(c.RotationHooks) == 0 {
		fmt.Println("INFO no credential rotation hooks configured; model can assess exposure but provider-specific rotation requires local access")
	}
	fmt.Println("No remote API calls or host changes were made. Credential presence does not verify account access.")
	if failures > 0 {
		return fmt.Errorf("%d setup checks require attention", failures)
	}
	return nil
}
func status(c config.Config) error {
	f, err := os.Open(filepath.Join(c.StateDir, "state.json"))
	if err != nil {
		return err
	}
	defer f.Close()
	var state store.State
	if err = json.NewDecoder(f).Decode(&state); err != nil {
		return err
	}
	counts := map[string]int{}
	for _, in := range state.Incidents {
		if in != nil {
			counts[in.Status]++
		}
	}
	sources := map[string]interface{}{}
	for name, s := range state.Sources {
		sources[name] = map[string]interface{}{"last_success": s.LastSuccess, "last_error": s.LastError, "next_poll": s.NextPoll, "failures": s.Failures}
	}
	output := map[string]interface{}{"incidents": counts, "undelivered_reports": len(state.Outbox), "last_host_review": state.LastHostReview, "sources": sources}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(output)
}
func usage() {
	fmt.Print(`firefighter — autonomous Ubuntu incident response

Usage: firefighter <command> [--config /etc/firefighter/config.json] [--observe]

  init     Write a new default configuration; never overwrite an existing file
  doctor   Check local setup without making remote calls or changing the host
  status   Read queue, source health, and undelivered report counts
  run      Continuously ingest, investigate, remediate, and report
  once     Poll once and process a bounded number of incidents
  version  Print build version

Autonomous mode executes model-directed commands without approvals.
Observation mode executes no model-generated commands, including scans.
`)
}
