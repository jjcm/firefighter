package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jjcm/firefighter/internal/broadcast"
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "firefighter-hub:", err)
		os.Exit(1)
	}
}
func run(args []string) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" {
		fmt.Print(`firefighter-hub — signed public advisory distribution, no remote commands

Usage: firefighter-hub <command> --config /etc/firefighter-hub/config.json

  init-key    Create a new private signing key; never replace an existing key
  public-key  Print only the base64 Ed25519 public key for client pinning
  check       Validate configuration and key without calling upstream APIs
  run         Poll upstream sources once globally and serve signed notices
  example     Print a default configuration with environment-variable names only

HTTP binds loopback only; publish through an HTTPS reverse proxy.
`)
		return nil
	}
	if args[0] == "example" {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(broadcast.DefaultConfig())
	}
	command := args[0]
	if command != "init-key" && command != "public-key" && command != "check" && command != "run" {
		return errors.New("unknown command")
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	path := flags.String("config", "/etc/firefighter-hub/config.json", "hub configuration file")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	cfg, err := broadcast.LoadConfig(*path)
	if err != nil {
		return err
	}
	if command == "init-key" {
		public, err := broadcast.InitKey(cfg.StateDir)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(public))
		return nil
	}
	if command == "public-key" {
		public, err := broadcast.PublicKey(cfg.StateDir)
		if err != nil {
			return err
		}
		fmt.Println(base64.StdEncoding.EncodeToString(public))
		return nil
	}
	sources, err := broadcast.BuildSources(cfg)
	if err != nil {
		return err
	}
	hub, err := broadcast.Open(cfg)
	if err != nil {
		return err
	}
	defer hub.Close()
	if command == "check" {
		fmt.Println("Hub configuration and signing key are valid. No upstream APIs were called.")
		for _, s := range cfg.Sources {
			if s.Type == "x" && os.Getenv(s.TokenEnv) == "" {
				fmt.Println("X intake degraded: configured credential environment variable is not set.")
			}
		}
		return nil
	}
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	server := &http.Server{Addr: cfg.Listen, Handler: hub.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	errs := make(chan error, 2)
	go func() { errs <- hub.Run(ctx, sources) }()
	go func() { errs <- server.ListenAndServe() }()
	fmt.Fprintln(os.Stderr, "Signed advisory hub listening on", cfg.Listen)
	received := 0
	select {
	case err = <-errs:
		received = 1
	case <-ctx.Done():
		err = nil
	}
	cancel()
	shutdown, done := context.WithTimeout(context.Background(), 10*time.Second)
	defer done()
	_ = server.Shutdown(shutdown)
	// Join the remaining worker before releasing the single-ingester state lock.
	for received < 2 {
		select {
		case next := <-errs:
			received++
			if err == nil && !errors.Is(next, http.ErrServerClosed) {
				err = next
			}
		case <-shutdown.Done():
			if err == nil {
				err = shutdown.Err()
			}
			received = 2
		}
	}
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
