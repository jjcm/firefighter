// Command firefighter-grokbot runs the configurable Grok Bot reporting plugin.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/jjcm/firefighter/plugins/grokbot"
)

type config struct {
	Listen           string   `json:"listen"`
	SigningSecretEnv string   `json:"signing_secret_env"`
	RoutineURL       string   `json:"routine_url"`
	RoutineURLEnv    string   `json:"routine_url_env"`
	RoutineTokenEnv  string   `json:"routine_token_env"`
	StatePath        string   `json:"state_path"`
	TimeoutSeconds   int      `json:"timeout_seconds"`
	IncludeTypes     []string `json:"include_types"`
}

func main() {
	path := flag.String("config", "/etc/firefighter-grokbot/config.json", "plugin configuration file")
	flag.Parse()
	if err := run(*path); err != nil {
		log.Fatal(err)
	}
}

func run(path string) error {
	cfg := config{Listen: "127.0.0.1:9087", SigningSecretEnv: "FIREFIGHTER_REPORT_SECRET", RoutineURLEnv: "GROKBOT_ROUTINE_URL", RoutineTokenEnv: "GROKBOT_ROUTINE_TOKEN", StatePath: "/var/lib/firefighter-grokbot/delivered.json", TimeoutSeconds: 15, IncludeTypes: []string{"started", "source_error", "source_recovered", "assessment_health_error", "assessment_health_recovered", "assessment_finished"}}
	f, err := os.Open(path)
	if err != nil {
		return errors.New("cannot open plugin config")
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 1<<20))
	d.DisallowUnknownFields()
	if d.Decode(&cfg) != nil || d.Decode(new(any)) != io.EOF {
		return errors.New("invalid plugin JSON config")
	}
	if cfg.RoutineURL != "" && cfg.RoutineURLEnv != "" {
		return errors.New("set routine_url or routine_url_env, not both")
	}
	if cfg.RoutineURLEnv != "" {
		cfg.RoutineURL = os.Getenv(cfg.RoutineURLEnv)
	}
	bridge, err := grokbot.New(grokbot.Config{Secret: os.Getenv(cfg.SigningSecretEnv), WebhookURL: cfg.RoutineURL, Token: os.Getenv(cfg.RoutineTokenEnv), StatePath: cfg.StatePath, Timeout: time.Duration(cfg.TimeoutSeconds) * time.Second, IncludeTypes: cfg.IncludeTypes})
	if err != nil {
		return err
	}
	srv := &http.Server{Addr: cfg.Listen, Handler: bridge, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 30 * time.Second, IdleTimeout: 60 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	errCh := make(chan error, 1)
	go func() { errCh <- srv.ListenAndServe() }()
	log.Printf("Grok Bot reporting plugin listening on %s", cfg.Listen)
	select {
	case err := <-errCh:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return errors.New("plugin HTTP server failed")
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}
