package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"regexp"
	"time"

	"github.com/jjcm/firefighter/internal/config"
	"github.com/jjcm/firefighter/internal/protocol"
	"github.com/jjcm/firefighter/internal/report"
)

func reportOptions(c config.Config) report.Options {
	endpoint := c.Report.URL
	if c.Report.URLEnv != "" {
		endpoint = os.Getenv(c.Report.URLEnv)
	}
	return report.Options{
		Type: c.Report.Type, URL: endpoint, Secret: os.Getenv(c.Report.SecretEnv),
		BearerToken: os.Getenv(c.Report.BearerTokenEnv), Token: os.Getenv(c.Report.TokenEnv), ChatID: c.Report.ChatID,
	}
}

func reportProvider(c config.Report) string {
	if c.Type == "" {
		return "webhook"
	}
	return c.Type
}

// Resolve only the explicitly selected destination's credentials. Validation
// ensures a token intended for one adapter cannot be silently sent to another.
func buildReporter(c config.Config) (report.Sender, error) {
	if err := c.Report.Validate(); err != nil {
		return nil, err
	}
	if !c.Report.Enabled() {
		return nil, nil
	}
	for _, name := range []string{c.Report.URLEnv, c.Report.SecretEnv, c.Report.BearerTokenEnv, c.Report.TokenEnv} {
		if name != "" && os.Getenv(name) == "" {
			return nil, fmt.Errorf("%s reporting requires its configured environment variables to be set", reportProvider(c.Report))
		}
	}
	sender, err := report.NewSender(reportOptions(c))
	if err != nil {
		return nil, fmt.Errorf("%s reporting configuration: %s", reportProvider(c.Report), buildRedactor(c)(err.Error()))
	}
	return sender, nil
}

func buildRedactor(c config.Config) func(string) string {
	secrets := append([]string{os.Getenv(c.LLM.APIKeyEnv)}, report.SecretValues(reportOptions(c))...)
	for _, source := range c.Sources {
		secrets = append(secrets, os.Getenv(source.TokenEnv))
	}
	return report.Redactor(secrets...)
}

func notifyTest(c config.Config) error {
	sender, err := buildReporter(c)
	if err != nil {
		return err
	}
	if sender == nil {
		return errors.New("external reporting is not configured")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return errors.New("could not create notification test identifier")
	}
	hostname, err := os.Hostname()
	if err != nil {
		return errors.New("could not read hostname for notification test")
	}
	provider := reportProvider(c.Report)
	event := protocol.Event{
		ID: "test-" + hex.EncodeToString(nonce[:]), Time: time.Now().UTC(), Host: hostname,
		Type: "report_test", Summary: "Firefighter connection test. This test does not start the agent or change the server.",
		Details: map[string]interface{}{"provider": provider},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := sender.Send(ctx, event); err != nil {
		return fmt.Errorf("%s notification test failed: %s", provider, buildRedactor(c)(err.Error()))
	}
	fmt.Printf("%s accepted the test notification; check your destination. Provider acceptance does not confirm a person received it.\n", provider)
	return nil
}

func telegramPair(args []string) error {
	flags := flag.NewFlagSet("telegram-pair", flag.ContinueOnError)
	tokenEnv := flags.String("token-env", "FIREFIGHTER_NOTIFY_TOKEN", "environment variable containing the Telegram bot token")
	code := flags.String("code", "", "one-time FF- code to match in a private bot chat")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected positional arguments")
	}
	if !config.ValidEnvName(*tokenEnv) {
		return errors.New("telegram-pair requires a valid token environment variable name")
	}
	if !regexp.MustCompile(`^FF-[a-f0-9]{24}$`).MatchString(*code) {
		return errors.New("telegram-pair requires an FF- code followed by 24 lowercase hexadecimal characters")
	}
	token := os.Getenv(*tokenEnv)
	if token == "" {
		return errors.New("Telegram bot token environment variable is not set")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	chatID, err := report.DiscoverTelegramChat(ctx, token, *code)
	if err != nil {
		return fmt.Errorf("Telegram pairing failed: %s", report.Redactor(token)(err.Error()))
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]string{"chat_id": chatID})
}
