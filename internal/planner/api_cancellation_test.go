package planner

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jjcm/firefighter/internal/protocol"
)

type bodyReadTransport func(*http.Request) (*http.Response, error)

func (f bodyReadTransport) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type interruptedResponseBody struct {
	ctx     context.Context
	started chan struct{}
}

func (b *interruptedResponseBody) Read([]byte) (int, error) {
	close(b.started)
	<-b.ctx.Done()
	return 0, b.ctx.Err()
}
func (*interruptedResponseBody) Close() error { return nil }

// Cancellation after response headers were read used to lose its cause and
// appear as an unexplained provider read failure during a controlled shutdown.
func TestAPIResponseReadPreservesCancellation(t *testing.T) {
	for _, backend := range []string{"api", "anthropic"} {
		for _, cause := range []error{context.Canceled, context.DeadlineExceeded} {
			t.Run(backend+"/"+cause.Error(), func(t *testing.T) {
				started := make(chan struct{})
				client := &http.Client{Transport: bodyReadTransport(func(r *http.Request) (*http.Response, error) {
					return &http.Response{StatusCode: http.StatusOK, Body: &interruptedResponseBody{ctx: r.Context(), started: started}, Header: make(http.Header)}, nil
				})}
				cfg := APIConfig{Backend: backend, BaseURL: "https://provider.invalid/v1", Model: "fixture", Client: client, Timeout: time.Second}
				if cause == context.DeadlineExceeded {
					cfg.Timeout = 50 * time.Millisecond
				}
				p, err := NewAPI(cfg)
				if err != nil {
					t.Fatal(err)
				}
				ctx, cancel := context.WithCancel(context.Background())
				defer cancel()
				finished := make(chan error, 1)
				go func() {
					_, err := p.Decide(ctx, protocol.Request{})
					finished <- err
				}()
				select {
				case <-started:
				case <-time.After(time.Second):
					t.Fatal("response body was not read")
				}
				if cause == context.Canceled {
					cancel()
				}
				select {
				case err := <-finished:
					if !errors.Is(err, cause) || !strings.HasPrefix(err.Error(), "planner response interrupted:") {
						t.Fatalf("response read lost interruption cause: %v", err)
					}
				case <-time.After(time.Second):
					t.Fatal("response read did not unblock")
				}
			})
		}
	}
}

type failedResponseBody struct{}

func (failedResponseBody) Read([]byte) (int, error) { return 0, errors.New("fixture-provider-secret") }
func (failedResponseBody) Close() error             { return nil }

func TestAPIResponseReadFailureStaysOpaque(t *testing.T) {
	client := &http.Client{Transport: bodyReadTransport(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.ReadCloser(failedResponseBody{}), Header: make(http.Header)}, nil
	})}
	p, err := NewAPI(APIConfig{BaseURL: "https://provider.invalid/v1", Model: "fixture", Client: client})
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.Decide(context.Background(), protocol.Request{})
	if err == nil || err.Error() != "cannot read planner response" {
		t.Fatalf("unexpected or unredacted body error: %v", err)
	}
}
