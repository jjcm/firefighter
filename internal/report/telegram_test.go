package report

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"
)

const testPairingCode = "FF-0123456789abcdef01234567"

func pairingMessage(chat, from int64, kind, text string) map[string]any {
	return map[string]any{"update_id": 1, "message": map[string]any{"text": text, "chat": map[string]any{"id": chat, "type": kind}, "from": map[string]any{"id": from, "is_bot": false}}}
}

func pairingResponse(messages ...map[string]any) string {
	b, _ := json.Marshal(map[string]any{"ok": true, "result": messages})
	return string(b)
}

func TestTelegramPairingOnlySelectsNonceBoundPrivateChat(t *testing.T) {
	for _, command := range []string{testPairingCode, "/start " + testPairingCode} {
		client := directClient()
		calls := 0
		client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) {
			calls++
			if r.Method != "POST" || r.URL.Host != "api.telegram.org" || r.URL.Scheme != "https" || r.URL.Path != "/bot"+telegramFixture+"/getUpdates" || r.URL.RawQuery != "" {
				t.Fatal("pairing used an unexpected endpoint or token-bearing query")
			}
			var body map[string]any
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body) != 2 || body["limit"] != float64(100) || body["timeout"] != float64(0) || body["offset"] != nil || body["allowed_updates"] != nil {
				t.Fatalf("pairing request changes polling state: %+v", body)
			}
			return response(200, pairingResponse(
				pairingMessage(111, 111, "private", "unrelated old message"),
				pairingMessage(-100123, 222, "group", testPairingCode),
				pairingMessage(333, 444, "private", testPairingCode),
				pairingMessage(9876543210, 9876543210, "private", command),
			)), nil
		})
		id, err := discoverTelegramChat(context.Background(), telegramFixture, testPairingCode, client)
		if err != nil || id != "9876543210" || calls != 1 {
			t.Fatalf("private pairing failed: chat=%q calls=%d err=%v", id, calls, err)
		}
	}
}

func TestTelegramPairingRejectsUnrelatedAndAmbiguousMessages(t *testing.T) {
	bot := pairingMessage(111, 111, "private", testPairingCode)
	bot["message"].(map[string]any)["from"].(map[string]any)["is_bot"] = true
	for _, tc := range []struct{ name, body string }{
		{"group", pairingResponse(pairingMessage(-100123, 222, "supergroup", testPairingCode))},
		{"channel", pairingResponse(pairingMessage(-100123, 222, "channel", testPairingCode))},
		{"wrong nonce", pairingResponse(pairingMessage(111, 111, "private", "FF-aaaaaaaaaaaaaaaaaaaaaaaa"))},
		{"prefix", pairingResponse(pairingMessage(111, 111, "private", "hello "+testPairingCode))},
		{"suffix", pairingResponse(pairingMessage(111, 111, "private", testPairingCode+" "))},
		{"from mismatch", pairingResponse(pairingMessage(111, 222, "private", testPairingCode))},
		{"bot", pairingResponse(bot)},
		{"empty", `{"ok":true,"result":[]}`},
		{"ambiguous", pairingResponse(pairingMessage(111, 111, "private", testPairingCode), pairingMessage(222, 222, "private", testPairingCode))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			client := directClient()
			client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(200, tc.body), nil })
			id, err := discoverTelegramChat(context.Background(), telegramFixture, testPairingCode, client)
			if err == nil || id != "" || strings.Contains(err.Error(), telegramFixture) || strings.Contains(err.Error(), "111") {
				t.Fatalf("unsafe pairing accepted or leaked messages: id=%q err=%v", id, err)
			}
		})
	}
}

func TestTelegramPairingValidatesBeforeNetwork(t *testing.T) {
	client := directClient()
	client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("invalid token/nonce reached network")
		return nil, nil
	})
	for _, tc := range []struct{ token, code string }{
		{telegramFixture, ""}, {telegramFixture, "FF-short"}, {telegramFixture, "FF-0123456789ABCDEF01234567"}, {telegramFixture, "FF-0123456789abcdef012345678"}, {telegramFixture, "FF-0123456789abcdef01234567\n"}, {"123:token/../getUpdates", testPairingCode},
	} {
		if _, err := discoverTelegramChat(context.Background(), tc.token, tc.code, client); err == nil || strings.Contains(err.Error(), tc.token) {
			t.Fatalf("invalid pairing input accepted or echoed: %v", err)
		}
	}
}

func TestTelegramPairingFailuresNeverExposeTokenOrBody(t *testing.T) {
	for _, tc := range []struct {
		status int
		body   string
		want   string
	}{
		{409, "private-remote-secret", "another poller"}, {401, "private-remote-secret", "check the bot token"}, {500, "private-remote-secret", "did not accept"}, {200, `{"ok":false,"description":"private-remote-secret"}`, "did not accept"}, {200, "private-remote-secret", "invalid pairing"}, {200, strings.Repeat("x", (1<<20)+1), "bounded"},
	} {
		t.Run(fmt.Sprintf("%d-%d", tc.status, len(tc.body)), func(t *testing.T) {
			client := directClient()
			client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) { return response(tc.status, tc.body), nil })
			_, err := discoverTelegramChat(context.Background(), telegramFixture, testPairingCode, client)
			if err == nil || !strings.Contains(err.Error(), tc.want) || strings.Contains(err.Error(), telegramFixture) || strings.Contains(err.Error(), "private-remote-secret") {
				t.Fatalf("unexpected or secret-bearing error: %v", err)
			}
		})
	}
	client := directClient()
	client.Transport = roundTripFunc(func(r *http.Request) (*http.Response, error) { return nil, errors.New("failed URL " + r.URL.String()) })
	if _, err := discoverTelegramChat(context.Background(), telegramFixture, testPairingCode, client); err == nil || strings.Contains(err.Error(), telegramFixture) || strings.Contains(err.Error(), "https:") {
		t.Fatalf("network error exposed token: %v", err)
	}
}

func TestTelegramPairingRateLimitAndRedirect(t *testing.T) {
	for _, status := range []int{429, 200} {
		client := directClient()
		client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
			return response(status, `{"ok":false,"error_code":429,"parameters":{"retry_after":37},"description":"private-remote-secret"}`), nil
		})
		_, err := discoverTelegramChat(context.Background(), telegramFixture, testPairingCode, client)
		var retry *RetryAfterError
		if !errors.As(err, &retry) || retry.RetryAfter() != 37*time.Second {
			t.Fatalf("pairing ignored rate limit: %v", err)
		}
	}
	client := directClient()
	calls := 0
	client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		calls++
		resp := response(307, "")
		resp.Header.Set("Location", "https://attacker.invalid/collect")
		return resp, nil
	})
	if _, err := discoverTelegramChat(context.Background(), telegramFixture, testPairingCode, client); err == nil || calls != 1 {
		t.Fatalf("pairing followed redirect: %d %v", calls, err)
	}
}
