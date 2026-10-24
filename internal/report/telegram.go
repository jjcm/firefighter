package report

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"regexp"
	"strconv"
	"time"
)

var pairingCode = regexp.MustCompile(`^FF-[a-f0-9]{24}$`)

// DiscoverTelegramChat reads pending messages without acknowledging, deleting,
// or changing webhook/polling settings. Only a private conversation containing
// the installer's unpredictable one-use code can become the destination.
func DiscoverTelegramChat(ctx context.Context, token, code string) (string, error) {
	return discoverTelegramChat(ctx, token, code, directClient())
}

func discoverTelegramChat(ctx context.Context, token, code string, client *http.Client) (string, error) {
	if !botToken.MatchString(token) || !pairingCode.MatchString(code) {
		return "", errors.New("Telegram pairing requires a valid bot token and generated pairing code")
	}
	data, _ := json.Marshal(map[string]any{"limit": 100, "timeout": 0})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://api.telegram.org/bot"+token+"/getUpdates", bytes.NewReader(data))
	if err != nil {
		return "", errors.New("cannot construct Telegram pairing request")
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return "", errors.New("Telegram pairing failed (network, timeout, or TLS error)")
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, (1<<20)+1))
	if resp.StatusCode == http.StatusTooManyRequests {
		return "", retryError(resp.Header, body, time.Now())
	}
	if resp.StatusCode == http.StatusConflict {
		return "", errors.New("Telegram pairing is unavailable while this bot has a webhook or another poller; use a dedicated bot or enter the chat ID manually")
	}
	if resp.StatusCode != http.StatusOK {
		return "", errors.New("Telegram did not accept the pairing request; check the bot token")
	}
	if err != nil || len(body) > 1<<20 {
		return "", errors.New("cannot read bounded Telegram pairing response")
	}
	var response struct {
		OK        bool `json:"ok"`
		ErrorCode int  `json:"error_code"`
		Result    []struct {
			Message struct {
				Text string `json:"text"`
				From struct {
					ID    int64 `json:"id"`
					IsBot bool  `json:"is_bot"`
				} `json:"from"`
				Chat struct {
					ID   int64  `json:"id"`
					Type string `json:"type"`
				} `json:"chat"`
			} `json:"message"`
		} `json:"result"`
	}
	if json.Unmarshal(body, &response) != nil {
		return "", errors.New("Telegram returned an invalid pairing response")
	}
	if response.ErrorCode == http.StatusTooManyRequests {
		return "", retryError(resp.Header, body, time.Now())
	}
	if !response.OK {
		return "", errors.New("Telegram did not accept the pairing request; check the bot token")
	}
	var matched int64
	for _, update := range response.Result {
		message := update.Message
		if message.Chat.Type != "private" || message.Chat.ID <= 0 || message.From.ID != message.Chat.ID || message.From.IsBot {
			continue
		}
		if message.Text != code && message.Text != "/start "+code {
			continue
		}
		if matched != 0 && matched != message.Chat.ID {
			return "", errors.New("Telegram pairing code matched more than one private chat; generate a new code")
		}
		matched = message.Chat.ID
	}
	if matched == 0 {
		return "", errors.New("Telegram pairing message not found; press Start in your bot's private chat, send the exact pairing code, and try again")
	}
	return strconv.FormatInt(matched, 10), nil
}
