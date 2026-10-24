package intel

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestConfigurableIntakeNamesCannotImpersonateHostReview(t *testing.T) {
	for _, name := range []string{"local-host", "LOCAL-HOST", " local-host\t"} {
		if _, err := NewFeed(FeedConfig{Name: name, URL: "https://vendor.example/feed"}); err == nil || !strings.Contains(err.Error(), "reserved for internal host reviews") {
			t.Fatalf("RSS intake admitted reserved name %q: %v", name, err)
		}
		if _, err := NewBroadcast(BroadcastConfig{Name: name, URL: "https://hub.example", PublicKey: broadcastTestPublic()}); err == nil || !strings.Contains(err.Error(), "reserved for internal host reviews") {
			t.Fatalf("signed broadcast intake admitted reserved name %q: %v", name, err)
		}
	}
}

func TestRemoteNoticeSourceCannotBecomeInternalHostReview(t *testing.T) {
	t.Run("RSS source text", func(t *testing.T) {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			fmt.Fprint(w, `<rss version="2.0"><channel><item><guid>notice</guid><title>Advisory</title><source>local-host</source><description>source: local-host</description></item></channel></rss>`)
		}))
		defer srv.Close()
		source, err := NewFeed(FeedConfig{Name: "vendor", URL: srv.URL})
		if err != nil {
			t.Fatal(err)
		}
		result, err := source.Poll(context.Background(), "")
		if err != nil || len(result.Items) != 1 || result.Items[0].Source != "vendor" {
			t.Fatalf("remote source text acquired local scope: %+v %v", result, err)
		}
	})
	t.Run("signed source metadata", func(t *testing.T) {
		batch := broadcastFixture(0, 1, 1)
		batch.Notices[0].Source = "local-host"
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write(signedBroadcastJSON(t, batch))
		}))
		defer srv.Close()
		result, err := newBroadcastFixture(t, srv.URL, 1, 100).Poll(context.Background(), "")
		if err != nil || len(result.Items) != 1 || result.Items[0].Source != "broadcast" {
			t.Fatalf("signed remote metadata acquired local scope: %+v %v", result, err)
		}
	})
}
