package host

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"testing"
)

func TestParsePackageFixtures(t *testing.T) {
	cases := []struct {
		name, manager, raw string
		truncated          bool
		want               []Package
	}{
		{"ubuntu", "dpkg", "openssl\t3.0.13-0ubuntu3.4\tamd64\tinstalled\nold-package\t1.0\tamd64\tconfig-files\nlibc6:amd64\t2.39-0ubuntu8.4\tamd64\tinstalled\n", false, []Package{{"openssl", "3.0.13-0ubuntu3.4", "amd64", "dpkg"}, {"libc6:amd64", "2.39-0ubuntu8.4", "amd64", "dpkg"}}},
		{"rpm", "rpm", "openssl-libs\t1:3.2.2-6.el9\tx86_64\n", false, []Package{{"openssl-libs", "1:3.2.2-6.el9", "x86_64", "rpm"}}},
		{"alpine", "apk", "apk-tools-2.12.14-r0\nlibc6-compat-1.2.3-r4\n", false, []Package{{"apk-tools", "2.12.14-r0", "", "apk"}, {"libc6-compat", "1.2.3-r4", "", "apk"}}},
		{"truncated", "rpm", "ok\t1\tx86_64\npartial\t2\tx86_64", true, []Package{{"ok", "1", "x86_64", "rpm"}}},
		{"empty truncated", "rpm", "partial\t2\tx86_64", true, []Package{}},
		{"malformed", "rpm", "warning: unavailable\nmissing\t\tx86_64\n", false, []Package{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := parsePackages(tc.manager, tc.raw, tc.truncated); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("got %#v, want %#v", got, tc.want)
			}
		})
	}
}

func TestParseOSReleaseDoesNotEvaluateShell(t *testing.T) {
	got := parseOSRelease("# comment\nNAME=\"Ubuntu\"\nID=ubuntu\nVERSION_ID='24.04'\nVALUE=\"$(touch /never-evaluate-this)\"\ninvalid\n")
	if got["NAME"] != "Ubuntu" || got["ID"] != "ubuntu" || got["VERSION_ID"] != "24.04" || got["VALUE"] != "$(touch /never-evaluate-this)" {
		t.Fatalf("bad os-release parse: %#v", got)
	}
}

func TestReadBoundedFileMakesTruncationExplicit(t *testing.T) {
	path := filepath.Join(t.TempDir(), "fixture")
	if err := os.WriteFile(path, []byte("123456789"), 0600); err != nil {
		t.Fatal(err)
	}
	got, err := readBoundedFile(path, 4)
	if got != "1234" || err == nil {
		t.Fatalf("expected explicit truncation, got %q %v", got, err)
	}
	if _, err := readBoundedFile(path+"-missing", 4); err == nil {
		t.Fatal("missing inventory input was not reported")
	}
}

func TestCollectCanceledDoesNotProbe(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	snapshot, err := Collect(ctx)
	if err != context.Canceled || len(snapshot.Probes) != 0 || snapshot.CollectedAt.IsZero() {
		t.Fatalf("canceled collection ran probes: %+v %v", snapshot, err)
	}
}

func TestCollectUnsupportedPlatformReturnsPartialEvidence(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("do not probe the test host")
	}
	snapshot, err := Collect(context.Background())
	if err != nil || len(snapshot.Probes) != 0 || len(snapshot.Problems) == 0 || snapshot.Problems[len(snapshot.Problems)-1].Kind != "unsupported" {
		t.Fatalf("unsupported platform was not explicit: %+v %v", snapshot, err)
	}
}
