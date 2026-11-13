package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/docopt/docopt-go"
)

// This PR changed two things in main.go:
//   - the socks5 dev server's default listen address, from the wildcard
//     ":9999" to the loopback "127.0.0.1:9999" (both in the --help doc text
//     and in the literal default passed to pick());
//   - removed the dev tool's own "any credentials accepted" ValidUser
//     override, relying instead on the proxy library's documented
//     nil-ValidUser no-auth default.
//
// Neither cfg nor pick() nor the usage string are exported (they are locals
// inside func main), so these tests read this package's own main.go source to
// exercise the real, current text/literals rather than a copy that could
// drift from it.

// usageFromSource extracts the literal `usage := \`...\“ doc string from
// main.go.
func usageFromSource(t *testing.T) string {
	t.Helper()

	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	m := regexp.MustCompile("(?s)usage := `(.*?)`").FindStringSubmatch(string(data))
	if m == nil {
		t.Fatal("could not find the usage doc string in main.go")
	}
	return m[1]
}

// TestUsageDocumentsLoopbackAddrDefault pins the --help text change: the
// --addr line must document the new loopback default, not the old wildcard
// one.
func TestUsageDocumentsLoopbackAddrDefault(t *testing.T) {
	usage := usageFromSource(t)

	var addrLine string
	for _, line := range strings.Split(usage, "\n") {
		if strings.Contains(line, "--addr=<addr>") {
			addrLine = line
			break
		}
	}
	if addrLine == "" {
		t.Fatal("usage doc has no --addr=<addr> line")
	}
	if !strings.Contains(addrLine, "default 127.0.0.1:9999") {
		t.Fatalf("--addr doc = %q, want it to document default 127.0.0.1:9999", addrLine)
	}
	if strings.Contains(addrLine, "default :9999") {
		t.Fatalf("--addr doc = %q, still documents the old wildcard default", addrLine)
	}
}

// TestUsageStillParsesWithDocopt is a sanity check that the doc string edited
// by this PR is still valid docopt syntax and --addr is still parsed as an
// ordinary flag. The "(env ADDR, default ...)" text is documentation only --
// docopt does not apply it -- so the actual default is checked separately by
// TestAddrDefaultLiteralIsLoopback below.
func TestUsageStillParsesWithDocopt(t *testing.T) {
	usage := usageFromSource(t)

	opts, err := docopt.ParseArgs(usage, []string{
		"--addr", "10.0.0.1:1234",
		"--user-auth", "u",
		"--password", "p",
	}, "test")
	if err != nil {
		t.Fatalf("ParseArgs: %v", err)
	}
	got, ok := opts["--addr"].(string)
	if !ok || got != "10.0.0.1:1234" {
		t.Fatalf("--addr = %v (ok=%v), want 10.0.0.1:1234", opts["--addr"], ok)
	}
}

// TestAddrDefaultLiteralIsLoopback pins the functional half of the change:
// the literal default passed to pick() for --addr/ADDR, which is what
// actually determines the listen address when neither the flag nor the env
// var is set.
func TestAddrDefaultLiteralIsLoopback(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}

	m := regexp.MustCompile(`cfg\.addr = pick\("--addr", "ADDR", "([^"]*)"\)`).FindStringSubmatch(string(data))
	if m == nil {
		t.Fatal("could not find the cfg.addr default assignment in main.go")
	}
	if got := m[1]; got != "127.0.0.1:9999" {
		t.Fatalf("addr default literal = %q, want 127.0.0.1:9999", got)
	}
}

// TestDevSocksProxyHasNoValidUserOverride pins the removal of the
// unconditional "any credentials accepted" ValidUser override that used to
// follow NewSocksProxyWithDefaults(). With it gone, SocksProxy.ValidUser stays
// nil, which proxy.SocksProxy now documents (and socks_test.go's
// TestSocksProxyNilValidUserAllowsNoAuthEndToEnd verifies) as "allow no-auth"
// -- the same effective behavior, expressed via the library default instead
// of a copy of it living in this dev tool.
func TestDevSocksProxyHasNoValidUserOverride(t *testing.T) {
	data, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatalf("read main.go: %v", err)
	}
	src := string(data)

	start := strings.Index(src, "NewSocksProxyWithDefaults()")
	if start == -1 {
		t.Fatal("could not find NewSocksProxyWithDefaults() call in main.go")
	}
	rest := src[start:]
	end := strings.Index(rest, "ConnectDialWithRequest")
	if end == -1 {
		t.Fatal("could not find ConnectDialWithRequest assignment after NewSocksProxyWithDefaults()")
	}
	between := rest[:end]

	if strings.Contains(between, "ValidUser") {
		t.Fatalf("found a ValidUser assignment between NewSocksProxyWithDefaults() and "+
			"ConnectDialWithRequest; the dev \"any credentials accepted\" override should "+
			"have been removed in favor of the library's nil-ValidUser no-auth default:\n%s", between)
	}
}

// TestCheckListenAuth pins that the dev proxy never exposes an
// unauthenticated socks5 port beyond loopback: a network-reachable --addr
// (for example so a tun2proxy container can reach it) requires credentials.
func TestCheckListenAuth(t *testing.T) {
	cases := []struct {
		addr    string
		user    string
		pass    string
		wantErr bool
	}{
		{"127.0.0.1:9999", "", "", false},
		{"[::1]:9999", "", "", false},
		{"localhost:9999", "", "", false},
		{"0.0.0.0:9999", "", "", true},
		{":9999", "", "", true},
		{"[::]:9999", "", "", true},
		{"172.17.0.1:9999", "", "", true},
		{"proxy.example:9999", "", "", true},
		{"not-an-addr", "", "", true},
		{"0.0.0.0:9999", "u", "p", false},
		{"172.17.0.1:9999", "u", "p", false},
		{"127.0.0.1:9999", "u", "p", false},
		{"0.0.0.0:9999", "u", "", true},
		{"127.0.0.1:9999", "", "p", true},
	}
	for _, c := range cases {
		err := checkListenAuth(c.addr, c.user, c.pass)
		if (err != nil) != c.wantErr {
			t.Errorf("checkListenAuth(%q, %q, %q) = %v, wantErr %v", c.addr, c.user, c.pass, err, c.wantErr)
		}
	}
}

func TestSocksCredentialValidator(t *testing.T) {
	valid := socksCredentialValidator("alice", "s3cret")
	if !valid("alice", "s3cret", "10.0.0.2:1234") {
		t.Fatal("configured credentials rejected")
	}
	for _, c := range [][2]string{{"alice", "wrong"}, {"bob", "s3cret"}, {"", ""}, {"alice", ""}, {"alice", "s3cret "}} {
		if valid(c[0], c[1], "10.0.0.2:1234") {
			t.Fatalf("credentials %q/%q accepted", c[0], c[1])
		}
	}
}

// TestReadmeDocumentsAddrDefault keeps socks/README.md in sync with the
// actual --addr default. The README used to document the old wildcard
// ":9999", which led users to point container clients at 127.0.0.1.
func TestReadmeDocumentsAddrDefault(t *testing.T) {
	data, err := os.ReadFile("README.md")
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	var addrLine string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "- `--addr`") {
			addrLine = line
			break
		}
	}
	if addrLine == "" {
		t.Fatal("README.md has no --addr option line")
	}
	if !strings.Contains(addrLine, "`127.0.0.1:9999`") {
		t.Fatalf("README --addr line = %q, want it to document default 127.0.0.1:9999", addrLine)
	}
	if strings.Contains(addrLine, "`:9999`") {
		t.Fatalf("README --addr line = %q, still documents the old wildcard default", addrLine)
	}
}
