package libauth

import (
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestNormalizeDNSServers(t *testing.T) {
	got := normalizeDNSServers([]string{"59.69.128.96", " 8.8.8.8:5353 ", "", "2001:da8:5018:5018::5"})
	want := []string{"59.69.128.96:53", "8.8.8.8:5353", "[2001:da8:5018:5018::5]:53"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestNormalizeDNSServersSplitsCommas(t *testing.T) {
	got := normalizeDNSServers([]string{"59.69.128.96,223.5.5.5"})
	if len(got) != 2 || got[0] != "59.69.128.96:53" || got[1] != "223.5.5.5:53" {
		t.Fatalf("unexpected result: %v", got)
	}
}

func TestLocalAddrFor(t *testing.T) {
	v4 := net.ParseIP("10.2.241.14")
	v6 := net.ParseIP("2001:da8::1")
	cases := []struct {
		network string
		address string
		src     net.IP
		want    bool
	}{
		{"tcp4", "122.207.209.6:8080", v4, true},
		{"tcp", "122.207.209.6:8080", v4, true},
		{"tcp", "[2001:da8::5]:443", v4, false},
		{"tcp", "[2001:da8::5]:443", v6, true},
		{"tcp4", "[2001:da8::5]:443", v6, false},
		{"tcp6", "122.207.209.6:80", v4, false},
		// DNS goes over UDP; net.Dialer rejects a TCP local address there.
		{"udp4", "59.69.128.96:53", v4, true},
		{"udp", "59.69.128.96:53", v4, true},
		{"udp", "[2001:da8::5]:53", v4, false},
	}
	for _, c := range cases {
		got := localAddrFor(c.network, c.address, c.src)
		if (got != nil) != c.want {
			t.Errorf("localAddrFor(%q, %q, %s) = %v, want non-nil=%v", c.network, c.address, c.src, got, c.want)
			continue
		}
		if got == nil {
			continue
		}
		// The concrete type has to match the network family, otherwise the dial
		// fails with "mismatched local address type".
		if strings.HasPrefix(c.network, "udp") {
			if _, ok := got.(*net.UDPAddr); !ok {
				t.Errorf("localAddrFor(%q, ...) returned %T, want *net.UDPAddr", c.network, got)
			}
		} else {
			if _, ok := got.(*net.TCPAddr); !ok {
				t.Errorf("localAddrFor(%q, ...) returned %T, want *net.TCPAddr", c.network, got)
			}
		}
	}
}

func TestIsTunnelInterface(t *testing.T) {
	tunnels := []string{"tun0", "Meta", "utun3", "wg0", "ds-br0", "docker0", "veth1a2b", "ds-v15150"}
	for _, name := range tunnels {
		if !isTunnelInterface(name) {
			t.Errorf("%q should be treated as a virtual adapter", name)
		}
	}
	for _, name := range []string{"wlan0", "eth0", "en0", "WLAN", "wlp3s0"} {
		if isTunnelInterface(name) {
			t.Errorf("%q should not be treated as a virtual adapter", name)
		}
	}
}

func TestStatusAccepted(t *testing.T) {
	if !statusAccepted(302, nil) {
		t.Fatal("302 should be accepted by default")
	}
	if !statusAccepted(200, nil) {
		t.Fatal("200 should be accepted by default")
	}
	if statusAccepted(404, nil) {
		t.Fatal("404 should be rejected by default")
	}
	if !statusAccepted(302, []int{200, 302}) {
		t.Fatal("explicit expectation should accept 302")
	}
	if statusAccepted(200, []int{302}) {
		t.Fatal("explicit expectation should reject 200")
	}
}

func TestParseStatusList(t *testing.T) {
	codes, err := ParseStatusList("200,204 302")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(codes) != 3 || codes[0] != 200 || codes[1] != 204 || codes[2] != 302 {
		t.Fatalf("unexpected codes: %v", codes)
	}
	if _, err := ParseStatusList("abc"); err == nil {
		t.Fatal("expected an error for a non-numeric code")
	}
	if _, err := ParseStatusList("999"); err == nil {
		t.Fatal("expected an error for an out-of-range code")
	}
}

// TestProbeHTTPDetectsClosedPort is the regression test for issue #4. An open
// port answers the probe, a closed port must not.
func TestHtonl(t *testing.T) {
	cases := map[uint32]uint32{
		0x0000000a: 0x0a000000, // interface index 10 -> 0A 00 00 00
		0x00000001: 0x01000000,
		0x01020304: 0x04030201,
		0x00000000: 0x00000000,
	}
	for in, want := range cases {
		if got := htonl(in); got != want {
			t.Errorf("htonl(0x%08x) = 0x%08x, want 0x%08x", in, got, want)
		}
	}
	if htonl(htonl(0x12345678)) != 0x12345678 {
		t.Error("htonl must be its own inverse")
	}
}

func TestNilNetFollowsSystemRouting(t *testing.T) {
	var n *Net
	if got := n.Description(); got != "system routing" {
		t.Fatalf("nil Net description = %q", got)
	}
	if r := n.Resolver(); r != nil {
		t.Fatal("nil Net must use the system resolver")
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	res := Probe(n, ProbeOptions{URL: srv.URL, Timeout: 3 * time.Second})
	if !res.OK {
		t.Fatalf("nil Net should still probe, got %s", res.String())
	}
}

func TestProbeHTTPDetectsClosedPort(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/opac/search/simsearch")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	n, err := NewNet(nil)
	if err != nil {
		t.Fatalf("NewNet: %v", err)
	}

	res := Probe(n, ProbeOptions{URL: srv.URL, Timeout: 3 * time.Second})
	if !res.OK {
		t.Fatalf("open port should probe as online, got %s", res.String())
	}
	if res.Status != http.StatusFound || res.Location != "/opac/search/simsearch" {
		t.Fatalf("unexpected response: %+v", res)
	}

	// Now point the probe at a port that refuses connections.
	_, port, err := net.SplitHostPort(strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	closed := "http://127.0.0.1:" + port
	srv.Close()
	res = Probe(n, ProbeOptions{URL: closed, Timeout: 2 * time.Second})
	if res.OK {
		t.Fatalf("closed port must probe as offline, got %s", res.String())
	}
}

func TestProbeExpectLocation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", "/opac/search/simsearch")
		w.WriteHeader(http.StatusFound)
	}))
	defer srv.Close()

	n, _ := NewNet(nil)
	res := Probe(n, ProbeOptions{
		URL:            srv.URL,
		ExpectStatus:   []int{302},
		ExpectLocation: "/opac/search/simsearch",
		Timeout:        3 * time.Second,
	})
	if !res.OK {
		t.Fatalf("expected a match, got %s", res.String())
	}
	res = Probe(n, ProbeOptions{
		URL:            srv.URL,
		ExpectLocation: "/nope",
		Timeout:        3 * time.Second,
	})
	if res.OK {
		t.Fatalf("expected a location mismatch, got %s", res.String())
	}
}

func TestProbeTCP(t *testing.T) {
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	defer ln.Close()

	n, _ := NewNet(nil)
	res := Probe(n, ProbeOptions{URL: addr, Kind: ProbeTCP, Timeout: 2 * time.Second})
	if !res.OK {
		t.Fatalf("listening socket should probe as online, got %s", res.String())
	}
}

// TestNewNetDegradesOnUnknownInterface covers the daemon case: a missing
// adapter must not abort the process, it degrades to another adapter or to
// system routing and reports why.
func TestNewNetDegradesOnUnknownInterface(t *testing.T) {
	n, err := NewNet(&NetworkOptions{Interface: "definitely-not-an-interface-0"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n.DegradedReason() == "" {
		t.Fatal("expected the binding to report a degraded reason")
	}
	if n.Requested != "definitely-not-an-interface-0" {
		t.Fatalf("Requested = %q", n.Requested)
	}
	desc := n.Description()
	if !strings.Contains(desc, "degraded from") {
		t.Fatalf("description should mention the degradation, got %q", desc)
	}
}

// TestNewNetStrictRejectsUnknownInterface is the opposite contract: with Strict
// the caller wants a hard failure instead of a silent fallback.
func TestNewNetStrictRejectsUnknownInterface(t *testing.T) {
	_, err := NewNet(&NetworkOptions{Interface: "definitely-not-an-interface-0", Strict: true})
	if err == nil {
		t.Fatal("expected an error for an unknown interface in strict mode")
	}
}

func TestNewNetStrictRejectsNetworkLessInterface(t *testing.T) {
	// The loopback adapter never carries a global IPv4 address.
	_, err := NewNet(&NetworkOptions{Interface: "lo", Strict: true})
	if err == nil {
		t.Fatal("expected an error for an interface without a global IPv4 address")
	}
}

// TestNetHealthyAfterLocalInterface checks the happy path with a real local
// adapter, so a degraded result cannot be mistaken for success.
func TestNetHealthyAfterLocalInterface(t *testing.T) {
	ifaces, err := net.Interfaces()
	if err != nil {
		t.Fatalf("interfaces: %v", err)
	}
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagLoopback != 0 || !hasGlobalIPv4(iface) || isTunnelInterface(iface.Name) {
			continue
		}
		n, err := NewNet(&NetworkOptions{Interface: iface.Name, Strict: true})
		if err != nil {
			t.Fatalf("binding %q: %v", iface.Name, err)
		}
		if !n.Healthy() {
			t.Fatalf("%q should report a healthy binding, got %q", iface.Name, n.DegradedReason())
		}
		return
	}
	t.Skip("no non-tunnel adapter with a global IPv4 address")
}

func TestNewNetRejectsBadSourceIP(t *testing.T) {
	_, err := NewNet(&NetworkOptions{SourceIP: "not-an-ip"})
	if err == nil {
		t.Fatal("expected an error for an invalid source ip")
	}
}
