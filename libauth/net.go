package libauth

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// DefaultDNSPort is appended to a DNS server configured without a port.
const DefaultDNSPort = "53"

// DefaultNetworkTimeout bounds a single dial when NetworkOptions.Timeout is 0.
const DefaultNetworkTimeout = 5 * time.Second

// AutomaticInterface is the Interface value that asks for auto detection.
const AutomaticInterface = "auto"

// NetworkOptions selects the interface, source address and DNS server used for
// every socket opened by this package.
//
// A TUN based proxy client terminates TCP in user space: a bare connect() then
// succeeds against the tunnel stack and reports nothing about the upstream
// host. Pinning the socket to the campus adapter (and resolving names through
// a campus DNS server instead of a fake-ip resolver) makes connect() and HTTP
// round trips observe the real link again.
type NetworkOptions struct {
	// Interface is the outbound adapter name, for example "WLAN", "wlan0" or
	// "en0". "auto" selects the interface that owns the default route.
	Interface string
	// SourceIP pins the local source address. It is derived from Interface
	// when left empty.
	SourceIP string
	// DNS lists resolver addresses such as "59.69.128.96" or
	// "59.69.128.96:53". When empty the system resolver is used.
	DNS []string
	// Insecure disables TLS certificate verification. The portal of some
	// deployments answers with a self-signed or mismatched certificate.
	Insecure bool
	// Strict fails instead of degrading when Interface is missing or holds no
	// global IPv4 address. Without it the binding falls back to auto detection
	// and then to system routing, so a daemon survives a disappearing adapter.
	Strict bool
	// Timeout bounds a single dial. Zero selects DefaultNetworkTimeout.
	Timeout time.Duration
}

// tunnelInterfacePrefixes lists adapter names that a proxy client or a
// container bridge installs. They are never a campus adapter, so automatic
// detection skips them.
var tunnelInterfacePrefixes = []string{
	"tun", "tap", "utun", "ppp", "ipsec", "wg", "meta", "clash", "wintun", "sing", "tailscale", "zt",
	// container and virtual bridges
	"docker", "veth", "virbr", "br-", "vmnet", "vboxnet", "cni", "flannel", "lxcbr", "lxdbr", "ds-br", "ds-v",
}

type dialer struct {
	control   func(network, address string, c syscall.RawConn) error
	sourceIP  net.IP
	timeout   time.Duration
	dns       []string
	dnsCursor uint32
}

// Net is a resolved NetworkOptions bundle. It exposes a dialer, an HTTP client
// and a resolver that share the same interface binding.
type Net struct {
	Options     NetworkOptions
	Interface   *net.Interface
	SourceIP    net.IP
	DeviceBound bool
	// Requested is the adapter name the caller asked for, kept even when the
	// binding degraded, so logs and Healthy can report the intent.
	Requested string
	// Missing is non-empty when the requested adapter was unavailable and the
	// binding degraded to another adapter or to system routing.
	Missing string

	dialer    *dialer
	warned    map[string]struct{}
	mu        sync.Mutex
	summary   string
	dnsExcept string
}

// NewNet resolves opts into a Net. A nil opts yields a plain client that
// follows the system routing and resolver configuration.
func NewNet(opts *NetworkOptions) (*Net, error) {
	n := &Net{warned: map[string]struct{}{}, dialer: &dialer{timeout: DefaultNetworkTimeout}}
	if opts == nil {
		n.summary = "system routing"
		return n, nil
	}
	n.Options = *opts
	if n.Options.Timeout <= 0 {
		n.Options.Timeout = DefaultNetworkTimeout
	}

	name := strings.TrimSpace(n.Options.Interface)
	n.Requested = name

	iface, degraded, err := resolveInterface(name, n.Options.Strict)
	if err != nil {
		return nil, err
	}
	n.Missing = degraded
	n.Interface = iface
	if iface != nil {
		n.Options.Interface = iface.Name
		if n.Options.SourceIP == "" {
			ip, ipErr := InterfaceIPv4(iface)
			if ipErr != nil {
				logger.Warningf("Interface %s has no global IPv4 address: %v", iface.Name, ipErr)
			} else {
				n.Options.SourceIP = ip.String()
			}
		}
	} else {
		n.Options.Interface = ""
	}

	if n.Options.SourceIP != "" {
		ip := net.ParseIP(strings.TrimSpace(n.Options.SourceIP))
		if ip == nil {
			return nil, fmt.Errorf("invalid source ip %q", n.Options.SourceIP)
		}
		n.SourceIP = ip
	}

	d := &dialer{
		timeout:  n.Options.Timeout,
		sourceIP: n.SourceIP,
		dns:      normalizeDNSServers(n.Options.DNS),
	}
	if n.Interface != nil && deviceBindNeedsPrivilege() {
		// SO_BINDTODEVICE needs CAP_NET_RAW. Probe it once so a permission
		// failure degrades to source address pinning instead of turning every
		// dial into an error.
		if !deviceBindUsable(n.Interface.Name, n.Interface.Index) {
			logger.Warningf("Cannot bind sockets to %s (needs CAP_NET_RAW); using source address %s only",
				n.Interface.Name, n.SourceIP)
		} else {
			d.control = socketControl(n.Interface.Name, n.Interface.Index)
			n.DeviceBound = true
		}
	} else if n.Interface != nil {
		d.control = socketControl(n.Interface.Name, n.Interface.Index)
		n.DeviceBound = d.control != nil
	}
	n.dialer = d
	n.summary = n.describe()
	return n, nil
}

// resolveInterface turns a requested adapter name into a usable interface.
//
// The three levels are: the requested adapter itself, auto detection (the
// wireless adapter that owns a default route, skipping tunnel and bridge
// devices), and finally no binding at all (system routing). The last level
// keeps a daemon alive when Wi-Fi is gone, which is why the previous failure
// mode — exiting with "find interface" — was wrong for a service.
//
// degraded is non-empty when the request could not be honoured; it names what
// was lost so the caller can log it once.
func resolveInterface(name string, strict bool) (iface *net.Interface, degraded string, err error) {
	auto := strings.EqualFold(name, AutomaticInterface)

	if name != "" && !auto {
		candidate, lookupErr := net.InterfaceByName(name)
		switch {
		case lookupErr == nil && hasGlobalIPv4(candidate):
			return candidate, "", nil
		case lookupErr == nil:
			// The adapter exists but has no address yet (Wi-Fi still
			// associating, DHCP pending). Binding to it would only produce
			// dial failures, so degrade.
			if strict {
				return nil, "", fmt.Errorf("interface %q has no global IPv4 address", name)
			}
			logger.Warningf("Interface %q has no global IPv4 address yet", name)
			degraded = fmt.Sprintf("%s (no IPv4 address)", name)
		default:
			if strict {
				return nil, "", fmt.Errorf("find interface %q: %w", name, lookupErr)
			}
			logger.Warningf("Interface %q unavailable (%v)", name, lookupErr)
			degraded = fmt.Sprintf("%s (not found)", name)
		}
	}

	detected, detectErr := detectCampusInterface()
	if detectErr == nil {
		if detected == name {
			// Detection only confirmed the adapter the caller named.
			return nil, degraded, detectErr
		}
		candidate, lookupErr := net.InterfaceByName(detected)
		if lookupErr == nil && hasGlobalIPv4(candidate) {
			if name != "" {
				logger.Warningf("Falling back to auto-detected interface %q", detected)
			} else {
				logger.Infof("Auto-detected interface %q", detected)
			}
			return candidate, degraded, nil
		}
	}

	if strict {
		if name == "" || auto {
			return nil, degraded, fmt.Errorf("auto-detect interface: %w", detectErr)
		}
		return nil, degraded, fmt.Errorf("interface %q unavailable: %w", name, detectErr)
	}
	if name != "" || auto {
		logger.Warningf("No usable campus interface (%v); falling back to system routing", detectErr)
	}
	if degraded == "" {
		degraded = name
	}
	return nil, degraded, nil
}

// Healthy reports whether the requested adapter is actually in use. It is
// false when the binding degraded, so a daemon can re-resolve the interface
// after Wi-Fi comes back instead of silently probing through the wrong route.
//
// A binding is also unhealthy when the adapter kept its name but changed its
// address: a pinned source address that no longer exists on the adapter makes
// every dial fail, which a long running daemon must recover from.
func (n *Net) Healthy() bool {
	if n == nil {
		return true
	}
	if n.Interface == nil {
		// A binding was requested but could not be applied.
		return n.Requested == ""
	}
	if n.Requested != "" && !strings.EqualFold(n.Interface.Name, n.Requested) {
		return false
	}
	if !hasGlobalIPv4(n.Interface) {
		return false
	}
	if n.SourceIP != nil && !n.interfaceHasIP(n.SourceIP) {
		return false
	}
	return true
}

// interfaceHasIP reports whether iface still holds ip. DHCP renewal changes the
// address under a bound daemon, and a stale pinned source address turns every
// dial into "cannot assign requested address".
func (n *Net) interfaceHasIP(ip net.IP) bool {
	addrs, err := n.Interface.Addrs()
	if err != nil {
		return true // cannot tell; do not force a pointless rebind
	}
	for _, addr := range addrs {
		var candidate net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			candidate = v.IP
		case *net.IPAddr:
			candidate = v.IP
		}
		if candidate != nil && candidate.Equal(ip) {
			return true
		}
	}
	return false
}

// DegradedReason explains why the requested adapter is not in use, or returns
// an empty string when it is.
func (n *Net) DegradedReason() string {
	if n == nil {
		return ""
	}
	return n.Missing
}

func (n *Net) describe() string {
	parts := make([]string, 0, 3)
	if n.Interface != nil {
		parts = append(parts, "interface="+n.Interface.Name)
	}
	if n.SourceIP != nil {
		parts = append(parts, "source="+n.SourceIP.String())
	}
	if len(n.dialer.dns) != 0 {
		parts = append(parts, "dns="+strings.Join(n.dialer.dns, ","))
	}
	if len(parts) == 0 {
		return "system routing"
	}
	desc := strings.Join(parts, " ")
	if n.Missing != "" {
		desc += " (degraded from " + n.Missing + ")"
	}
	return desc
}

// Description returns a short human readable summary of the binding.
func (n *Net) Description() string {
	if n == nil {
		return "system routing"
	}
	return n.summary
}

func (n *Net) warnOnce(format string, err error) {
	if n == nil || err == nil {
		return
	}
	key := err.Error()
	n.mu.Lock()
	defer n.mu.Unlock()
	if _, ok := n.warned[key]; ok {
		return
	}
	n.warned[key] = struct{}{}
	logger.Warningf(format, err)
}

// DialContext dials address through the bound interface.
func (n *Net) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if n == nil || n.dialer == nil {
		var d net.Dialer
		return d.DialContext(ctx, network, address)
	}
	return n.dialer.DialContext(ctx, network, address)
}

// Dial dials address through the bound interface.
func (n *Net) Dial(network, address string) (net.Conn, error) {
	return n.DialContext(context.Background(), network, address)
}

// DialContext opens a socket bound to the configured interface and source
// address.
func (d *dialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	nd := &net.Dialer{Timeout: d.timeout, Control: d.control}
	if d.sourceIP != nil {
		if local := localAddrFor(network, address, d.sourceIP); local != nil {
			nd.LocalAddr = local
		}
	}
	conn, err := nd.DialContext(ctx, network, address)
	if err == nil || d.control == nil || !isPermissionError(err) {
		return conn, err
	}
	// The device option was rejected after all; retry without it so the source
	// address pinning still routes through the adapter.
	nd.Control = nil
	return nd.DialContext(ctx, network, address)
}

// localAddrFor returns a source address only when it matches the target address
// family, so pinning an IPv4 campus address never breaks an IPv6 target.
func localAddrFor(network, address string, src net.IP) net.Addr {
	host, _, err := net.SplitHostPort(address)
	if err != nil {
		host = address
	}
	target := net.ParseIP(strings.Trim(host, "[]"))
	want4 := target == nil || target.To4() != nil
	if strings.HasSuffix(network, "4") {
		want4 = true
	} else if strings.HasSuffix(network, "6") {
		want4 = false
	}
	is4 := src.To4() != nil
	if want4 != is4 {
		return nil
	}
	return &net.TCPAddr{IP: src}
}

func isPermissionError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "operation not permitted") || strings.Contains(msg, "permission denied") ||
		strings.Contains(msg, "access is denied")
}

// Resolver returns a resolver that asks the configured DNS servers through the
// bound interface. It returns nil when no DNS server is configured, meaning the
// system resolver applies.
func (n *Net) Resolver() *net.Resolver {
	if n == nil || n.dialer == nil || len(n.dialer.dns) == 0 {
		return nil
	}
	return &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return n.dialer.dialDNS(ctx, network)
		},
	}
}

func (d *dialer) dialDNS(ctx context.Context, network string) (net.Conn, error) {
	servers := d.dns
	if len(servers) == 0 {
		return nil, errors.New("no DNS server configured")
	}
	start := int(atomic.AddUint32(&d.dnsCursor, 1)-1) % len(servers)
	var lastErr error
	for i := 0; i < len(servers); i++ {
		server := servers[(start+i)%len(servers)]
		conn, err := d.DialContext(ctx, network, server)
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	return nil, fmt.Errorf("query dns %s: %w", strings.Join(servers, ","), lastErr)
}

// Transport builds an HTTP transport whose sockets and DNS lookups follow this
// binding. An environment proxy is never used: the point of the binding is to
// reach the portal directly. A nil Net yields a plain transport that follows
// the system routing.
func (n *Net) Transport(timeout time.Duration) *http.Transport {
	dial := n.DialContext
	if r := n.Resolver(); r != nil {
		full := &resolverDialer{net: n, resolver: r}
		dial = full.DialContext
	}
	insecure := n != nil && n.Options.Insecure
	return &http.Transport{
		Proxy:               nil,
		DialContext:         dial,
		TLSClientConfig:     BuildTLSConfig(insecure),
		MaxIdleConns:        4,
		IdleConnTimeout:     30 * time.Second,
		TLSHandshakeTimeout: timeout,
	}
}

// HTTPClient builds an HTTP client whose sockets, DNS lookups and timeouts all
// follow this binding. Redirects are not followed so callers can inspect the
// portal redirect itself.
func (n *Net) HTTPClient(timeout time.Duration) *http.Client {
	return n.HTTPClientWithRedirect(timeout, func(req *http.Request, via []*http.Request) error {
		return http.ErrUseLastResponse
	})
}

// HTTPClientWithRedirect builds a bound HTTP client with a custom redirect
// policy. A nil check follows the standard policy (up to 10 redirects).
func (n *Net) HTTPClientWithRedirect(timeout time.Duration, check func(req *http.Request, via []*http.Request) error) *http.Client {
	if timeout <= 0 && n != nil {
		timeout = n.Options.Timeout
	}
	if timeout <= 0 {
		timeout = DefaultNetworkTimeout
	}
	return &http.Client{
		Timeout:       timeout,
		Transport:     n.Transport(timeout),
		CheckRedirect: check,
	}
}

// resolverDialer resolves names with the configured DNS servers and then dials
// the resulting addresses through the bound interface.
type resolverDialer struct {
	net      *Net
	resolver *net.Resolver
}

func (r *resolverDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return r.net.DialContext(ctx, network, address)
	}
	if net.ParseIP(host) != nil {
		return r.net.DialContext(ctx, network, address)
	}
	ips, err := r.resolver.LookupIPAddr(ctx, host)
	if err != nil {
		return nil, fmt.Errorf("resolve %s via %s: %w", host, strings.Join(r.net.dialer.dns, ","), err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no address", host)
	}
	want6 := strings.HasSuffix(network, "6")
	want4 := strings.HasSuffix(network, "4")
	var lastErr error
	for _, ipAddr := range ips {
		is4 := ipAddr.IP.To4() != nil
		if (want4 && !is4) || (want6 && is4) {
			continue
		}
		conn, err := r.net.DialContext(ctx, network, net.JoinHostPort(ipAddr.IP.String(), port))
		if err == nil {
			return conn, nil
		}
		lastErr = err
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("resolve %s: no usable address", host)
	}
	return nil, lastErr
}

func normalizeDNSServers(in []string) []string {
	out := make([]string, 0, len(in))
	for _, raw := range in {
		for _, part := range strings.Split(raw, ",") {
			s := strings.TrimSpace(part)
			if s == "" {
				continue
			}
			if _, _, err := net.SplitHostPort(s); err != nil {
				s = net.JoinHostPort(strings.Trim(s, "[]"), DefaultDNSPort)
			}
			out = append(out, s)
		}
	}
	return out
}

// InterfaceIPv4 returns the first global IPv4 address of iface.
func InterfaceIPv4(iface *net.Interface) (net.IP, error) {
	if iface == nil {
		return nil, errors.New("no interface")
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		var ip net.IP
		switch v := addr.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		}
		v4 := ip.To4()
		if v4 == nil || v4.IsLoopback() || v4.IsLinkLocalUnicast() {
			continue
		}
		return v4, nil
	}
	return nil, errors.New("no global IPv4 address")
}

func hasGlobalIPv4(iface *net.Interface) bool {
	_, err := InterfaceIPv4(iface)
	return err == nil
}

// detectCampusInterface picks a plausible physical adapter for
// NetworkOptions.Interface == "auto". Wireless adapters win over wired ones,
// and a candidate that owns a default route wins over one that does not.
func detectCampusInterface() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}
	defaults := defaultRouteInterfaces()
	type candidate struct {
		name     string
		wireless bool
		default4 bool
	}
	var candidates []candidate
	for i := range ifaces {
		iface := &ifaces[i]
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		if isTunnelInterface(iface.Name) || !hasGlobalIPv4(iface) {
			continue
		}
		cand := candidate{name: iface.Name, wireless: isWirelessInterface(iface.Name)}
		for _, name := range defaults {
			if name == iface.Name {
				cand.default4 = true
			}
		}
		candidates = append(candidates, cand)
	}

	best := func(match func(candidate) bool) (string, bool) {
		var found []string
		for _, cand := range candidates {
			if match(cand) {
				found = append(found, cand.name)
			}
		}
		if len(found) == 1 {
			return found[0], true
		}
		return "", false
	}

	if name, ok := best(func(c candidate) bool { return c.wireless && c.default4 }); ok {
		return name, nil
	}
	if name, ok := best(func(c candidate) bool { return c.wireless }); ok {
		return name, nil
	}
	if name, ok := best(func(c candidate) bool { return c.default4 }); ok {
		return name, nil
	}
	switch len(candidates) {
	case 0:
		return "", errors.New("no non-tunnel interface with a global IPv4 address; set the interface explicitly")
	case 1:
		return candidates[0].name, nil
	}
	names := make([]string, 0, len(candidates))
	for _, cand := range candidates {
		names = append(names, cand.name)
	}
	return "", fmt.Errorf("ambiguous adapter, set it explicitly (candidates: %s)", strings.Join(names, ", "))
}

// isWirelessInterface reports whether name looks like a Wi-Fi adapter.
func isWirelessInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range []string{"wlan", "wl", "wifi", "en0", "ath", "ra", "wlp"} {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

func isTunnelInterface(name string) bool {
	lower := strings.ToLower(name)
	for _, prefix := range tunnelInterfacePrefixes {
		if strings.HasPrefix(lower, prefix) {
			return true
		}
	}
	return false
}

// defaultRouteInterfaces lists the interfaces that own a default route, most
// preferred first. Only Linux reads /proc/net/route; elsewhere the candidate
// list decides.
func defaultRouteInterfaces() []string {
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return nil
	}
	defer f.Close()
	buf := make([]byte, 16384)
	n, _ := f.Read(buf)
	lines := strings.Split(string(buf[:n]), "\n")
	var names []string
	for _, line := range lines[1:] {
		fields := strings.Fields(line)
		if len(fields) < 2 || fields[1] != "00000000" {
			continue
		}
		names = append(names, fields[0])
	}
	return names
}

// deviceBindUsable reports whether the device binding can be applied to a
// socket right now.
func deviceBindUsable(ifName string, ifIndex int) bool {
	control := socketControl(ifName, ifIndex)
	if control == nil {
		return false
	}
	lc := net.ListenConfig{Control: control}
	l, err := lc.Listen(context.Background(), "tcp4", "127.0.0.1:0")
	if err != nil {
		logger.Debugf("Device binding unavailable (%v)", err)
		return false
	}
	_ = l.Close()
	return true
}
