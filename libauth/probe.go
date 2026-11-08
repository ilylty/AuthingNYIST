package libauth

import (
	"context"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ProbeKind selects how a probe decides whether the campus link works.
type ProbeKind string

const (
	// ProbeHTTP sends a request and requires a real HTTP response. This is the
	// default because a TUN client answers a bare TCP handshake locally.
	ProbeHTTP ProbeKind = "http"
	// ProbeTCP only checks that a TCP handshake completes. Cheap, but a TUN
	// client can answer the SYN itself, so it proves little.
	ProbeTCP ProbeKind = "tcp"
)

// DefaultProbeURL is the NYIST library root. It answers 302 to
// /opac/search/simsearch while a campus session is active, so any complete HTTP
// response means the campus link carries traffic.
const DefaultProbeURL = "http://122.207.209.6:8080/"

// ProbeResult describes one connectivity probe.
type ProbeResult struct {
	Target   string
	Kind     ProbeKind
	OK       bool
	Status   int
	Location string
	Elapsed  time.Duration
	Err      error
}

// String renders the probe outcome for logs.
func (r ProbeResult) String() string {
	elapsed := formatElapsed(r.Elapsed)
	if r.OK {
		if r.Kind == ProbeHTTP && r.Status != 0 {
			return fmt.Sprintf("%s %d in %s", r.Target, r.Status, elapsed)
		}
		return fmt.Sprintf("%s ok in %s", r.Target, elapsed)
	}
	return fmt.Sprintf("%s failed after %s: %v", r.Target, elapsed, r.Err)
}

// formatElapsed keeps sub-millisecond probes readable instead of collapsing
// them into "0s".
func formatElapsed(d time.Duration) string {
	if d < time.Millisecond {
		return d.Round(time.Microsecond).String()
	}
	return d.Round(time.Millisecond).String()
}

// ProbeOptions configures a single probe.
type ProbeOptions struct {
	// URL is an absolute http(s) URL for ProbeHTTP, or "host:port" for ProbeTCP.
	URL string
	// Kind selects HTTP or TCP.
	Kind ProbeKind
	// ExpectStatus lists acceptable HTTP status codes. Empty accepts any code
	// in [200,400) plus 3xx redirects, which is what a reachable portal replies.
	ExpectStatus []int
	// ExpectLocation, when set, must be a substring of the Location header.
	ExpectLocation string
	// Timeout bounds the whole probe.
	Timeout time.Duration
}

// Probe checks connectivity through net.
func Probe(n *Net, opts ProbeOptions) (res ProbeResult) {
	kind := opts.Kind
	if kind == "" {
		kind = ProbeHTTP
	}
	target := strings.TrimSpace(opts.URL)
	if target == "" {
		target = DefaultProbeURL
	}
	timeout := opts.Timeout
	if timeout <= 0 {
		timeout = DefaultNetworkTimeout
	}
	res = ProbeResult{Target: target, Kind: kind}
	start := time.Now()
	defer func() { res.Elapsed = time.Since(start) }()

	switch kind {
	case ProbeTCP:
		address := target
		if strings.Contains(target, "://") {
			u, err := url.Parse(target)
			if err != nil {
				res.Err = err
				return res
			}
			address = u.Host
			if u.Port() == "" {
				if u.Scheme == "https" {
					address = net.JoinHostPort(u.Hostname(), "443")
				} else {
					address = net.JoinHostPort(u.Hostname(), "80")
				}
			}
		}
		res.Target = address
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()
		conn, err := n.DialContext(ctx, "tcp", address)
		if err != nil {
			res.Err = dialError(address, err)
			return res
		}
		_ = conn.Close()
		res.OK = true
		return res
	default:
		return probeHTTP(n, target, opts, timeout, res)
	}
}

func probeHTTP(n *Net, target string, opts ProbeOptions, timeout time.Duration, res ProbeResult) ProbeResult {
	if !strings.Contains(target, "://") {
		target = "http://" + target
	}
	u, err := url.Parse(target)
	if err != nil {
		res.Err = fmt.Errorf("invalid probe url %q: %w", target, err)
		return res
	}
	if u.Host == "" {
		res.Err = fmt.Errorf("invalid probe url %q: no host", target)
		return res
	}
	res.Target = target
	client := n.HTTPClient(timeout)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		res.Err = err
		return res
	}
	req.Header.Set("User-Agent", "auth-nyist-cli")
	req.Header.Set("Connection", "close")

	resp, err := client.Do(req)
	if err != nil {
		res.Err = httpError(u.Host, err)
		return res
	}
	defer resp.Body.Close()
	// Drain a bounded amount so the round trip completes and the connection can
	// be reused or closed cleanly.
	_, _ = io.Copy(ioutil.Discard, io.LimitReader(resp.Body, 4096))

	res.Status = resp.StatusCode
	res.Location = resp.Header.Get("Location")
	if !statusAccepted(resp.StatusCode, opts.ExpectStatus) {
		res.Err = fmt.Errorf("unexpected status %d", resp.StatusCode)
		return res
	}
	if opts.ExpectLocation != "" && !strings.Contains(res.Location, opts.ExpectLocation) {
		res.Err = fmt.Errorf("unexpected location %q (want substring %q)", res.Location, opts.ExpectLocation)
		return res
	}
	res.OK = true
	return res
}

func statusAccepted(status int, expect []int) bool {
	if len(expect) != 0 {
		for _, want := range expect {
			if status == want {
				return true
			}
		}
		return false
	}
	return status >= 200 && status < 400
}

// dialError converts a dial failure into a message that names the real cause.
func dialError(address string, err error) error {
	var nErr net.Error
	if errors.As(err, &nErr) && nErr.Timeout() {
		return fmt.Errorf("%s timeout", address)
	}
	return fmt.Errorf("connect %s error: %v", address, err)
}

func httpError(host string, err error) error {
	var nErr net.Error
	if errors.As(err, &nErr) && nErr.Timeout() {
		return fmt.Errorf("%s timeout", host)
	}
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return fmt.Errorf("resolve %s error: %v", host, err)
	}
	msg := err.Error()
	if strings.Contains(msg, "connection reset") || strings.Contains(msg, "EOF") {
		return fmt.Errorf("%s closed the connection: %v", host, err)
	}
	return fmt.Errorf("request %s error: %v", host, err)
}

// ParseStatusList parses "200,204" or "200 204" into status codes.
func ParseStatusList(in string) ([]int, error) {
	fields := strings.FieldsFunc(in, func(r rune) bool {
		return r == ',' || r == ' ' || r == ';'
	})
	codes := make([]int, 0, len(fields))
	for _, field := range fields {
		code, err := strconv.Atoi(field)
		if err != nil {
			return nil, fmt.Errorf("invalid status code %q", field)
		}
		if code < 100 || code > 599 {
			return nil, fmt.Errorf("status code %d out of range", code)
		}
		codes = append(codes, code)
	}
	return codes, nil
}
