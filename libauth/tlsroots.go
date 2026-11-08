package libauth

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// extraCertDirs lists trust stores that Go's crypto/x509 does not read by
// itself. A binary running on Android (or in a container with a minimal rootfs)
// finds no roots at all otherwise, so every HTTPS request fails with
// "certificate signed by unknown authority".
var extraCertDirs = []string{
	"/system/etc/security/cacerts",
	"/apex/com.android.conscrypt/cacerts",
	"/data/misc/keychain/cacerts-added",
	"/etc/ssl/certs",
	"/usr/local/share/ca-certificates",
}

// extraCertFiles lists single-file PEM bundles some images ship.
var extraCertFiles = []string{
	"/system/etc/security/cacerts.pem",
	"/etc/security/cacerts.pem",
	"/etc/ssl/cert.pem",
	"/etc/ssl/certs/ca-certificates.crt",
	"/etc/pki/tls/certs/ca-bundle.crt",
}

var (
	certPoolOnce sync.Once
	certPool     *x509.CertPool
)

// DefaultRootCAs returns the system certificate pool, extended from the
// well-known bundle paths when the system pool is empty. The result is cached.
func DefaultRootCAs() *x509.CertPool {
	certPoolOnce.Do(func() {
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			if err != nil {
				logger.Debugf("System certificate pool unavailable: %v", err)
			}
			pool = x509.NewCertPool()
		}
		if len(pool.Subjects()) > 0 {
			certPool = pool
			return
		}
		if added := appendCertBundles(pool); added > 0 {
			logger.Debugf("Loaded %d CA files into the root certificate pool", added)
		} else {
			logger.Debugf("No CA bundle found; HTTPS verification may fail")
		}
		certPool = pool
	})
	return certPool
}

// appendCertBundles loads PEM bundles from the extra locations and returns how
// many files contributed at least one certificate.
func appendCertBundles(pool *x509.CertPool) int {
	added := 0
	seen := map[string]bool{}
	load := func(path string) {
		if seen[path] {
			return
		}
		seen[path] = true
		pem, err := os.ReadFile(path)
		if err != nil || len(pem) == 0 {
			return
		}
		if pool.AppendCertsFromPEM(pem) {
			added++
		}
	}
	for _, file := range extraCertFiles {
		load(file)
	}
	for _, dir := range extraCertDirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
				continue
			}
			load(filepath.Join(dir, entry.Name()))
		}
	}
	return added
}

// BuildTLSConfig returns a TLS configuration using the pool from
// DefaultRootCAs, or nil when insecure is set.
//
// A nil config means "use the Go defaults", which is the common case. When
// InsecureSkipVerify is explicitly selected, the returned config also turns off
// the server name check so a portal that answers with a mismatched certificate
// stays reachable.
func BuildTLSConfig(insecure bool) *tls.Config {
	if insecure {
		return &tls.Config{InsecureSkipVerify: true}
	}
	pool := DefaultRootCAs()
	if pool == nil || len(pool.Subjects()) == 0 {
		return nil
	}
	return &tls.Config{RootCAs: pool}
}
