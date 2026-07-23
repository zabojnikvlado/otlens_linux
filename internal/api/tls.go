package api

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"time"

	"github.com/zabojnikvlado/otlens_linux/internal/logger"
	"go.uber.org/zap"
)

// ensureSelfSignedCert makes sure a TLS certificate/key pair exists
// at certFile/keyFile, generating a self-signed one if either is
// missing. If you already have a real certificate (e.g. from an
// internal CA), just point api.tls.certfile/keyfile at those files —
// this function only generates when both are absent, so a valid
// existing pair is always left alone.
//
// A self-signed certificate is the practical default for OTLens:
// it typically runs on an internal OT network with no public CA
// available, the same tradeoff appliances like Nozomi Guardian make
// out of the box. The browser will show a one-time "not trusted"
// warning to click past (or you can import the generated
// otlens.crt into your OS/browser trust store to suppress it).
func ensureSelfSignedCert(certFile, keyFile string) error {

	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)

	if certErr == nil && keyErr == nil {
		// Both already exist — use them as-is, whether that's a
		// previously generated pair or a real CA-issued one.
		return nil
	}

	logger.Log.Info(
		"Generating self-signed TLS certificate",
		zap.String("cert_file", certFile),
		zap.String("key_file", keyFile),
	)

	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	if err != nil {
		return fmt.Errorf("generating key failed: %w", err)
	}

	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)

	serial, err := rand.Int(rand.Reader, serialLimit)

	if err != nil {
		return fmt.Errorf("generating serial number failed: %w", err)
	}

	template := x509.Certificate{
		SerialNumber: serial,

		Subject: pkix.Name{
			CommonName:   "otlens",
			Organization: []string{"OTLens"},
		},

		NotBefore: time.Now(),
		// Long-lived on purpose: this is a self-signed local/OT
		// appliance cert, not something rotated through a CA — a
		// short expiry would just mean it silently breaks in a year
		// with no one around to renew it.
		NotAfter: time.Now().AddDate(10, 0, 0),

		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},

		BasicConstraintsValid: true,
		IsCA:                  true, // self-signed leaf acting as its own root

		DNSNames:    []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)

	if err != nil {
		return fmt.Errorf("creating certificate failed: %w", err)
	}

	certOut, err := os.Create(certFile)

	if err != nil {
		return fmt.Errorf("writing cert file failed: %w", err)
	}

	defer certOut.Close()

	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		return fmt.Errorf("encoding cert failed: %w", err)
	}

	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)

	if err != nil {
		return fmt.Errorf("writing key file failed: %w", err)
	}

	defer keyOut.Close()

	keyBytes, err := x509.MarshalECPrivateKey(priv)

	if err != nil {
		return fmt.Errorf("marshaling key failed: %w", err)
	}

	if err := pem.Encode(keyOut, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyBytes}); err != nil {
		return fmt.Errorf("encoding key failed: %w", err)
	}

	return nil
}

// resolveTLSMinVersion maps a config string ("1.0"/"1.1"/"1.2"/"1.3")
// to the corresponding crypto/tls constant. Empty or unrecognized
// falls back to TLS 1.2 — modern enough to be safe, but still
// compatible with older tooling that might poll this API (e.g.
// older HMI/SCADA client libraries), unlike requiring 1.3 outright.
func resolveTLSMinVersion(version string) uint16 {

	switch version {

	case "1.0":
		return tls.VersionTLS10

	case "1.1":
		return tls.VersionTLS11

	case "1.2", "":
		return tls.VersionTLS12

	case "1.3":
		return tls.VersionTLS13

	default:

		logger.Log.Warn(
			"Unknown api.tls.minversion, falling back to TLS 1.2",
			zap.String("version", version),
		)

		return tls.VersionTLS12
	}
}

// resolveCipherSuites converts a list of cipher suite names (the
// standard Go/IANA names, e.g. "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256"
// — see `go doc crypto/tls.CipherSuites` for the full list) into the
// numeric IDs crypto/tls.Config.CipherSuites expects. Unknown names
// are logged and skipped rather than failing startup over a config
// typo. An empty result means "let Go pick its own secure defaults",
// which is also what an empty/omitted config list does.
//
// Note: this only has any effect when the negotiated connection uses
// TLS 1.2 or below — TLS 1.3's cipher suite selection is fixed by
// the protocol and Go's stdlib, and CipherSuites is ignored for 1.3
// connections. If api.tls.minversion is "1.3", cipher suite
// configuration is a no-op; that's expected, not a bug.
func resolveCipherSuites(names []string) []uint16 {

	var ids []uint16

	for _, name := range names {

		id, ok := cipherSuiteByName(name)

		if !ok {

			logger.Log.Warn(
				"Unknown TLS cipher suite name, ignoring",
				zap.String("name", name),
			)

			continue
		}

		ids = append(ids, id)
	}

	return ids
}

func cipherSuiteByName(name string) (uint16, bool) {

	for _, suite := range tls.CipherSuites() {

		if suite.Name == name {
			return suite.ID, true
		}
	}

	// InsecureCipherSuites includes suites Go considers weak (e.g.
	// RC4, 3DES) — still resolved by name rather than silently
	// rejected, so an operator who deliberately needs one for
	// legacy-client compatibility can configure it; it's on them to
	// have made that call deliberately.
	for _, suite := range tls.InsecureCipherSuites() {

		if suite.Name == name {
			return suite.ID, true
		}
	}

	return 0, false
}
