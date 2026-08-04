// Package tlsutil provides shared TLS helpers for all DBFW proxy modes.
package tlsutil

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"
	"net"
	"time"
)

// GenerateSelfSignedCert creates an RSA-2048 self-signed certificate valid for
// 10 years. The proxy presents this to clients during TLS termination.
// Clients should skip certificate verification (ssl-mode=REQUIRED, sslmode=require, etc.).
func GenerateSelfSignedCert() (tls.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("generate serial: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "DBFW Proxy"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(10 * 365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		IPAddresses:  []net.IP{net.IPv4(127, 0, 0, 1)},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("create certificate: %w", err)
	}

	return tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}, nil
}

// PrefixedConn wraps a net.Conn and replays prefix bytes before delegating
// reads to the underlying connection. Used to "put back" bytes that were
// consumed for protocol detection.
type PrefixedConn struct {
	net.Conn
	Prefix []byte
	offset int
}

func (p *PrefixedConn) Read(b []byte) (int, error) {
	if p.offset < len(p.Prefix) {
		n := copy(b, p.Prefix[p.offset:])
		p.offset += n
		return n, nil
	}
	return p.Conn.Read(b)
}
