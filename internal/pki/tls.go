package pki

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"

	"google.golang.org/grpc/credentials"
)

// ServerTLSConfig creates a TLS config for the teamserver that requires client
// certificates signed by the given CA (mutual TLS).
func ServerTLSConfig(serverBundle *CertBundle, caCertPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(serverBundle.CertPEM, serverBundle.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading server certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		ClientAuth:   tls.RequireAndVerifyClientCert,
		ClientCAs:    caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ClientTLSConfig creates a TLS config for operators connecting to the teamserver.
// The client presents its certificate and verifies the server against the CA.
func ClientTLSConfig(clientBundle *CertBundle, caCertPEM []byte) (*tls.Config, error) {
	cert, err := tls.X509KeyPair(clientBundle.CertPEM, clientBundle.KeyPEM)
	if err != nil {
		return nil, fmt.Errorf("loading client certificate: %w", err)
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to parse CA certificate")
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
		MinVersion:   tls.VersionTLS13,
	}, nil
}

// ServerTransportCredentials returns gRPC transport credentials for a server with mTLS.
func ServerTransportCredentials(serverBundle *CertBundle, caCertPEM []byte) (credentials.TransportCredentials, error) {
	tlsCfg, err := ServerTLSConfig(serverBundle, caCertPEM)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(tlsCfg), nil
}

// ClientTransportCredentials returns gRPC transport credentials for a client with mTLS.
func ClientTransportCredentials(clientBundle *CertBundle, caCertPEM []byte) (credentials.TransportCredentials, error) {
	tlsCfg, err := ClientTLSConfig(clientBundle, caCertPEM)
	if err != nil {
		return nil, err
	}
	return credentials.NewTLS(tlsCfg), nil
}
