package pki

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"testing"
	"time"
)

func TestGenerateCA(t *testing.T) {
	ca, err := GenerateCA("TestOrg", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	cert, err := ParseCertificate(ca.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if !cert.IsCA {
		t.Error("expected CA certificate")
	}
	if cert.Subject.CommonName != "STRATUS CA" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}
	if cert.Subject.Organization[0] != "TestOrg" {
		t.Errorf("unexpected org: %s", cert.Subject.Organization[0])
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("expected CertSign key usage")
	}

	// Verify key is valid
	block, _ := pem.Decode(ca.KeyPEM)
	if block == nil {
		t.Fatal("no key PEM data")
	}
	if block.Type != "EC PRIVATE KEY" {
		t.Errorf("unexpected key type: %s", block.Type)
	}
}

func TestGenerateServerCert(t *testing.T) {
	ca, err := GenerateCA("TestOrg", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	hosts := []string{"server.example.com", "10.0.0.1"}
	serverBundle, err := GenerateServerCert(ca, hosts, 90*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateServerCert: %v", err)
	}

	cert, err := ParseCertificate(serverBundle.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if cert.IsCA {
		t.Error("server cert should not be CA")
	}
	if cert.Subject.CommonName != "STRATUS Teamserver" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}

	// Check SANs
	foundDNS := false
	for _, dns := range cert.DNSNames {
		if dns == "server.example.com" {
			foundDNS = true
		}
	}
	if !foundDNS {
		t.Errorf("expected server.example.com in DNS SANs, got: %v", cert.DNSNames)
	}

	// Check localhost is always included
	foundLocalhost := false
	for _, dns := range cert.DNSNames {
		if dns == "localhost" {
			foundLocalhost = true
		}
	}
	if !foundLocalhost {
		t.Error("expected localhost in DNS SANs")
	}

	// Check IP SANs
	foundIP := false
	for _, ip := range cert.IPAddresses {
		if ip.Equal(net.ParseIP("10.0.0.1")) {
			foundIP = true
		}
	}
	if !foundIP {
		t.Errorf("expected 10.0.0.1 in IP SANs, got: %v", cert.IPAddresses)
	}

	// Check EKU
	hasServerAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageServerAuth {
			hasServerAuth = true
		}
	}
	if !hasServerAuth {
		t.Error("expected ServerAuth EKU")
	}

	// Verify against CA
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	})
	if err != nil {
		t.Errorf("server cert failed CA verification: %v", err)
	}
}

func TestGenerateClientCert(t *testing.T) {
	ca, err := GenerateCA("TestOrg", 365*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateCA: %v", err)
	}

	clientBundle, err := GenerateClientCert(ca, "operator-alice", 30*24*time.Hour)
	if err != nil {
		t.Fatalf("GenerateClientCert: %v", err)
	}

	cert, err := ParseCertificate(clientBundle.CertPEM)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	if cert.IsCA {
		t.Error("client cert should not be CA")
	}
	if cert.Subject.CommonName != "operator-alice" {
		t.Errorf("unexpected CN: %s", cert.Subject.CommonName)
	}
	if cert.Subject.Organization[0] != "STRATUS Operators" {
		t.Errorf("unexpected org: %s", cert.Subject.Organization[0])
	}

	hasClientAuth := false
	for _, eku := range cert.ExtKeyUsage {
		if eku == x509.ExtKeyUsageClientAuth {
			hasClientAuth = true
		}
	}
	if !hasClientAuth {
		t.Error("expected ClientAuth EKU")
	}

	// Verify against CA
	caPool := x509.NewCertPool()
	caPool.AppendCertsFromPEM(ca.CertPEM)
	_, err = cert.Verify(x509.VerifyOptions{
		Roots:     caPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err != nil {
		t.Errorf("client cert failed CA verification: %v", err)
	}
}

func TestCrossSignedCertsRejected(t *testing.T) {
	// Generate two independent CAs
	ca1, _ := GenerateCA("CA1", 365*24*time.Hour)
	ca2, _ := GenerateCA("CA2", 365*24*time.Hour)

	// Generate client cert with CA1
	clientBundle, _ := GenerateClientCert(ca1, "rogue", 30*24*time.Hour)
	clientCert, _ := ParseCertificate(clientBundle.CertPEM)

	// Try to verify against CA2 — should fail
	ca2Pool := x509.NewCertPool()
	ca2Pool.AppendCertsFromPEM(ca2.CertPEM)
	_, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     ca2Pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	})
	if err == nil {
		t.Error("expected verification to fail with wrong CA")
	}
}

func TestServerTLSConfig(t *testing.T) {
	ca, _ := GenerateCA("TestOrg", 365*24*time.Hour)
	server, _ := GenerateServerCert(ca, []string{"localhost"}, 90*24*time.Hour)

	cfg, err := ServerTLSConfig(server, ca.CertPEM)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	if cfg.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Error("expected RequireAndVerifyClientCert")
	}
	if cfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3 minimum")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
}

func TestClientTLSConfig(t *testing.T) {
	ca, _ := GenerateCA("TestOrg", 365*24*time.Hour)
	client, _ := GenerateClientCert(ca, "test-op", 30*24*time.Hour)

	cfg, err := ClientTLSConfig(client, ca.CertPEM)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	if cfg.MinVersion != tls.VersionTLS13 {
		t.Error("expected TLS 1.3 minimum")
	}
	if len(cfg.Certificates) != 1 {
		t.Errorf("expected 1 certificate, got %d", len(cfg.Certificates))
	}
	if cfg.RootCAs == nil {
		t.Error("expected RootCAs to be set")
	}
}

func TestMTLSHandshake(t *testing.T) {
	ca, _ := GenerateCA("TestOrg", 365*24*time.Hour)
	serverBundle, _ := GenerateServerCert(ca, []string{"127.0.0.1"}, 90*24*time.Hour)
	clientBundle, _ := GenerateClientCert(ca, "test-operator", 30*24*time.Hour)

	serverTLS, err := ServerTLSConfig(serverBundle, ca.CertPEM)
	if err != nil {
		t.Fatalf("ServerTLSConfig: %v", err)
	}

	clientTLS, err := ClientTLSConfig(clientBundle, ca.CertPEM)
	if err != nil {
		t.Fatalf("ClientTLSConfig: %v", err)
	}

	// Start TLS listener
	lis, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer lis.Close()

	// Server goroutine
	done := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()

		// Force handshake
		tlsConn := conn.(*tls.Conn)
		if err := tlsConn.Handshake(); err != nil {
			done <- err
			return
		}

		// Verify client identity
		state := tlsConn.ConnectionState()
		if len(state.PeerCertificates) == 0 {
			done <- fmt.Errorf("no client certificate presented")
			return
		}
		cn := state.PeerCertificates[0].Subject.CommonName
		if cn != "test-operator" {
			done <- fmt.Errorf("unexpected client CN: %s", cn)
			return
		}

		conn.Write([]byte("OK"))
		done <- nil
	}()

	// Client connection
	clientTLS.ServerName = "127.0.0.1"
	conn, err := tls.Dial("tcp", lis.Addr().String(), clientTLS)
	if err != nil {
		t.Fatalf("tls.Dial: %v", err)
	}
	defer conn.Close()

	buf := make([]byte, 2)
	conn.Read(buf)
	if string(buf) != "OK" {
		t.Errorf("unexpected response: %s", buf)
	}

	if err := <-done; err != nil {
		t.Errorf("server error: %v", err)
	}
}

func TestMTLSRejectsUntrustedClient(t *testing.T) {
	ca1, _ := GenerateCA("Legit CA", 365*24*time.Hour)
	ca2, _ := GenerateCA("Rogue CA", 365*24*time.Hour)

	serverBundle, _ := GenerateServerCert(ca1, []string{"127.0.0.1"}, 90*24*time.Hour)
	rogueClient, _ := GenerateClientCert(ca2, "rogue-operator", 30*24*time.Hour)

	serverTLS, _ := ServerTLSConfig(serverBundle, ca1.CertPEM)

	lis, err := tls.Listen("tcp", "127.0.0.1:0", serverTLS)
	if err != nil {
		t.Fatalf("tls.Listen: %v", err)
	}
	defer lis.Close()

	serverErr := make(chan error, 1)
	go func() {
		conn, err := lis.Accept()
		if err != nil {
			serverErr <- err
			return
		}
		defer conn.Close()
		// Server handshake will fail verifying the rogue client cert
		err = conn.(*tls.Conn).Handshake()
		serverErr <- err
	}()

	// Client with cert signed by wrong CA
	clientTLS, _ := ClientTLSConfig(rogueClient, ca1.CertPEM)
	clientTLS.ServerName = "127.0.0.1"

	conn, dialErr := tls.Dial("tcp", lis.Addr().String(), clientTLS)
	if dialErr == nil {
		// With TLS 1.3, dial may succeed — try to read to surface the server-side rejection
		buf := make([]byte, 1)
		_, readErr := conn.Read(buf)
		conn.Close()
		// The read should fail because the server rejected the handshake
		if readErr == nil {
			t.Error("expected read to fail after server rejected untrusted client cert")
		}
	}

	// Verify server-side got a handshake error
	sErr := <-serverErr
	if sErr == nil {
		t.Error("expected server to reject untrusted client certificate")
	}
}
