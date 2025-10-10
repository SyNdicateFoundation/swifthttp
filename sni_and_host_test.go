package swifthttp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/SyNdicateFoundation/legitagent"
)

type httpbinResponse struct {
	Headers map[string]string `json:"headers"`
}

func TestSNIAndHostHeaders(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping test in short mode.")
	}

	generator := legitagent.NewGenerator(
		legitagent.WithBrowsers(legitagent.BrowserChrome),
		legitagent.WithOS(legitagent.OSWindows),
	)
	t.Run("HTTP1.1_Remote_Connection", func(t *testing.T) {
		targetURL, _ := url.Parse("https://httpbin.org/")
		client := NewHttpClient(
			WithAgentGenerator(generator),
			WithVersion(HttpVersion1_1),
		)
		session, err := client.CreateSession(context.Background(), targetURL)
		if err != nil {
			t.Fatalf("Failed to create H1 session: %v", err)
		}
		defer session.Close()
		resp, err := session.Request(context.Background(), NewRequest())
		if err != nil {
			t.Fatalf("H1 request failed: %v", err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK for H1, but got %d", resp.StatusCode)
		}
	})

	t.Run("HTTP2_Remote_Connection", func(t *testing.T) {
		targetURL, _ := url.Parse("https://httpbin.org/")
		client := NewHttpClient(
			WithAgentGenerator(generator),
			WithVersion(HttpVersion2_0),
		)
		session, err := client.CreateSession(context.Background(), targetURL)
		if err != nil {
			t.Fatalf("Failed to create H2 session: %v", err)
		}
		defer session.Close()
		resp, err := session.Request(context.Background(), NewRequest())
		if err != nil {
			t.Fatalf("H2 request failed: %v", err)
		}
		defer resp.Body.Close()
		io.Copy(io.Discard, resp.Body)
		if resp.StatusCode != http.StatusOK {
			t.Errorf("Expected status OK for H2, but got %d", resp.StatusCode)
		}
	})
	t.Run("HTTP1.1_Remote_HostHeader", func(t *testing.T) {
		targetURL, _ := url.Parse("https://httpbin.org/get")
		client := NewHttpClient(
			WithAgentGenerator(generator),
			WithVersion(HttpVersion1_1),
		)
		session, err := client.CreateSession(context.Background(), targetURL)
		if err != nil {
			t.Fatalf("Failed to create H1 session: %v", err)
		}
		defer session.Close()
		resp, err := session.Request(context.Background(), NewRequest(WithPath("/get")))
		if err != nil {
			t.Fatalf("H1 request failed: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read H1 response body: %v", err)
		}
		var respData httpbinResponse
		if err := json.Unmarshal(body, &respData); err != nil {
			t.Fatalf("Failed to unmarshal JSON response: %v", err)
		}
		receivedHost := respData.Headers["Host"]
		t.Logf("HTTP/1.1 test: httpbin.org received Host header: '%s'", receivedHost)
		if receivedHost != targetURL.Hostname() {
			t.Errorf("Incorrect Host header for HTTP/1.1. Expected '%s', got '%s'", targetURL.Hostname(), receivedHost)
		}
	})

	t.Run("HTTP2_Remote_AuthorityHeader", func(t *testing.T) {
		targetURL, _ := url.Parse("https://httpbin.org/get")
		client := NewHttpClient(
			WithAgentGenerator(generator),
			WithVersion(HttpVersion2_0),
		)
		session, err := client.CreateSession(context.Background(), targetURL)
		if err != nil {
			t.Fatalf("Failed to create H2 session: %v", err)
		}
		defer session.Close()
		resp, err := session.Request(context.Background(), NewRequest(WithPath("/get")))
		if err != nil {
			t.Fatalf("H2 request failed: %v", err)
		}
		defer resp.Body.Close()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("Failed to read H2 response body: %v", err)
		}
		var respData httpbinResponse
		if err := json.Unmarshal(body, &respData); err != nil {
			t.Fatalf("Failed to unmarshal JSON response: %v. Body: %s", err, string(body))
		}
		receivedAuthority := respData.Headers["Host"]
		t.Logf("HTTP/2.0 test: httpbin.org received :authority as Host: '%s'", receivedAuthority)
		if receivedAuthority != targetURL.Hostname() {
			t.Errorf("Incorrect :authority header for HTTP/2.0. Expected '%s', got '%s'", targetURL.Hostname(), receivedAuthority)
		}
	})

	t.Run("LocalTLS_SNI_Verification", func(t *testing.T) {
		serverURL, sniChan, hostChan, cleanup := setupLocalTLSServer(t)
		defer cleanup()
		client := NewHttpClient(
			WithAgentGenerator(generator),
			WithVersion(HttpVersion2_0),
		)
		session, err := client.CreateSession(context.Background(), serverURL)
		if err != nil {
			t.Fatalf("Failed to create session to local server: %v", err)
		}
		defer session.Close()
		resp, err := session.Request(context.Background(), NewRequest(WithPath("/get")))
		if err != nil {
			t.Fatalf("Request to local server failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()

		select {
		case receivedSNI := <-sniChan:
			t.Logf("Local server received SNI: '%s'", receivedSNI)
			if receivedSNI != "localhost" {
				t.Errorf("Incorrect SNI value. Expected 'localhost', got '%s'", receivedSNI)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Timeout: Did not receive SNI value from local server.")
		}
		select {
		case receivedHost := <-hostChan:
			t.Logf("Local server received Host/Authority: '%s'", receivedHost)
			if receivedHost != serverURL.Host {
				t.Errorf("Incorrect Host/Authority value. Expected '%s', got '%s'", serverURL.Host, receivedHost)
			}
		case <-time.After(3 * time.Second):
			t.Fatal("Timeout: Did not receive Host value from local server.")
		}
	})
}

func setupLocalTLSServer(t *testing.T) (serverURL *url.URL, sniChan, hostChan chan string, cleanup func()) {
	sniChan = make(chan string, 1)
	hostChan = make(chan string, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.TLS != nil {
			sniChan <- r.TLS.ServerName
		} else {
			sniChan <- ""
		}
		hostChan <- r.Host
		w.WriteHeader(http.StatusOK)
	})
	server := httptest.NewUnstartedServer(handler)

	cert, key, err := generateSelfSignedCert("localhost")
	if err != nil {
		t.Fatalf("Failed to generate self-signed cert: %v", err)
	}
	tlsCert, err := tls.X509KeyPair(cert, key)
	if err != nil {
		t.Fatalf("Failed to create key pair: %v", err)
	}
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{tlsCert},
		NextProtos:   []string{"h2", "http/1.1"},
	}
	server.StartTLS()

	u, err := url.Parse(server.URL)
	if err != nil {
		server.Close()
		t.Fatalf("Failed to parse server URL: %v", err)
	}

	u.Host = "localhost:" + u.Port()

	return u, sniChan, hostChan, server.Close
}

func generateSelfSignedCert(host string) (cert, key []byte, err error) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{Organization: []string{"Test Co"}},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{host},
	}
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return nil, nil, err
	}
	certBuf := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	keyBuf := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	return certBuf, keyBuf, nil
}
