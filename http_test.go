package swifthttp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	utls "github.com/refraction-networking/utls"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	"github.com/SyNdicateFoundation/legitagent"
	uquic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/http3"
	"github.com/shykes/spdy-go"
)

type receivedRequest struct {
	Method string
	URL    *url.URL
	Proto  string
	Header http.Header
	Body   []byte
	Host   string
}

func TestClient_Request_HTTP1_1_NoTLS(t *testing.T) {
	receivedChan := make(chan receivedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		receivedChan <- receivedRequest{Method: r.Method, URL: r.URL, Proto: r.Proto, Header: r.Header, Body: body, Host: r.Host}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	serverURL, _ := url.ParseRequestURI(server.URL)
	client := NewHttpClient(WithVersion(HttpVersion1_1))

	reqBody := []byte("Hello HTTP/1.1")
	httpReq := NewRequest(
		WithMethod(RequestTypePut),
		WithBody(reqBody, "application/json"),
		WithSetHeader("X-Custom-H11", "Value-H11"),
	)

	session, err := client.CreateSession(context.Background(), serverURL)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	defer session.Close()

	resp, err := session.Request(context.Background(), httpReq)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	select {
	case rec := <-receivedChan:
		if rec.Method != string(RequestTypePut) {
			t.Errorf("Expected method %s, got %s", RequestTypePut, rec.Method)
		}
		if val := rec.Header.Get("X-Custom-H11"); val != "Value-H11" {
			t.Errorf("Expected header X-Custom-H11 to be 'Value-H11', got '%s'", val)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("Timeout waiting for request at server")
	}
}

func TestClient_Request_HTTP2_0(t *testing.T) {
	receivedChan := make(chan receivedRequest, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		receivedChan <- receivedRequest{
			Method: r.Method,
			URL:    r.URL,
			Proto:  r.Proto,
			Header: r.Header,
			Body:   body,
			Host:   r.Host,
		}
		w.WriteHeader(http.StatusOK)
	})

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	server.StartTLS()
	defer server.Close()

	serverURL, _ := url.ParseRequestURI(server.URL)
	la := legitagent.NewGenerator()

	client := NewHttpClient(
		WithVersion(HttpVersion2_0),
		WithAgentGenerator(la),
	)

	httpReq := NewRequest(
		WithMethod(RequestTypePost),
		WithBody([]byte(`{"key": "value"}`), "application/json"),
	)

	session, err := client.CreateSession(context.Background(), serverURL)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	defer session.Close()

	resp, err := session.Request(context.Background(), httpReq)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	select {
	case rec := <-receivedChan:
		t.Logf("Received request at server: %#v", rec)
		if rec.Proto != "HTTP/2.0" {
			t.Errorf("Expected protocol HTTP/2.0, got %s", rec.Proto)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for H2 request at server")
	}
}

func generateH3TestTLSConfig() *utls.Config {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost", "127.0.0.1"}}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, _ := utls.X509KeyPair(certPEM, keyPEM)
	return &utls.Config{Certificates: []utls.Certificate{tlsCert}, NextProtos: []string{http3.NextProtoH3}}
}

func setupH3TestServer(handler http.Handler) (*url.URL, func()) {
	udpAddr, _ := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	udpConn, _ := net.ListenUDP("udp", udpAddr)
	serverPort := udpConn.LocalAddr().(*net.UDPAddr).Port
	serverURL, _ := url.Parse(fmt.Sprintf("https://127.0.0.1:%d", serverPort))

	http3Server := &http3.Server{
		Addr:       serverURL.Host,
		TLSConfig:  generateH3TestTLSConfig(),
		QuicConfig: &uquic.Config{MaxIdleTimeout: 30 * time.Second},
		Handler:    handler,
	}

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		http3Server.Serve(udpConn)
	}()

	time.Sleep(100 * time.Millisecond)
	cleanup := func() {
		http3Server.Close()
		udpConn.Close()
		wg.Wait()
	}
	return serverURL, cleanup
}

func TestClient_Request_HTTP3_0(t *testing.T) {
	receivedChan := make(chan receivedRequest, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		receivedChan <- receivedRequest{Method: r.Method, Proto: r.Proto, Header: r.Header, Body: body}
		w.WriteHeader(http.StatusOK)
	})

	serverURL, cleanup := setupH3TestServer(handler)
	defer cleanup()

	client := NewHttpClient(WithVersion(HttpVersion3_0))
	httpReq := NewRequest(
		WithMethod(RequestTypePost),
		WithBody([]byte(`{}`), "application/json"),
	)

	session, err := client.CreateSession(context.Background(), serverURL)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	defer session.Close()

	resp, err := session.Request(context.Background(), httpReq)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	select {
	case rec := <-receivedChan:
		if rec.Proto != "HTTP/3.0" {
			t.Errorf("Expected proto HTTP/3.0, got %s", rec.Proto)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for request at H3 server")
	}
}

func setupSPDYTestServer(t *testing.T, handler http.Handler) (*url.URL, func()) {
	key, _ := rsa.GenerateKey(rand.Reader, 2048)
	template := x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now(), NotAfter: time.Now().Add(time.Hour), DNSNames: []string{"localhost"}}
	certDER, _ := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	tlsCert, _ := tls.X509KeyPair(certPEM, keyPEM)
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{tlsCert}, NextProtos: []string{"spdy/3.1"}}
	listener, _ := tls.Listen("tcp", "127.0.0.1:0", tlsConfig)
	serverURL, _ := url.Parse("https://" + listener.Addr().String())

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer func() { recover() }()
		spdy.ListenAndServe(listener, handler)
	}()

	return serverURL, func() {
		listener.Close()
		wg.Wait()
	}
}

func TestClient_Request_SPDY_3_1(t *testing.T) {
	receivedChan := make(chan receivedRequest, 1)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		r.Body.Close()
		receivedChan <- receivedRequest{Method: r.Method, URL: r.URL, Proto: r.Proto, Header: r.Header, Body: body}
		w.WriteHeader(http.StatusOK)
	})

	serverURL, cleanup := setupSPDYTestServer(t, handler)
	defer cleanup()

	client := NewHttpClient(WithVersion(HttpVersionSPDY31))
	reqBody := []byte("Hello SPDY")
	httpReq := NewRequest(WithMethod(RequestTypePost), WithBody(reqBody, "text/plain"))

	session, err := client.CreateSession(context.Background(), serverURL)
	if err != nil {
		t.Fatalf("CreateSession failed: %v", err)
	}
	defer session.Close()

	resp, err := session.Request(context.Background(), httpReq)
	if err != nil {
		t.Fatalf("Request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	select {
	case rec := <-receivedChan:
		if !bytes.Equal(rec.Body, reqBody) {
			t.Errorf("Expected body '%s', got '%s'", string(reqBody), string(rec.Body))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Timeout waiting for request at SPDY server")
	}
}
