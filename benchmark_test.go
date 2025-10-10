package swifthttp

import (
	"context"
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

func setupBenchmarkServer(useHTTP2 bool) (serverURL *url.URL, cleanup func()) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.Copy(io.Discard, r.Body)
		r.Body.Close()
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("ok"))
	})

	if !useHTTP2 {
		server := httptest.NewServer(handler)
		u, _ := url.Parse(server.URL)
		return u, server.Close
	}

	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{NextProtos: []string{"h2", "http/1.1"}}
	server.StartTLS()
	u, _ := url.Parse(server.URL)
	return u, server.Close
}

func BenchmarkH1_HighRPS_SingleConnection(b *testing.B) {
	serverURL, cleanup := setupBenchmarkServer(false)
	defer cleanup()

	client := NewHttpClient(WithVersion(HttpVersion1_1))
	session, err := client.CreateSession(context.Background(), serverURL)
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	req := NewRequest()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp, err := session.Request(context.Background(), req)
		if err != nil {
			b.Fatalf("Request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func BenchmarkH2_HighRPS_SingleConnection(b *testing.B) {
	serverURL, cleanup := setupBenchmarkServer(true)
	defer cleanup()

	client := NewHttpClient(WithVersion(HttpVersion2_0))
	session, err := client.CreateSession(context.Background(), serverURL)
	if err != nil {
		b.Fatalf("Failed to create session: %v", err)
	}
	defer session.Close()

	req := NewRequest()

	b.ResetTimer()
	b.ReportAllocs()

	for i := 0; i < b.N; i++ {
		resp, err := session.Request(context.Background(), req)
		if err != nil {
			b.Fatalf("Request failed: %v", err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
}

func BenchmarkH2_HighConcurrency_NewConnections(b *testing.B) {
	serverURL, cleanup := setupBenchmarkServer(true)
	defer cleanup()

	client := NewHttpClient(WithVersion(HttpVersion2_0), WithEnableReader(true))
	req := NewRequest()

	b.ResetTimer()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			session, err := client.CreateSession(context.Background(), serverURL)
			if err != nil {
				b.Errorf("Failed to create session in parallel run: %v", err)
				continue
			}

			resp, err := session.Request(context.Background(), req)
			if err != nil {
				session.Close()
				continue
			}

			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			session.Close()
		}
	})
}
