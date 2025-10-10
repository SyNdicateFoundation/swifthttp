package swifthttp

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"time"

	"github.com/SyNdicateFoundation/legitagent"
	"github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"
	"golang.org/x/net/http2"
)

type HttpSession interface {
	io.Closer
	Fire(ctx context.Context, req *HttpRequest) error
	Request(ctx context.Context, req *HttpRequest) (*http.Response, error)
}

var (
	h1TLSProtos   = []string{"http/1.1"}
	h2TLSProtos   = []string{http2.NextProtoTLS}
	h3TLSProtos   = []string{http3.NextProtoH3}
	spdyTLSProtos = []string{"spdy/3.1"}
)

var globalDnsCache = sync.Map{}

func (hc *Client) lookupIP(hostname string) ([]net.IP, error) {
	if !hc.enableCache {
		return net.LookupIP(hostname)
	}

	if entry, found := globalDnsCache.Load(hostname); found {
		e := entry.(*dnsCacheEntry)
		if time.Now().Before(e.expiry) {
			return e.ips, nil
		}
	}

	ips, err := net.LookupIP(hostname)
	if err != nil {
		return nil, err
	}

	newEntry := &dnsCacheEntry{
		ips:      ips,
		expiry:   time.Now().Add(DefaultCacheTTL),
		hostname: hostname,
	}

	globalDnsCache.Store(hostname, newEntry)

	return ips, nil
}

func (hc *Client) CreateSession(ctx context.Context, u *url.URL) (HttpSession, error) {
	hostname := u.Hostname()
	portStr := u.Port()
	if portStr == "" {
		if u.Scheme == "https" {
			portStr = "443"
		} else {
			portStr = "80"
		}
	}

	ips, err := hc.lookupIP(hostname)
	if err != nil {
		return nil, fmt.Errorf("dns lookup failed for %s: %w", hostname, err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("no ip addresses found for %s", hostname)
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, fmt.Errorf("invalid port %s: %w", portStr, err)
	}

	addr := &net.TCPAddr{IP: ips[0], Port: port}
	isTLS := u.Scheme == "https" || hc.tls.TLSMode == HttpTlsModeForever

	return hc.createSessionWithAddr(ctx, addr, hostname, isTLS)
}

func (hc *Client) createSessionWithAddr(ctx context.Context, addr *net.TCPAddr, hostname string, isTLS bool) (HttpSession, error) {
	conn, err := hc.dial(ctx, addr)
	if err != nil {
		return nil, err
	}

	return hc.CreateSessionOverConn(ctx, conn, hostname, isTLS)
}

func (hc *Client) CreateSessionOverConn(ctx context.Context, conn net.Conn, hostname string, isTLS bool) (HttpSession, error) {
	var agent *legitagent.Agent

	if hc.legitAgentGenerator != nil {
		var err error
		agent, err = hc.legitAgentGenerator.Generate()
		if err != nil {
			return nil, fmt.Errorf("failed to generate legitagent: %w", err)
		}
	}

	if hc.httpVersion == HttpVersion3_0 {
		if !isTLS {
			if agent != nil {
				hc.legitAgentGenerator.ReleaseAgent(agent)
			}
			return nil, fmt.Errorf("HTTP/3 requires a TLS connection")
		}

		addr, ok := conn.RemoteAddr().(*net.UDPAddr)
		if !ok {
			return nil, fmt.Errorf("HTTP/3 requires a TCP address to derive UDP address, but got %T", conn.RemoteAddr())
		}

		session, err := newH3Session(ctx, hc, (*net.TCPAddr)(addr), hostname, agent, hc.prepareTLSConfig(hostname, h3TLSProtos))
		if err != nil && agent != nil {
			hc.legitAgentGenerator.ReleaseAgent(agent)
		}

		return session, err
	}

	if isTLS {
		var protos []string
		switch hc.httpVersion {
		case HttpVersion2_0:
			protos = h2TLSProtos
		case HttpVersionSPDY31:
			protos = spdyTLSProtos
		default:
			protos = h1TLSProtos
		}

		tlsConfig := hc.prepareTLSConfig(hostname, protos)
		helloID := utls.HelloChrome_Auto

		if agent != nil && agent.ClientHelloSpec != nil {
			helloID = utls.HelloCustom
		} else if agent != nil && agent.ClientHelloID.Client != "" {
			helloID = agent.ClientHelloID
		}

		if hc.httpVersion == HttpVersionSPDY31 {
			helloID = utls.HelloGolang
		}

		uconn := utls.UClient(conn, tlsConfig, helloID)
		if agent != nil && agent.ClientHelloSpec != nil {
			if err := uconn.ApplyPreset(agent.ClientHelloSpec); err != nil {
				uconn.Close()
				hc.legitAgentGenerator.ReleaseAgent(agent)
				return nil, fmt.Errorf("failed to apply utls preset: %w", err)
			}
		}

		if err := uconn.HandshakeContext(ctx); err != nil {
			uconn.Close()
			if agent != nil {
				hc.legitAgentGenerator.ReleaseAgent(agent)
			}
			return nil, fmt.Errorf("utls handshake failed: %w", err)
		}
		conn = uconn
	}

	var session HttpSession
	var err error
	switch hc.httpVersion {
	case HttpVersion1_1:
		session, err = newH1Session(hc, conn, hostname, agent)
	case HttpVersion2_0:
		session, err = newH2Session(hc, conn, hostname, agent)
	case HttpVersionSPDY31:
		session, err = newSpdy3Session(hc, conn, hostname, agent)
	default:
		conn.Close()
		err = fmt.Errorf("unsupported http version for tcp session: %s", hc.httpVersion)
	}

	if err != nil && agent != nil {
		hc.legitAgentGenerator.ReleaseAgent(agent)
	}
	return session, err
}

func (hc *Client) prepareTLSConfig(hostname string, alpns []string) *utls.Config {
	var tlsConfig *utls.Config

	if hc.tls != nil && hc.tls.UTLSConfig != nil {
		tlsConfig = hc.tls.UTLSConfig.Clone()
	} else {
		tlsConfig = &utls.Config{
			InsecureSkipVerify: true,
		}
	}

	tlsConfig.ServerName = hostname
	tlsConfig.NextProtos = alpns
	return tlsConfig
}
