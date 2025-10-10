package swifthttp

import (
	"context"
	"fmt"
	"github.com/SyNdicateFoundation/fastrand"
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
	host := u.Host

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

	addr := &net.TCPAddr{IP: fastrand.Choice(ips), Port: port}
	isTLS := u.Scheme == "https" || hc.tls.TLSMode == HttpTlsModeForever

	return hc.createSessionWithAddr(ctx, addr, hostname, host, isTLS)
}

func (hc *Client) createSessionWithAddr(ctx context.Context, addr *net.TCPAddr, hostname, host string, isTLS bool) (HttpSession, error) {
	conn, err := hc.dial(ctx, addr)
	if err != nil {
		return nil, err
	}
	return hc.CreateSessionOverConn(ctx, conn, hostname, host, isTLS)
}

func (hc *Client) CreateSessionOverConn(ctx context.Context, conn net.Conn, hostname, host string, isTLS bool) (HttpSession, error) {
	var agent *legitagent.Agent
	var err error

	if hc.legitAgentGenerator != nil {
		agent, err = hc.legitAgentGenerator.Generate()
		if err != nil {
			return nil, fmt.Errorf("failed to generate legitagent: %w", err)
		}
	}

	if hc.httpVersion == HttpVersion3_0 {
		if !isTLS {
			hc.releaseAgent(agent)
			return nil, fmt.Errorf("HTTP/3 requires a TLS connection")
		}

		tlsConfig := hc.prepareTLSConfig(hostname, h3TLSProtos)

		addr, ok := conn.RemoteAddr().(*net.UDPAddr)
		if !ok {
			hc.releaseAgent(agent)
			return nil, fmt.Errorf("HTTP/3 session requires a UDP connection, but got %T", conn.RemoteAddr())
		}
		tcpAddr := &net.TCPAddr{IP: addr.IP, Port: addr.Port, Zone: addr.Zone}

		session, err := newH3Session(ctx, hc, tcpAddr, hostname, host, agent, tlsConfig)
		if err != nil {
			hc.releaseAgent(agent)
		}
		return session, err
	}

	if isTLS {
		tlsConfig := hc.prepareTLSConfig(hostname, hc.getTLSProtos())
		uconn := utls.UClient(conn, tlsConfig, utls.HelloCustom)

		finalSpec, err := hc.prepareFinalSpec(agent, hc.getTLSProtos())
		if err != nil {
			uconn.Close()
			hc.releaseAgent(agent)
			return nil, err
		}

		if err := uconn.ApplyPreset(finalSpec); err != nil {
			uconn.Close()
			hc.releaseAgent(agent)
			return nil, fmt.Errorf("failed to apply modified uTLS preset: %w", err)
		}

		uconn.SetSNI(hostname)

		if err := uconn.HandshakeContext(ctx); err != nil {
			uconn.Close()
			hc.releaseAgent(agent)
			return nil, fmt.Errorf("utls handshake failed: %w", err)
		}
		conn = uconn
	}

	var session HttpSession
	switch hc.httpVersion {
	case HttpVersion1_1:
		session, err = newH1Session(hc, conn, hostname, host, agent)
	case HttpVersion2_0:
		session, err = newH2Session(hc, conn, hostname, host, agent)
	case HttpVersionSPDY31:
		session, err = newSpdy3Session(hc, conn, hostname, host, agent)
	default:
		conn.Close()
		err = fmt.Errorf("unsupported http version for tcp session: %s", hc.httpVersion)
	}

	if err != nil {
		hc.releaseAgent(agent)
	}
	return session, err
}

func (hc *Client) prepareFinalSpec(agent *legitagent.Agent, alpns []string) (*utls.ClientHelloSpec, error) {
	var finalSpec *utls.ClientHelloSpec

	if agent != nil && agent.ClientHelloSpec != nil {
		finalSpec = agent.ClientHelloSpec
	} else {
		helloID := hc.getHelloID(agent)
		spec, err := utls.UTLSIdToSpec(helloID)
		if err != nil {
			return nil, fmt.Errorf("failed to convert HelloID to spec: %w", err)
		}
		finalSpec = &spec
	}

	var alpnExtension *utls.ALPNExtension
	var foundAlpn bool
	for _, ext := range finalSpec.Extensions {
		if alpnExtension, foundAlpn = ext.(*utls.ALPNExtension); foundAlpn {
			break
		}
	}

	if foundAlpn {
		alpnExtension.AlpnProtocols = alpns
	} else {
		finalSpec.Extensions = append(finalSpec.Extensions, &utls.ALPNExtension{
			AlpnProtocols: alpns,
		})
	}

	return finalSpec, nil
}

func (hc *Client) getHelloID(agent *legitagent.Agent) utls.ClientHelloID {
	if agent != nil {
		if agent.ClientHelloID.Client != "" {
			return agent.ClientHelloID
		}
	}

	return utls.HelloChrome_Auto
}
func (hc *Client) getTLSProtos() []string {
	switch hc.httpVersion {
	case HttpVersion2_0:
		return h2TLSProtos
	case HttpVersionSPDY31:
		return spdyTLSProtos
	case HttpVersion3_0:
		return h3TLSProtos
	case HttpVersion1_1:
		fallthrough
	default:
		return h1TLSProtos
	}

}

func (hc *Client) releaseAgent(agent *legitagent.Agent) {
	if hc.legitAgentGenerator != nil && agent != nil {
		hc.legitAgentGenerator.ReleaseAgent(agent)
	}
}

func (hc *Client) prepareTLSConfig(hostname string, alpns []string) *utls.Config {
	var tlsConfig *utls.Config

	if hc.tls != nil && hc.tls.UTLSConfig != nil {
		tlsConfig = hc.tls.UTLSConfig.Clone()
	} else {
		tlsConfig = &utls.Config{}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.PreferSkipResumptionOnNilExtension = true
	}

	if hc.tls != nil && hc.tls.OptimizedConn {
		tlsConfig.CipherSuites = []uint16{
			utls.TLS_AES_128_GCM_SHA256,
			utls.TLS_CHACHA20_POLY1305_SHA256,
		}

		tlsConfig.MinVersion = utls.VersionTLS13
		tlsConfig.MaxVersion = utls.VersionTLS13
		tlsConfig.InsecureSkipTimeVerify = true
	}

	tlsConfig.ServerName = hostname
	tlsConfig.NextProtos = append([]string(nil), alpns...)

	return tlsConfig
}
