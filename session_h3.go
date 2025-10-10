package swifthttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/SyNdicateFoundation/legitagent"
	uquic "github.com/refraction-networking/uquic"
	"github.com/refraction-networking/uquic/http3"
	utls "github.com/refraction-networking/utls"
)

type httpSessionH3 struct {
	*SessionCommon
	rt         *http3.RoundTripper
	quicConn   uquic.EarlyConnection
	connClosed atomic.Bool
}

func newH3Session(ctx context.Context, client *Client, addr *net.TCPAddr, hostname string, host string, agent *legitagent.Agent, utlsConfig *utls.Config) (HttpSession, error) {
	udpAddr := &net.UDPAddr{IP: addr.IP, Port: addr.Port, Zone: addr.Zone}

	var packetConn net.PacketConn
	var err error

	if client.proxy != nil {
		var rawConn net.Conn
		rawConn, err = client.dial(ctx, addr)
		if err != nil {
			return nil, fmt.Errorf("h3 proxy dial failed: %w", err)
		}
		var ok bool
		packetConn, ok = rawConn.(net.PacketConn)
		if !ok {
			rawConn.Close()
			return nil, fmt.Errorf("proxy conn for H3 was not a net.PacketConn")
		}
	} else {
		network := "udp4"
		if addr.IP.To4() == nil {
			network = "udp6"
		}
		packetConn, err = net.ListenPacket(network, ":0")
		if err != nil {
			return nil, fmt.Errorf("h3 listen packet on %s failed: %w", network, err)
		}
	}

	quicConfig := &uquic.Config{
		MaxIdleTimeout:  30 * time.Second,
		KeepAlivePeriod: 5 * time.Second,
	}

	quicConn, err := uquic.DialEarly(ctx, packetConn, udpAddr, utlsConfig, quicConfig)
	if err != nil {
		packetConn.Close()
		return nil, fmt.Errorf("failed to establish QUIC connection: %w", err)
	}

	s := &httpSessionH3{
		SessionCommon: newSessionCommon(client, hostname, host, agent),
		quicConn:      quicConn,
		rt: &http3.RoundTripper{
			Dial: func(context.Context, string, *utls.Config, *uquic.Config) (uquic.EarlyConnection, error) {
				return quicConn, nil
			},
		},
	}
	s.connClosed.Store(false)
	return s, nil
}

func (h *httpSessionH3) isClosed() bool {
	return h.connClosed.Load()
}

func (h *httpSessionH3) Close() error {
	if h.connClosed.CompareAndSwap(false, true) {
		if h.agent != nil && h.client.legitAgentGenerator != nil {
			h.client.legitAgentGenerator.ReleaseAgent(h.agent)
		}

		if h.rt != nil {
			h.rt.Close()
		}
		if h.quicConn != nil {
			return h.quicConn.CloseWithError(0, "")
		}
	}
	return nil
}

func (h *httpSessionH3) Fire(ctx context.Context, req *HttpRequest) error {
	if h.isClosed() {
		return net.ErrClosed
	}
	go func() {
		defer func() {
			recover()
		}()
		resp, err := h.Request(ctx, req)
		if err != nil {
			return
		}
		if resp != nil && resp.Body != nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	return nil
}

func (h *httpSessionH3) Request(ctx context.Context, req *HttpRequest) (*http.Response, error) {
	if h.isClosed() {
		return nil, net.ErrClosed
	}

	method := string(req.Method)
	if method == "" {
		method = http.MethodGet
	}

	var finalBody []byte
	if len(req.Body) > 0 {
		finalBody = req.Body
		if h.client.randomizer != nil {
			finalBody = h.client.randomizer.Randomizer(finalBody)
		}
	}

	var bodyReader io.Reader
	if finalBody != nil {
		bodyReader = bytes.NewReader(finalBody)
	}

	uri := req.RawPath
	if uri == "" {
		uri = "/"
	}

	if h.client.randomizer != nil {
		uri = h.client.randomizer.RandomizerString(uri)
	}

	urlStr := fmt.Sprintf("https://%s%s", h.host, uri)
	stdReq, err := http.NewRequestWithContext(ctx, method, urlStr, bodyReader)
	if err != nil {
		return nil, fmt.Errorf("failed to create standard http.Request: %w", err)
	}

	headers := h.prepareHeaders(req, false)

	if h.client.randomizer != nil {
		randomizedHeaders := make(http.Header)
		for key, values := range headers {
			randomKey := h.client.randomizer.RandomizerString(key)
			for _, value := range values {
				randomizedHeaders.Add(randomKey, h.client.randomizer.RandomizerString(value))
			}
		}
		stdReq.Header = randomizedHeaders
	} else {
		stdReq.Header = headers
	}

	resp, err := h.rt.RoundTrip(stdReq)
	if err != nil {
		h.Close()
		return nil, err
	}
	return resp, nil
}
