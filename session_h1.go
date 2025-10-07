package swifthttp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/SyNdicateFoundation/legitagent"
	"github.com/valyala/bytebufferpool"
)

type HttpSessionH1 struct {
	*SessionCommon
	net.Conn
	connClosed atomic.Bool
}

func newH1Session(client *Client, conn net.Conn, hostname string, agent *legitagent.Agent) (HttpSession, error) {
	common := newSessionCommon(client, hostname, agent)
	h := &HttpSessionH1{
		Conn:          conn,
		SessionCommon: common,
	}
	h.connClosed.Store(false)
	return h, nil
}

func (h *HttpSessionH1) Close() error {
	if h.connClosed.CompareAndSwap(false, true) {
		if h.Conn == nil {
			return nil
		}
		if h.agent != nil && h.client.legitAgentGenerator != nil {
			h.client.legitAgentGenerator.ReleaseAgent(h.agent)
		}

		return h.Conn.Close()
	}
	return nil
}

func (h *HttpSessionH1) isClosed() bool {
	return h.connClosed.Load()
}

func (h *HttpSessionH1) Fire(ctx context.Context, req *HttpRequest) error {
	if h.isClosed() {
		return net.ErrClosed
	}

	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)

	h.buildH1Payload(buf, req)

	if _, err := h.Conn.Write(buf.B); err != nil {
		_ = h.Close()
		return err
	}
	return nil
}

func (h *HttpSessionH1) Request(ctx context.Context, req *HttpRequest) (*http.Response, error) {
	if h.isClosed() {
		return nil, net.ErrClosed
	}

	buf := bytebufferpool.Get()
	defer bytebufferpool.Put(buf)
	h.buildH1Payload(buf, req)

	if h.client.timeout.Request > 0 {
		deadline := time.Now().Add(h.client.timeout.Request)
		if err := h.Conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
		defer h.Conn.SetDeadline(time.Time{})
	}

	if _, err := h.Conn.Write(buf.B); err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("h1 request write failed: %w", err)
	}

	reader := bufio.NewReader(h.Conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("h1 read response failed: %w", err)
	}
	return resp, nil
}

func (h *HttpSessionH1) buildH1Payload(buf *bytebufferpool.ByteBuffer, req *HttpRequest) {
	method := string(req.Method)
	if method == "" {
		method = http.MethodGet
	}

	_, _ = buf.WriteString(method)
	_ = buf.WriteByte(' ')

	uri := req.RawPath
	if uri == "" {
		uri = "/"
	}
	_, _ = buf.WriteString(uri)
	_ = buf.WriteByte(' ')
	_, _ = buf.WriteString("HTTP/1.1\r\n")

	headers := h.buildHeaders(req, false)
	headerKeys := h.getHeaderOrder(headers)

	for _, k := range headerKeys {
		for _, v := range headers[k] {
			_, _ = buf.WriteString(k)
			_, _ = buf.WriteString(": ")
			_, _ = buf.WriteString(v)
			_, _ = buf.WriteString("\r\n")
		}
	}
	_, _ = buf.WriteString("\r\n")

	if req.Body != nil {
		_, _ = buf.Write(req.Body)
	}
}
