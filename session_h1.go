package swifthttp

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/SyNdicateFoundation/legitagent"
	"github.com/valyala/bytebufferpool"
)

type HttpSessionH1 struct {
	*SessionCommon
	net.Conn
	connClosed atomic.Bool
	writeMu    sync.Mutex
	br         *bufio.Reader
	bw         *bufio.Writer
	requestBuf *bytebufferpool.ByteBuffer
}

func newH1Session(client *Client, conn net.Conn, hostname string, host string, agent *legitagent.Agent) (HttpSession, error) {
	common := newSessionCommon(client, hostname, host, agent)
	h := &HttpSessionH1{
		Conn:          conn,
		SessionCommon: common,
		br:            bufio.NewReader(conn),
		bw:            bufio.NewWriter(conn),
		requestBuf:    new(bytebufferpool.ByteBuffer),
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

	h.writeMu.Lock()
	defer h.writeMu.Unlock()

	h.requestBuf.Reset()
	h.buildH1Payload(h.requestBuf, req)

	if _, err := h.bw.Write(h.requestBuf.B); err != nil {
		_ = h.Close()
		return err
	}
	return h.bw.Flush()
}

func (h *HttpSessionH1) Request(ctx context.Context, req *HttpRequest) (*http.Response, error) {
	if h.isClosed() {
		return nil, net.ErrClosed
	}

	h.writeMu.Lock()
	defer h.writeMu.Unlock()

	h.requestBuf.Reset()
	h.buildH1Payload(h.requestBuf, req)

	if h.client.timeout.Request > 0 {
		deadline := time.Now().Add(h.client.timeout.Request)
		if err := h.Conn.SetDeadline(deadline); err != nil {
			return nil, err
		}
		defer h.Conn.SetDeadline(time.Time{})
	}

	if _, err := h.bw.Write(h.requestBuf.B); err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("h1 request write failed: %w", err)
	}

	if err := h.bw.Flush(); err != nil {
		_ = h.Close()
		return nil, fmt.Errorf("h1 request flush failed: %w", err)
	}

	resp, err := http.ReadResponse(h.br, nil)
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

	uri := req.RawPath
	if uri == "" {
		uri = "/"
	}

	if h.client.randomizer != nil {
		uri = h.client.randomizer.RandomizerString(uri)
	}

	buf.WriteString(method)
	buf.WriteByte(' ')
	buf.WriteString(uri)
	buf.WriteString(" HTTP/1.1\r\n")

	var finalBody []byte
	hasBody := len(req.Body) > 0
	if hasBody {
		finalBody = req.Body
		if h.client.randomizer != nil {
			finalBody = h.client.randomizer.Randomizer(finalBody)
		}
	}

	headers := h.prepareHeaders(req, false)
	if hasBody {
		headers.Set("Content-Length", strconv.Itoa(len(finalBody)))
	}

	headerOrder := h.prepareHeaderOrder(headers)

	for _, k := range headerOrder {
		values, ok := headers[k]
		if !ok {
			continue
		}
		for _, v := range values {
			keyToWrite := k
			valueToWrite := v

			if h.client.randomizer != nil {
				keyToWrite = h.client.randomizer.RandomizerString(keyToWrite)
				valueToWrite = h.client.randomizer.RandomizerString(valueToWrite)
			}

			buf.WriteString(keyToWrite)
			buf.WriteString(": ")
			buf.WriteString(valueToWrite)
			buf.WriteString("\r\n")
		}
	}

	buf.WriteString("\r\n")

	if hasBody {
		buf.Write(finalBody)
	}
}
