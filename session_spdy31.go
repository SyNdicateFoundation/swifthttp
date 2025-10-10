package swifthttp

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/SyNdicateFoundation/legitagent"
	"github.com/shykes/spdy-go"
	"github.com/valyala/bytebufferpool"
)

type spdyStream struct {
	responseChan chan<- *http.Response
	body         *bytebufferpool.ByteBuffer
	header       http.Header
	streamEnded  bool
}

type HttpSessionSpdy31 struct {
	*SessionCommon
	conn             net.Conn
	framer           *spdy.Framer
	writeMu          sync.Mutex
	lastStreamID     uint32
	streams          map[uint32]*spdyStream
	streamMu         sync.RWMutex
	connClosed       atomic.Bool
	bw               *bufio.Writer
	enableReaderLoop sync.Once
}

func newSpdy3Session(client *Client, conn net.Conn, hostname string, host string, agent *legitagent.Agent) (HttpSession, error) {
	bw := bufio.NewWriter(conn)
	framer, err := spdy.NewFramer(bw, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create SPDY framer: %w", err)
	}

	s3s := &HttpSessionSpdy31{
		SessionCommon: newSessionCommon(client, hostname, host, agent),
		conn:          conn,
		framer:        framer,
		streams:       make(map[uint32]*spdyStream),
		lastStreamID:  ^uint32(0),
		bw:            bw,
	}

	if client.enableReaderLoop {
		s3s.enableReaderLoop.Do(func() {
			go s3s.readLoop()
		})
	}

	return s3s, nil
}

func (h *HttpSessionSpdy31) Close() error {
	if h.connClosed.CompareAndSwap(false, true) {
		if h.agent != nil && h.client.legitAgentGenerator != nil {
			h.client.legitAgentGenerator.ReleaseAgent(h.agent)
		}
		h.writeMu.Lock()
		h.framer.WriteFrame(&spdy.GoAwayFrame{LastGoodStreamId: atomic.LoadUint32(&h.lastStreamID)})
		h.bw.Flush()
		h.writeMu.Unlock()
		return h.conn.Close()
	}
	return nil
}

func (h *HttpSessionSpdy31) NextStreamID() uint32 {
	return atomic.AddUint32(&h.lastStreamID, 2)
}

func (h *HttpSessionSpdy31) CurrentStreamID() uint32 {
	return atomic.LoadUint32(&h.lastStreamID)
}

func (h *HttpSessionSpdy31) Fire(ctx context.Context, req *HttpRequest) error {
	if h.connClosed.Load() {
		return net.ErrClosed
	}
	return h.sendRequest(req, 0)
}

func (h *HttpSessionSpdy31) Request(ctx context.Context, req *HttpRequest) (*http.Response, error) {
	if h.connClosed.Load() {
		return nil, net.ErrClosed
	}

	h.enableReaderLoop.Do(func() {
		go h.readLoop()
	})

	respChan := make(chan *http.Response, 1)
	streamID := h.NextStreamID()

	h.streamMu.Lock()
	h.streams[streamID] = &spdyStream{
		responseChan: respChan,
		body:         bytebufferpool.Get(),
		header:       make(http.Header),
	}
	h.streamMu.Unlock()

	defer func() {
		h.streamMu.Lock()
		if stream, ok := h.streams[streamID]; ok {
			if !stream.streamEnded {
				bytebufferpool.Put(stream.body)
			}
		}
		delete(h.streams, streamID)
		h.streamMu.Unlock()
	}()

	if err := h.sendRequest(req, streamID); err != nil {
		return nil, err
	}

	select {
	case resp, ok := <-respChan:
		if !ok {
			return nil, errors.New("stream closed before response was complete")
		}
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (h *HttpSessionSpdy31) sendRequest(req *HttpRequest, streamID uint32) error {
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
		headers.Set("content-length", strconv.Itoa(len(finalBody)))
	}

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

	spdyHeaders := make(http.Header)
	for k, v := range headers {
		keyToWrite := strings.ToLower(k)
		valuesToWrite := v
		if h.client.randomizer != nil {
			keyToWrite = h.client.randomizer.RandomizerString(keyToWrite)
			randomizedValues := make([]string, len(v))
			for i, val := range v {
				randomizedValues[i] = h.client.randomizer.RandomizerString(val)
			}
			valuesToWrite = randomizedValues
		}
		spdyHeaders[keyToWrite] = valuesToWrite
	}

	spdyHeaders.Set("method", method)
	spdyHeaders.Set("url", uri)
	spdyHeaders.Set("version", "HTTP/1.1")
	spdyHeaders.Set("scheme", "https")
	spdyHeaders.Del("host")
	spdyHeaders.Set("host", h.hostname)

	h.writeMu.Lock()
	defer h.writeMu.Unlock()

	synStreamFrame := &spdy.SynStreamFrame{
		StreamId: streamID,
		Headers:  spdyHeaders,
	}

	if !hasBody {
		synStreamFrame.CFHeader.Flags = spdy.ControlFlagFin
	}

	if err := h.framer.WriteFrame(synStreamFrame); err != nil {
		return fmt.Errorf("spdy write syn_stream failed: %w", err)
	}

	if hasBody {
		dataFrame := &spdy.DataFrame{
			StreamId: streamID,
			Data:     finalBody,
			Flags:    spdy.DataFlagFin,
		}
		if err := h.framer.WriteFrame(dataFrame); err != nil {
			return fmt.Errorf("spdy write data failed: %w", err)
		}
	}

	return h.bw.Flush()
}

func (h *HttpSessionSpdy31) WriteFrame(frame spdy.Frame) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return h.framer.WriteFrame(frame)
}

func (h *HttpSessionSpdy31) readLoop() {
	defer h.Close()
	for {
		frame, err := h.framer.ReadFrame()
		if err != nil {
			return
		}

		var streamID uint32
		var isFin bool
		switch f := frame.(type) {
		case *spdy.SynReplyFrame:
			streamID = f.StreamId
			isFin = f.CFHeader.Flags&spdy.ControlFlagFin != 0
		case *spdy.DataFrame:
			streamID = f.StreamId
			isFin = f.Flags&spdy.DataFlagFin != 0
		case *spdy.RstStreamFrame:
			h.streamMu.Lock()
			if stream, ok := h.streams[f.StreamId]; ok && !stream.streamEnded {
				close(stream.responseChan)
			}
			delete(h.streams, f.StreamId)
			h.streamMu.Unlock()
			continue
		default:
			continue
		}

		h.streamMu.RLock()
		stream, ok := h.streams[streamID]
		h.streamMu.RUnlock()
		if !ok {
			continue
		}

		switch f := frame.(type) {
		case *spdy.SynReplyFrame:
			for k, v := range f.Headers {
				stream.header[http.CanonicalHeaderKey(k)] = v
			}
		case *spdy.DataFrame:
			stream.body.Write(f.Data)
		}

		if isFin {
			h.streamMu.Lock()
			if stream.streamEnded {
				h.streamMu.Unlock()
				continue
			}
			stream.streamEnded = true
			h.streamMu.Unlock()

			status := stream.header.Get("status")
			statusCode, _ := strconv.Atoi(strings.Split(status, " ")[0])
			resp := &http.Response{
				StatusCode: statusCode,
				Status:     status,
				Header:     stream.header,
				Body:       &byteBufferPoolCloser{reader: bytes.NewReader(stream.body.Bytes()), buffer: stream.body},
				Proto:      "SPDY/3.1",
			}
			stream.responseChan <- resp
		}
	}
}
