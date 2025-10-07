package swifthttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/SyNdicateFoundation/legitagent"
	"github.com/shykes/spdy-go"
)

type spdyStream struct {
	responseChan chan<- *http.Response
	body         *bytes.Buffer
	header       http.Header
	streamEnded  bool
}

type HttpSessionSpdy31 struct {
	*SessionCommon
	conn         net.Conn
	framer       *spdy.Framer
	writeMu      sync.Mutex
	lastStreamID uint32
	streams      map[uint32]*spdyStream
	streamMu     sync.RWMutex
	connClosed   atomic.Bool
}

func newSpdy3Session(client *Client, conn net.Conn, hostname string, agent *legitagent.Agent) (HttpSession, error) {
	framer, err := spdy.NewFramer(conn, conn)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create SPDY framer: %w", err)
	}

	s3s := &HttpSessionSpdy31{
		SessionCommon: newSessionCommon(client, hostname, agent),
		conn:          conn,
		framer:        framer,
		streams:       make(map[uint32]*spdyStream),
		lastStreamID:  ^uint32(0),
	}

	go s3s.readLoop()
	return s3s, nil
}

func (s *HttpSessionSpdy31) Close() error {
	if s.connClosed.CompareAndSwap(false, true) {
		s.writeMu.Lock()
		s.framer.WriteFrame(&spdy.GoAwayFrame{LastGoodStreamId: atomic.LoadUint32(&s.lastStreamID)})
		s.writeMu.Unlock()
		return s.conn.Close()
	}
	return nil
}

func (s *HttpSessionSpdy31) nextStreamID() uint32 {
	return atomic.AddUint32(&s.lastStreamID, 2)
}

func (s *HttpSessionSpdy31) Fire(ctx context.Context, req *HttpRequest) error {
	if s.connClosed.Load() {
		return net.ErrClosed
	}
	return s.sendRequest(req, 0, nil)
}

func (s *HttpSessionSpdy31) Request(ctx context.Context, req *HttpRequest) (*http.Response, error) {
	if s.connClosed.Load() {
		return nil, net.ErrClosed
	}

	respChan := make(chan *http.Response, 1)
	streamID := s.nextStreamID()

	s.streamMu.Lock()
	s.streams[streamID] = &spdyStream{responseChan: respChan, body: new(bytes.Buffer), header: make(http.Header)}
	s.streamMu.Unlock()

	if err := s.sendRequest(req, streamID, nil); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-ctx.Done():
		s.streamMu.Lock()
		delete(s.streams, streamID)
		s.streamMu.Unlock()
		return nil, ctx.Err()
	}
}

func (s *HttpSessionSpdy31) sendRequest(req *HttpRequest, streamID uint32, respChan chan *http.Response) error {
	headers := s.buildHeaders(req, false)

	method := string(req.Method)
	if method == "" {
		method = http.MethodGet
	}
	uri := req.RawPath
	if uri == "" {
		uri = "/"
	}

	spdyHeaders := make(http.Header)
	for k, v := range headers {
		spdyHeaders[strings.ToLower(k)] = v
	}
	spdyHeaders.Set("method", method)
	spdyHeaders.Set("url", uri)
	spdyHeaders.Set("version", "HTTP/1.1")
	spdyHeaders.Set("scheme", "https")
	spdyHeaders.Del("host")
	spdyHeaders.Set("host", s.hostname)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	synStreamFrame := &spdy.SynStreamFrame{
		StreamId: streamID,
		Headers:  spdyHeaders,
	}

	hasBody := req.Body != nil && len(req.Body) > 0
	if !hasBody {
		synStreamFrame.CFHeader.Flags = spdy.ControlFlagFin
	}

	if err := s.framer.WriteFrame(synStreamFrame); err != nil {
		return fmt.Errorf("spdy write syn_stream failed: %w", err)
	}

	if hasBody {
		dataFrame := &spdy.DataFrame{
			StreamId: streamID,
			Data:     req.Body,
			Flags:    spdy.DataFlagFin,
		}
		if err := s.framer.WriteFrame(dataFrame); err != nil {
			return fmt.Errorf("spdy write data failed: %w", err)
		}
	}
	return nil
}

func (s *HttpSessionSpdy31) readLoop() {
	defer s.Close()
	for {
		frame, err := s.framer.ReadFrame()
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
		default:
			continue
		}

		s.streamMu.RLock()
		stream, ok := s.streams[streamID]
		s.streamMu.RUnlock()
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
			status := stream.header.Get("status")
			statusCode, _ := strconv.Atoi(strings.Split(status, " ")[0])
			resp := &http.Response{
				StatusCode: statusCode,
				Status:     status,
				Header:     stream.header,
				Body:       io.NopCloser(stream.body),
				Proto:      "SPDY/3.1",
			}
			stream.responseChan <- resp
			s.streamMu.Lock()
			delete(s.streams, streamID)
			s.streamMu.Unlock()
		}
	}
}
