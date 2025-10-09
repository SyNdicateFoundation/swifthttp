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
	conn         net.Conn
	framer       *spdy.Framer
	writeMu      sync.Mutex
	lastStreamID uint32
	streams      map[uint32]*spdyStream
	streamMu     sync.RWMutex
	connClosed   atomic.Bool
	bw           *bufio.Writer
}

func newSpdy3Session(client *Client, conn net.Conn, hostname string, agent *legitagent.Agent) (HttpSession, error) {
	bw := bufio.NewWriter(conn)
	framer, err := spdy.NewFramer(bw, conn)
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
		bw:            bw,
	}

	go s3s.readLoop()
	return s3s, nil
}

func (s *HttpSessionSpdy31) Close() error {
	if s.connClosed.CompareAndSwap(false, true) {
		if s.agent != nil && s.client.legitAgentGenerator != nil {
			s.client.legitAgentGenerator.ReleaseAgent(s.agent)
		}
		s.writeMu.Lock()
		s.framer.WriteFrame(&spdy.GoAwayFrame{LastGoodStreamId: atomic.LoadUint32(&s.lastStreamID)})
		s.bw.Flush()
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
	return s.sendRequest(req, 0)
}

func (s *HttpSessionSpdy31) Request(ctx context.Context, req *HttpRequest) (*http.Response, error) {
	if s.connClosed.Load() {
		return nil, net.ErrClosed
	}

	respChan := make(chan *http.Response, 1)
	streamID := s.nextStreamID()

	s.streamMu.Lock()
	s.streams[streamID] = &spdyStream{
		responseChan: respChan,
		body:         bytebufferpool.Get(),
		header:       make(http.Header),
	}
	s.streamMu.Unlock()

	defer func() {
		s.streamMu.Lock()
		if stream, ok := s.streams[streamID]; ok {
			if !stream.streamEnded {
				bytebufferpool.Put(stream.body)
			}
		}
		delete(s.streams, streamID)
		s.streamMu.Unlock()
	}()

	if err := s.sendRequest(req, streamID); err != nil {
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

func (s *HttpSessionSpdy31) sendRequest(req *HttpRequest, streamID uint32) error {
	var finalBody []byte
	hasBody := len(req.Body) > 0
	if hasBody {
		finalBody = req.Body
		if s.client.randomizer != nil {
			finalBody = s.client.randomizer.Randomizer(finalBody)
		}
	}

	headers := s.prepareHeaders(req, false)
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

	spdyHeaders := make(http.Header)
	for k, v := range headers {
		keyToWrite := strings.ToLower(k)
		valuesToWrite := v
		if s.client.randomizer != nil {
			keyToWrite = s.client.randomizer.RandomizerString(keyToWrite)
			randomizedValues := make([]string, len(v))
			for i, val := range v {
				randomizedValues[i] = s.client.randomizer.RandomizerString(val)
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
	spdyHeaders.Set("host", s.hostname)

	s.writeMu.Lock()
	defer s.writeMu.Unlock()

	synStreamFrame := &spdy.SynStreamFrame{
		StreamId: streamID,
		Headers:  spdyHeaders,
	}

	if !hasBody {
		synStreamFrame.CFHeader.Flags = spdy.ControlFlagFin
	}

	if err := s.framer.WriteFrame(synStreamFrame); err != nil {
		return fmt.Errorf("spdy write syn_stream failed: %w", err)
	}

	if hasBody {
		dataFrame := &spdy.DataFrame{
			StreamId: streamID,
			Data:     finalBody,
			Flags:    spdy.DataFlagFin,
		}
		if err := s.framer.WriteFrame(dataFrame); err != nil {
			return fmt.Errorf("spdy write data failed: %w", err)
		}
	}
	return s.bw.Flush()
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
		case *spdy.RstStreamFrame:
			s.streamMu.Lock()
			if stream, ok := s.streams[f.StreamId]; ok && !stream.streamEnded {
				close(stream.responseChan)
			}
			delete(s.streams, f.StreamId)
			s.streamMu.Unlock()
			continue
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
			s.streamMu.Lock()
			if stream.streamEnded {
				s.streamMu.Unlock()
				continue
			}
			stream.streamEnded = true
			s.streamMu.Unlock()

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
