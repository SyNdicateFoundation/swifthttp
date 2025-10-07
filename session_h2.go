package swifthttp

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/SyNdicateFoundation/fastrand"
	"github.com/SyNdicateFoundation/legitagent"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var preface = []byte(http2.ClientPreface)

const initialWindowSizeIncrement = 15663105

type byteBufferPoolCloser struct {
	reader io.Reader
	buffer *bytebufferpool.ByteBuffer
}

func (b *byteBufferPoolCloser) Read(p []byte) (n int, err error) { return b.reader.Read(p) }
func (b *byteBufferPoolCloser) Close() error                     { bytebufferpool.Put(b.buffer); return nil }

type h2Stream struct {
	id           uint32
	responseChan chan<- *http.Response
	body         *bytebufferpool.ByteBuffer
	header       http.Header
	done         chan struct{}
	streamEnded  bool
}

type HttpSessionH2 struct {
	*SessionCommon
	conn                      net.Conn
	framer                    *http2.Framer
	writeMu                   sync.Mutex
	lastStreamID              uint32
	streams                   map[uint32]*h2Stream
	streamMu                  sync.RWMutex
	connClosed                atomic.Bool
	effectivePeerMaxFrameSize uint32
}

func newH2Session(client *Client, conn net.Conn, hostname string, agent *legitagent.Agent) (HttpSession, error) {
	if _, err := conn.Write(preface); err != nil {
		conn.Close()
		return nil, fmt.Errorf("h2 preface write failed: %w", err)
	}

	h2s := &HttpSessionH2{
		SessionCommon:             newSessionCommon(client, hostname, agent),
		conn:                      conn,
		framer:                    http2.NewFramer(conn, conn),
		streams:                   make(map[uint32]*h2Stream),
		lastStreamID:              ^uint32(0),
		effectivePeerMaxFrameSize: 16384,
	}
	h2s.framer.AllowIllegalWrites = true

	var settings []http2.Setting
	if agent != nil && agent.H2Settings != nil {
		for id, val := range agent.H2Settings {
			settings = append(settings, http2.Setting{ID: id, Val: val})
		}
	}

	h2s.writeMu.Lock()
	if err := h2s.framer.WriteSettings(settings...); err != nil {
		h2s.writeMu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("h2 write initial settings failed: %w", err)
	}

	if err := h2s.UpdateWindow(
		0,
		uint32(initialWindowSizeIncrement+fastrand.Int(-100000, 100000)),
	); err != nil {
		h2s.writeMu.Unlock()
		conn.Close()
		return nil, fmt.Errorf("h2 write initial window update failed: %w", err)
	}

	h2s.writeMu.Unlock()

	go h2s.readLoop()
	return h2s, nil
}

func (h *HttpSessionH2) Close() error {
	if h.connClosed.CompareAndSwap(false, true) {
		if h.agent != nil && h.client.legitAgentGenerator != nil {
			h.client.legitAgentGenerator.ReleaseAgent(h.agent)
		}

		h.writeMu.Lock()
		h.framer.WriteGoAway(atomic.LoadUint32(&h.lastStreamID), http2.ErrCodeNo, nil)
		h.writeMu.Unlock()
		return h.conn.Close()
	}
	return nil
}

func (h *HttpSessionH2) nextStreamID() uint32 {
	return atomic.AddUint32(&h.lastStreamID, 2)
}

func (h *HttpSessionH2) Fire(_ context.Context, req *HttpRequest) error {
	if h.connClosed.Load() {
		return net.ErrClosed
	}
	streamID := h.nextStreamID()
	return h.sendRequestFrames(streamID, req)
}

func (h *HttpSessionH2) Request(ctx context.Context, req *HttpRequest) (*http.Response, error) {
	if h.connClosed.Load() {
		return nil, net.ErrClosed
	}

	respChan := make(chan *http.Response, 1)
	streamID := h.nextStreamID()

	stream := &h2Stream{
		id:           streamID,
		responseChan: respChan,
		body:         bytebufferpool.Get(),
		header:       make(http.Header),
		done:         make(chan struct{}),
	}
	h.streamMu.Lock()
	h.streams[streamID] = stream
	h.streamMu.Unlock()

	defer func() {
		h.streamMu.Lock()
		delete(h.streams, streamID)
		h.streamMu.Unlock()
	}()

	if err := h.sendRequestFrames(streamID, req); err != nil {
		return nil, err
	}

	select {
	case resp := <-respChan:
		return resp, nil
	case <-stream.done:
		return nil, errors.New("stream closed before response was complete")
	case <-ctx.Done():
		h.ResetStream(streamID, http2.ErrCodeCancel)
		return nil, ctx.Err()
	}
}

func (h *HttpSessionH2) sendRequestFrames(streamID uint32, req *HttpRequest) error {
	headers := h.buildHeaders(req, true)
	headerKeys := h.getHeaderOrder(headers)

	h.writeMu.Lock()
	defer h.writeMu.Unlock()

	encoderBuf := bytebufferpool.Get()
	defer bytebufferpool.Put(encoderBuf)
	hpackEncoder := hpack.NewEncoder(encoderBuf)

	for _, key := range headerKeys {
		for _, value := range headers[key] {
			if h.client.randomizer {
				value = fastrand.RandomizerString(value)
			}
			hpackEncoder.WriteField(hpack.HeaderField{Name: strings.ToLower(key), Value: value})
		}
	}

	headerBlock := encoderBuf.Bytes()
	endStream := req.Body == nil

	maxPayload := int(atomic.LoadUint32(&h.effectivePeerMaxFrameSize))
	var sent int
	for sent < len(headerBlock) {
		chunk := headerBlock[sent:]
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		sent += len(chunk)
		endHeaders := sent == len(headerBlock)

		if sent == len(chunk) {
			if err := h.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: chunk, EndStream: endStream, EndHeaders: endHeaders}); err != nil {
				return err
			}
		} else {
			if err := h.framer.WriteContinuation(streamID, endHeaders, chunk); err != nil {
				return err
			}
		}
	}

	if !endStream {
		body := req.Body
		if h.client.randomizer {
			body = fastrand.Randomizer(body)
		}
		if err := h.framer.WriteData(streamID, true, body); err != nil {
			return err
		}
	}
	return nil
}

func (h *HttpSessionH2) readLoop() {
	defer h.Close()
	hpackDecoder := hpack.NewDecoder(4096, nil)
	for {
		frame, err := h.framer.ReadFrame()
		if err != nil {
			return
		}
		switch f := frame.(type) {
		case *http2.HeadersFrame:
			h.handleHeadersFrame(f, hpackDecoder)
		case *http2.DataFrame:
			h.handleDataFrame(f)
		case *http2.RSTStreamFrame:
			h.handleRSTStreamFrame(f)
		case *http2.SettingsFrame:
			if f.IsAck() {
				continue
			}
			for i := 0; i < f.NumSettings(); i++ {
				s := f.Setting(i)
				if s.ID == http2.SettingMaxFrameSize {
					atomic.StoreUint32(&h.effectivePeerMaxFrameSize, s.Val)
				}
			}
			h.framer.WriteSettingsAck()
		case *http2.GoAwayFrame:
			h.Close()
			return
		case *http2.WindowUpdateFrame:
			continue
		}
	}
}

func (h *HttpSessionH2) handleHeadersFrame(f *http2.HeadersFrame, dec *hpack.Decoder) {
	h.streamMu.RLock()
	stream, ok := h.streams[f.StreamID]
	h.streamMu.RUnlock()
	if !ok {
		return
	}
	headers, _ := dec.DecodeFull(f.HeaderBlockFragment())
	for _, hf := range headers {
		stream.header.Add(hf.Name, hf.Value)
	}
	if f.StreamEnded() {
		h.finalizeStream(stream)
	}
}

func (h *HttpSessionH2) handleDataFrame(f *http2.DataFrame) {
	h.streamMu.RLock()
	stream, ok := h.streams[f.StreamID]
	h.streamMu.RUnlock()
	if !ok {
		return
	}

	dataLen := f.Length
	stream.body.Write(f.Data())

	h.writeMu.Lock()
	h.framer.WriteWindowUpdate(f.StreamID, dataLen)
	h.framer.WriteWindowUpdate(0, dataLen)
	h.writeMu.Unlock()

	if f.StreamEnded() {
		h.finalizeStream(stream)
	}
}

func (h *HttpSessionH2) handleRSTStreamFrame(f *http2.RSTStreamFrame) {
	h.streamMu.RLock()
	stream, ok := h.streams[f.StreamID]
	h.streamMu.RUnlock()
	if ok {
		close(stream.done)
	}
}

func (h *HttpSessionH2) finalizeStream(stream *h2Stream) {
	if stream.streamEnded {
		return
	}
	stream.streamEnded = true
	status := stream.header.Get(":status")
	statusCode, _ := strconv.Atoi(status)
	resp := &http.Response{
		StatusCode: statusCode,
		Status:     status,
		Header:     stream.header,
		Body:       &byteBufferPoolCloser{reader: bytes.NewReader(stream.body.Bytes()), buffer: stream.body},
		Proto:      "HTTP/2.0",
		ProtoMajor: 2,
	}
	stream.responseChan <- resp
	close(stream.done)
}

func (h *HttpSessionH2) ResetStream(streamID uint32, errCode http2.ErrCode) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return h.framer.WriteRSTStream(streamID, errCode)
}

func (h *HttpSessionH2) WriteGoAway(maxStreamID uint32, code http2.ErrCode, debugData []byte) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return h.framer.WriteGoAway(maxStreamID, code, debugData)
}

func (h *HttpSessionH2) UpdateWindow(streamId uint32, windowId uint32) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	return h.framer.WriteWindowUpdate(streamId, windowId)
}
