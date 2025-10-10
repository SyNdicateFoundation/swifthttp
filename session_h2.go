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

	"github.com/SyNdicateFoundation/fastrand"
	"github.com/SyNdicateFoundation/legitagent"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/net/http2"
	"golang.org/x/net/http2/hpack"
)

var preface = []byte(http2.ClientPreface)

const initialWindowSizeIncrement = 15663105

type h2Stream struct {
	id           uint32
	responseChan chan<- *http.Response
	body         *bytebufferpool.ByteBuffer
	header       http.Header
	done         chan struct{}
	streamEnded  bool
}

func (s *h2Stream) Reset() {
	s.id = 0
	s.responseChan = nil
	if s.body != nil {
		bytebufferpool.Put(s.body)
		s.body = bytebufferpool.Get()
	}
	s.body.Reset()
	for k := range s.header {
		delete(s.header, k)
	}
	s.done = nil
	s.streamEnded = false
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
	bw                        *bufio.Writer
}

func newH2Session(client *Client, conn net.Conn, hostname string, agent *legitagent.Agent) (HttpSession, error) {
	if _, err := conn.Write(preface); err != nil {
		conn.Close()
		return nil, fmt.Errorf("h2 preface write failed: %w", err)
	}

	bw := bufio.NewWriter(conn)

	h2s := &HttpSessionH2{
		SessionCommon:             newSessionCommon(client, hostname, agent),
		conn:                      conn,
		framer:                    http2.NewFramer(bw, conn),
		streams:                   make(map[uint32]*h2Stream),
		lastStreamID:              ^uint32(0),
		effectivePeerMaxFrameSize: 16384,
		bw:                        bw,
	}
	h2s.framer.AllowIllegalWrites = true

	var settings []http2.Setting
	if agent != nil && agent.H2Settings != nil {
		for id, val := range agent.H2Settings {
			settings = append(settings, http2.Setting{ID: id, Val: val})
		}
	} else {
		settings = []http2.Setting{
			{ID: http2.SettingHeaderTableSize, Val: 65536},
			{ID: http2.SettingEnablePush, Val: 0},
			{ID: http2.SettingMaxConcurrentStreams, Val: 1000},
			{ID: http2.SettingInitialWindowSize, Val: 6291456},
			{ID: http2.SettingMaxFrameSize, Val: 16384},
			{ID: http2.SettingMaxHeaderListSize, Val: 262144},
		}
	}

	h2s.writeMu.Lock()
	if err := h2s.framer.WriteSettings(settings...); err != nil {
		h2s.writeMu.Unlock()
		conn.Close()
		return nil, err
	}
	if err := h2s.framer.WriteWindowUpdate(0, uint32(initialWindowSizeIncrement+fastrand.Int(-100000, 100000))); err != nil {
		h2s.writeMu.Unlock()
		conn.Close()
		return nil, err
	}
	if err := h2s.bw.Flush(); err != nil {
		h2s.writeMu.Unlock()
		conn.Close()
		return nil, err
	}
	h2s.writeMu.Unlock()

	frame, err := h2s.framer.ReadFrame()
	if err != nil {
		conn.Close()
		return nil, err
	}
	sf, ok := frame.(*http2.SettingsFrame)
	if !ok {
		conn.Close()
		return nil, fmt.Errorf("h2 expected settings frame, got %T", frame)
	}

	if sf.IsAck() {
		frame, err = h2s.framer.ReadFrame()
		if err != nil {
			conn.Close()
			return nil, err
		}
		sf, ok = frame.(*http2.SettingsFrame)
		if !ok {
			conn.Close()
			return nil, fmt.Errorf("h2 expected settings frame, got %T", frame)
		}
	}

	for i := 0; i < sf.NumSettings(); i++ {
		s := sf.Setting(i)
		if s.ID == http2.SettingMaxFrameSize {
			atomic.StoreUint32(&h2s.effectivePeerMaxFrameSize, s.Val)
		}
	}

	h2s.writeMu.Lock()
	if err := h2s.framer.WriteSettingsAck(); err != nil {
		h2s.writeMu.Unlock()
		conn.Close()
		return nil, err
	}
	if err := h2s.bw.Flush(); err != nil {
		h2s.writeMu.Unlock()
		conn.Close()
		return nil, err
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
		h.bw.Flush()
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
	return h.sendRequestFrames(streamID, req, false)
}

func (h *HttpSessionH2) Request(ctx context.Context, req *HttpRequest) (*http.Response, error) {
	if h.connClosed.Load() {
		return nil, net.ErrClosed
	}

	stream := h.client.h2StreamPool.Get().(*h2Stream)
	respChan := make(chan *http.Response, 1)
	streamID := h.nextStreamID()

	stream.id = streamID
	stream.responseChan = respChan
	stream.done = make(chan struct{})

	h.streamMu.Lock()
	h.streams[streamID] = stream
	h.streamMu.Unlock()

	defer func() {
		h.streamMu.Lock()
		delete(h.streams, streamID)
		h.streamMu.Unlock()
		stream.Reset()
		h.client.h2StreamPool.Put(stream)
	}()

	if err := h.sendRequestFrames(streamID, req, true); err != nil {
		return nil, err
	}

	select {
	case resp, ok := <-respChan:
		if !ok {
			return nil, errors.New("stream closed before response was complete")
		}
		return resp, nil
	case <-stream.done:
		return nil, errors.New("stream closed before response was complete")
	case <-ctx.Done():
		h.ResetStream(streamID, http2.ErrCodeCancel)
		return nil, ctx.Err()
	}
}

func (h *HttpSessionH2) sendRequestFrames(streamID uint32, req *HttpRequest, expectResponse bool) error {
	headers := h.prepareHeaders(req, true)
	headerOrder := h.prepareHeaderOrder(headers)

	hpackEncoderBuf := h.client.hpackEncoderBufPool.Get().(*bytebufferpool.ByteBuffer)
	hpackEncoderBuf.Reset()
	defer h.client.hpackEncoderBufPool.Put(hpackEncoderBuf)
	hpackEncoder := hpack.NewEncoder(hpackEncoderBuf)

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

			hpackEncoder.WriteField(hpack.HeaderField{
				Name:  strings.ToLower(keyToWrite),
				Value: valueToWrite,
			})
		}
	}

	headerBlock := hpackEncoderBuf.B
	hasBody := len(req.Body) > 0
	endStreamOnHeaders := !hasBody && expectResponse

	maxPayload := int(atomic.LoadUint32(&h.effectivePeerMaxFrameSize))

	h.writeMu.Lock()
	defer h.writeMu.Unlock()

	var sent int
	for sent < len(headerBlock) {
		chunk := headerBlock[sent:]
		if len(chunk) > maxPayload {
			chunk = chunk[:maxPayload]
		}
		sent += len(chunk)
		endHeaders := sent == len(headerBlock)
		var err error
		if sent == len(chunk) {
			err = h.framer.WriteHeaders(http2.HeadersFrameParam{StreamID: streamID, BlockFragment: chunk, EndStream: endStreamOnHeaders, EndHeaders: endHeaders})
		} else {
			err = h.framer.WriteContinuation(streamID, endHeaders, chunk)
		}
		if err != nil {
			return err
		}
	}

	if hasBody {
		body := req.Body
		if h.client.randomizer != nil {
			body = h.client.randomizer.Randomizer(body)
		}
		if err := h.framer.WriteData(streamID, expectResponse, body); err != nil {
			return err
		}
	}

	return h.bw.Flush()
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
			h.handleSettingsFrame(f)
		case *http2.PingFrame:
			h.handlePingFrame(f)
		case *http2.GoAwayFrame:
			h.handleGoAway(f)
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
	dataLen := f.Length

	h.streamMu.RLock()
	stream, ok := h.streams[f.StreamID]
	h.streamMu.RUnlock()

	h.writeMu.Lock()
	if !h.connClosed.Load() {
		if ok {
			h.framer.WriteWindowUpdate(f.StreamID, dataLen)
		}
		h.framer.WriteWindowUpdate(0, dataLen)
		h.bw.Flush()
	}
	h.writeMu.Unlock()

	if ok {
		stream.body.Write(f.Data())
		if f.StreamEnded() {
			h.finalizeStream(stream)
		}
	}
}

func (h *HttpSessionH2) handleSettingsFrame(f *http2.SettingsFrame) {
	if f.IsAck() {
		return
	}
	go func() {
		h.writeMu.Lock()
		defer h.writeMu.Unlock()
		if h.connClosed.Load() {
			return
		}
		for i := 0; i < f.NumSettings(); i++ {
			s := f.Setting(i)
			if s.ID == http2.SettingMaxFrameSize {
				atomic.StoreUint32(&h.effectivePeerMaxFrameSize, s.Val)
			}
		}
		h.framer.WriteSettingsAck()
		h.bw.Flush()
	}()
}

func (h *HttpSessionH2) handlePingFrame(f *http2.PingFrame) {
	if f.IsAck() {
		return
	}
	pingData := f.Data
	go func() {
		h.writeMu.Lock()
		defer h.writeMu.Unlock()
		if h.connClosed.Load() {
			return
		}
		h.framer.WritePing(true, pingData)
		h.bw.Flush()
	}()
}

func (h *HttpSessionH2) handleRSTStreamFrame(f *http2.RSTStreamFrame) {
	h.streamMu.Lock()
	defer h.streamMu.Unlock()
	if stream, ok := h.streams[f.StreamID]; ok {
		if !stream.streamEnded {
			close(stream.responseChan)
			close(stream.done)
		}
	}
}

func (h *HttpSessionH2) handleGoAway(f *http2.GoAwayFrame) {
	lastStreamID := f.LastStreamID
	h.streamMu.Lock()
	defer h.streamMu.Unlock()

	for id, stream := range h.streams {
		if id > lastStreamID {
			if !stream.streamEnded {
				close(stream.responseChan)
				close(stream.done)
			}
		}
	}
}

func (h *HttpSessionH2) finalizeStream(stream *h2Stream) {
	h.streamMu.Lock()
	if stream.streamEnded {
		h.streamMu.Unlock()
		return
	}
	stream.streamEnded = true
	responseChan := stream.responseChan
	doneChan := stream.done
	h.streamMu.Unlock()

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

	if responseChan == nil {
		bytebufferpool.Put(stream.body)
		return
	}

	responseChan <- resp
	if doneChan != nil {
		close(doneChan)
	}
}

func (h *HttpSessionH2) ResetStream(streamID uint32, errCode http2.ErrCode) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	h.framer.WriteRSTStream(streamID, errCode)
	return h.bw.Flush()
}

func (h *HttpSessionH2) WriteGoAway(maxStreamID uint32, code http2.ErrCode, debugData []byte) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	h.framer.WriteGoAway(maxStreamID, code, debugData)
	return h.bw.Flush()
}

func (h *HttpSessionH2) UpdateWindow(streamId uint32, windowId uint32) error {
	h.writeMu.Lock()
	defer h.writeMu.Unlock()
	h.framer.WriteWindowUpdate(streamId, windowId)
	return h.bw.Flush()
}
