package swifthttp

import (
	"github.com/SyNdicateFoundation/fastrand"
	"github.com/SyNdicateFoundation/legitagent"
	"github.com/valyala/bytebufferpool"
	"io"
	"net"
	"net/http"
	"strings"
)

type byteBufferPoolCloser struct {
	reader io.Reader
	buffer *bytebufferpool.ByteBuffer
}

func (b *byteBufferPoolCloser) Read(p []byte) (n int, err error) {
	if b.reader == nil {
		return 0, io.EOF
	}
	return b.reader.Read(p)
}
func (b *byteBufferPoolCloser) Close() error {
	if b.buffer != nil {
		bytebufferpool.Put(b.buffer)
		b.buffer = nil
		b.reader = nil
	}
	return nil
}

type SessionCommon struct {
	client   *Client
	hostname string
	host     string
	agent    *legitagent.Agent
	ipAddr   net.IP
}

func newSessionCommon(client *Client, hostname, host string, agent *legitagent.Agent) *SessionCommon {
	sc := &SessionCommon{
		client:   client,
		hostname: hostname,
		host:     host,
		agent:    agent,
	}

	if client.ipSpoofing != nil && client.ipSpoofing.enabled && client.ipSpoofing.perSessionIp {
		if client.ipSpoofing.useIpv6 {
			sc.ipAddr = fastrand.IPv6()
		} else {
			sc.ipAddr = fastrand.IPv4()
		}
	}

	return sc
}
func (s *SessionCommon) prepareHeaderOrder(headers http.Header) []string {
	lengthHeaders := len(headers)

	if s.client.randomizeHeaderSort {
		headerOrder := make([]string, 0, lengthHeaders)
		for k := range headers {
			headerOrder = append(headerOrder, k)
		}

		fastrand.Shuffle(lengthHeaders, func(a, b int) {
			headerOrder[a], headerOrder[b] = headerOrder[b], headerOrder[a]
		})

		return headerOrder
	}

	est := lengthHeaders
	if s.agent != nil {
		est += len(s.agent.HeaderOrder)
	}

	headerOrder := make([]string, 0, est)
	seen := make(map[string]struct{}, est)

	if s.agent != nil {
		for _, k := range s.agent.HeaderOrder {
			lower := strings.ToLower(k)
			if _, ok := headers[lower]; ok {
				headerOrder = append(headerOrder, k)
				seen[lower] = struct{}{}
			}
		}
	}

	for k := range headers {
		lower := strings.ToLower(k)
		if _, ok := seen[lower]; !ok {
			headerOrder = append(headerOrder, k)
		}
	}

	return headerOrder
}

func (s *SessionCommon) prepareHeaders(req *HttpRequest, isHttp2 bool) http.Header {
	finalHeaders := make(http.Header)

	req.headerMx.RLock()
	for key, values := range req.Header {
		finalHeaders[key] = values
	}
	req.headerMx.RUnlock()

	if s.agent != nil {
		if s.agent.Headers != nil {
			for key, values := range s.agent.Headers {
				if _, exists := finalHeaders[key]; !exists {
					finalHeaders[key] = values
				} else {
					finalHeaders[key] = append(finalHeaders[key], values...)
				}
			}
		}

		if s.agent.UserAgent != "" {
			if finalHeaders.Get("User-Agent") == "" {
				finalHeaders.Set("User-Agent", s.agent.UserAgent)
			}
		}
	}

	method := string(req.Method)
	if method == "" {
		method = http.MethodGet
	}

	uri := req.RawPath
	if uri == "" {
		uri = "/"
	}

	if s.client.randomizer != nil {
		uri = s.client.randomizer.RandomizerString(uri)
	}

	if isHttp2 {
		if finalHeaders.Get(":method") == "" {
			finalHeaders.Set(":method", method)
		}
		if finalHeaders.Get(":scheme") == "" {
			finalHeaders.Set(":scheme", "https")
		}
		if finalHeaders.Get(":authority") == "" {
			finalHeaders.Set(":authority", s.host)
		}
		if finalHeaders.Get(":path") == "" {
			finalHeaders.Set(":path", uri)
		}

		if finalHeaders.Get("Connection") == "" {
			finalHeaders.Del("Connection")
		}

	} else {
		if finalHeaders.Get("Host") == "" {
			finalHeaders.Set("Host", s.host)
		}
	}

	if len(req.Body) > 0 {
		if finalHeaders.Get("Content-Type") == "" && req.ContentType != "" {
			finalHeaders.Set("Content-Type", req.ContentType)
		}
	}

	if s.client.ipSpoofing != nil && s.client.ipSpoofing.enabled {
		ip := s.ipAddr
		if ip == nil {
			if s.client.ipSpoofing.useIpv6 {
				ip = fastrand.IPv6()
			} else {
				ip = fastrand.IPv4()
			}
		}
		applyIpSpoof(finalHeaders, ip, s.hostname, "https", isHttp2)
	}
	return finalHeaders
}
