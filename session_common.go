package swifthttp

import (
	"net"
	"net/http"
	"strconv"

	"github.com/SyNdicateFoundation/fastrand"
	"github.com/SyNdicateFoundation/legitagent"
)

type SessionCommon struct {
	client   *Client
	hostname string
	agent    *legitagent.Agent
	ipAddr   net.IP
}

func newSessionCommon(client *Client, hostname string, agent *legitagent.Agent) *SessionCommon {
	sc := &SessionCommon{
		client:   client,
		hostname: hostname,
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

func (s *SessionCommon) buildHeaders(req *HttpRequest, isHttp2 bool) http.Header {
	headers := make(http.Header)

	req.headerMx.RLock()
	for key, values := range req.Header {
		headers[key] = values
	}
	req.headerMx.RUnlock()

	if s.agent != nil && s.agent.Headers != nil {
		for key, values := range s.agent.Headers {
			if _, exists := headers[key]; !exists {
				headers[key] = values
			}
		}
	}

	method := string(req.Method)
	if method == "" {
		method = "GET"
	}

	path := req.RawPath
	if path == "" {
		path = "/"
	}

	if isHttp2 {
		if _, ok := headers[":method"]; !ok {
			headers.Set(":method", method)
		}
		if _, ok := headers[":scheme"]; !ok {
			headers.Set(":scheme", "https")
		}
		if _, ok := headers[":authority"]; !ok {
			headers.Set(":authority", s.hostname)
		}
		if _, ok := headers[":path"]; !ok {
			headers.Set(":path", path)
		}
	} else {
		if _, ok := headers["Host"]; !ok {
			headers.Set("Host", s.hostname)
		}
	}

	if req.Body != nil {
		if _, ok := headers["Content-Type"]; !ok && req.ContentType != "" {
			headers.Set("Content-Type", req.ContentType)
		}
		if _, ok := headers["Content-Length"]; !ok {
			headers.Set("Content-Length", strconv.Itoa(len(req.Body)))
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
		applyIpSpoof(headers, ip, s.hostname, "https", isHttp2)
	}

	return headers
}

func (s *SessionCommon) getHeaderOrder(headers http.Header) []string {
	if s.agent != nil && len(s.agent.HeaderOrder) > 0 {
		orderedKeys := make([]string, 0, len(headers))
		presentHeaders := make(map[string]bool)
		for key := range headers {
			presentHeaders[http.CanonicalHeaderKey(key)] = true
		}

		for _, key := range s.agent.HeaderOrder {
			if presentHeaders[http.CanonicalHeaderKey(key)] {
				orderedKeys = append(orderedKeys, key)
			}
		}
		return orderedKeys
	}

	keys := make([]string, 0, len(headers))
	for k := range headers {
		keys = append(keys, k)
	}

	if s.client.randomizeHeaderSort {
		fastrand.Shuffle(len(keys), func(i, j int) {
			keys[i], keys[j] = keys[j], keys[i]
		})
		return keys
	}
	return keys
}
