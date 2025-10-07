package swifthttp

import (
	"github.com/SyNdicateFoundation/legitagent"
	"net/http"
	"net/http/cookiejar"
	"sync"
	"time"

	"github.com/SyNdicateFoundation/signproxy"
	utls "github.com/refraction-networking/utls"
)

type HttpVersion string

const (
	HttpVersion1_1    HttpVersion = "HTTP/1.1"
	HttpVersion2_0    HttpVersion = "HTTP/2.0"
	HttpVersion3_0    HttpVersion = "HTTP/3.0"
	HttpVersionSPDY31 HttpVersion = "SPDY/3.1"
)

type HttpTlsMode uint8

const (
	HttpTlsModeAutoTLS HttpTlsMode = iota
	HttpTlsModeForever
)

type RequestType string

const (
	RequestTypeGet     RequestType = "GET"
	RequestTypePost    RequestType = "POST"
	RequestTypePut     RequestType = "PUT"
	RequestTypeDelete  RequestType = "DELETE"
	RequestTypeHead    RequestType = "HEAD"
	RequestTypePatch   RequestType = "PATCH"
	RequestTypeOptions RequestType = "OPTIONS"
	RequestTypeTrace   RequestType = "TRACE"
	RequestTypeConnect RequestType = "CONNECT"
)

type ipSpoofConfig struct {
	enabled      bool
	perSessionIp bool
	useIpv6      bool
}

type HttpTimeout struct {
	Dial, Request time.Duration
}

type HttpTLSConfig struct {
	UTLSConfig    *utls.Config
	TLSMode       HttpTlsMode
	OptimizedConn bool
}

type Client struct {
	timeout             HttpTimeout
	proxy               signproxy.Proxy
	ipSpoofing          *ipSpoofConfig
	tls                 *HttpTLSConfig
	httpVersion         HttpVersion
	legitAgentGenerator *legitagent.Generator
	randomizer          bool
	randomizeHeaderSort bool
	enableCache         bool
}

type HttpRequest struct {
	Method      RequestType
	Header      http.Header
	Body        []byte
	ContentType string
	RawPath     string
	headerMx    sync.RWMutex
	CookieJar   *cookiejar.Jar
}

type OptionFunc func(*Client)
type RequestOpt func(*HttpRequest)
