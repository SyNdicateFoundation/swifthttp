package swifthttp

import (
	"github.com/SyNdicateFoundation/fastrand"
	"github.com/valyala/bytebufferpool"
	"golang.org/x/net/http2"
	"net/http"
	"sync"
	"time"

	"github.com/SyNdicateFoundation/legitagent"
	"github.com/SyNdicateFoundation/singproxy"
	utls "github.com/refraction-networking/utls"
)

var defaultTimeout = HttpTimeout{
	Dial:    time.Second * 5,
	Request: time.Second * 10,
}

func NewHttpClient(options ...OptionFunc) *Client {
	hc := &Client{
		timeout:     defaultTimeout,
		httpVersion: HttpVersion1_1,
		tls: &HttpTLSConfig{
			TLSMode: HttpTlsModeAutoTLS,
		},
		h2StreamPool: sync.Pool{
			New: func() interface{} {
				return &h2Stream{
					header: make(http.Header),
					body:   bytebufferpool.Get(),
				}
			},
		},
		hpackEncoderBufPool: sync.Pool{
			New: func() interface{} {
				return new(bytebufferpool.ByteBuffer)
			},
		},
	}
	for _, option := range options {
		option(hc)
	}
	return hc
}

func WithTimeout(timeout HttpTimeout) OptionFunc {
	return func(hc *Client) {
		hc.timeout = timeout
	}
}

func WithDialTimeout(timeout time.Duration) OptionFunc {
	return func(hc *Client) {
		hc.timeout.Dial = timeout
	}
}

func WithRequestTimeout(timeout time.Duration) OptionFunc {
	return func(hc *Client) {
		hc.timeout.Request = timeout
	}
}

func WithAgentGenerator(gen *legitagent.Generator) OptionFunc {
	return func(hc *Client) {
		hc.legitAgentGenerator = gen
	}
}

func WithIpSpoofer(perSession bool, useIpv6 bool) OptionFunc {
	return func(hc *Client) {
		if hc.ipSpoofing == nil {
			hc.ipSpoofing = new(ipSpoofConfig)
		}
		hc.ipSpoofing.enabled = true
		hc.ipSpoofing.perSessionIp = perSession
		hc.ipSpoofing.useIpv6 = useIpv6
	}
}

func WithProxy(proxy singproxy.Proxy) OptionFunc {
	return func(hc *Client) {
		if proxy == nil {
			panic("WithProxy: proxy cannot be nil")
		}
		hc.proxy = proxy
	}
}

func WithCustomTLSConfig(config *HttpTLSConfig) OptionFunc {
	return func(hc *Client) {
		if config == nil {
			panic("WithCustomTLSConfig: tls config cannot be nil")
		}
		hc.tls = config
	}
}

func WithTLS(tlsMode HttpTlsMode) OptionFunc {
	return func(hc *Client) {
		if hc.tls == nil {
			hc.tls = new(HttpTLSConfig)
		}
		hc.tls.TLSMode = tlsMode
	}
}

func WithTLSCustomConfig(config *utls.Config) OptionFunc {
	return func(hc *Client) {
		if config == nil {
			panic("WithTLSCustomConfig: utls.Config cannot be nil")
		}
		if hc.tls == nil {
			hc.tls = new(HttpTLSConfig)
		}
		hc.tls.UTLSConfig = config
	}
}

func WithOptimizedTLS(optimized bool) OptionFunc {
	return func(hc *Client) {
		if hc.tls == nil {
			hc.tls = new(HttpTLSConfig)
		}
		hc.tls.OptimizedConn = optimized
	}
}

func WithVersion(httpVersion HttpVersion) OptionFunc {
	return func(hc *Client) {
		hc.httpVersion = httpVersion
		if hc.httpVersion == HttpVersion3_0 || hc.httpVersion == HttpVersionSPDY31 {
			if hc.tls == nil {
				hc.tls = new(HttpTLSConfig)
			}
			hc.tls.TLSMode = HttpTlsModeForever
		}
	}
}

func WithRandomizer(randomizer fastrand.Engine) OptionFunc {
	return func(hc *Client) {
		hc.randomizer = randomizer
	}
}

func WithRandomizedHeaderSort(randomize bool) OptionFunc {
	return func(hc *Client) {
		hc.randomizeHeaderSort = randomize
	}
}

func WithEnableReader(enable bool) OptionFunc {
	return func(hc *Client) {
		hc.enableReaderLoop = enable
	}
}

func WithCustomH2Settings(settings []http2.Setting) OptionFunc {
	return func(client *Client) {
		client.customH2Settings = settings
	}
}

func WithoutPooling() OptionFunc {
	return func(hc *Client) {
		hc.h2StreamPool = sync.Pool{
			New: func() any {
				return &h2Stream{
					header: make(http.Header),
					body:   bytebufferpool.Get(),
				}
			},
		}
		hc.hpackEncoderBufPool = sync.Pool{
			New: func() any { return new(bytebufferpool.ByteBuffer) },
		}
	}
}
