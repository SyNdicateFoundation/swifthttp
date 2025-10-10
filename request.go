package swifthttp

import (
	"net/http"
	"net/http/cookiejar"
)

func NewRequest(opts ...RequestOpt) *HttpRequest {
	rq := &HttpRequest{
		Method: RequestTypeGet,
		Header: make(http.Header),
	}

	for _, opt := range opts {
		opt(rq)
	}

	return rq
}

func WithMethod(method RequestType) RequestOpt {
	return func(req *HttpRequest) {
		req.Method = method
	}
}

func WithCustomMethod(method string) RequestOpt {
	return func(req *HttpRequest) {
		req.Method = RequestType(method)
	}
}

func WithBody(body []byte, contentType string) RequestOpt {
	return func(req *HttpRequest) {
		req.Body = body
		req.ContentType = contentType
	}
}

func WithHeaders(headers http.Header) RequestOpt {
	return func(req *HttpRequest) {
		req.headerMx.Lock()
		defer req.headerMx.Unlock()

		req.Header = make(http.Header, len(headers))
		for k, v := range headers {
			newV := make([]string, len(v))
			copy(newV, v)
			req.Header[k] = newV
		}
	}
}

func WithSetHeader(header, value string) RequestOpt {
	return func(req *HttpRequest) {
		req.headerMx.Lock()
		defer req.headerMx.Unlock()

		if req.Header == nil {
			req.Header = make(http.Header)
		}

		req.Header.Set(header, value)
	}
}

func WithAddHeader(header, value string) RequestOpt {
	return func(req *HttpRequest) {
		req.headerMx.Lock()
		defer req.headerMx.Unlock()

		if req.Header == nil {
			req.Header = make(http.Header)
		}

		req.Header.Add(header, value)
	}
}

func WithContentType(contentType string) RequestOpt {
	return func(req *HttpRequest) {
		req.ContentType = contentType
	}
}

func WithBoundary(value string) RequestOpt {
	return func(req *HttpRequest) {
		req.ContentType = "multipart/form-data; boundary=" + value
	}
}

func WithPath(s string) RequestOpt {
	return func(req *HttpRequest) {
		req.RawPath = s
	}
}

func WithCookieJar(jar *cookiejar.Jar) RequestOpt {
	return func(req *HttpRequest) {
		req.CookieJar = jar
	}
}
