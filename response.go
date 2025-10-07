package swifthttp

import (
	"io"
	"net/http"
)

type HttpResponse struct {
	Status           string
	StatusCode       int
	Header           http.Header
	Body             io.ReadCloser
	ContentLength    int64
	TransferEncoding []string
	Close            bool
	Uncompressed     bool
}
