package swifthttp

import (
	"net/http"
	"reflect"
	"testing"
)

func TestNewRequest(t *testing.T) {
	req := NewRequest()
	if req == nil {
		t.Fatal("NewRequest returned nil")
	}
	if req.Method != RequestTypeGet {
		t.Errorf("Expected default method to be GET, got %s", req.Method)
	}
	if req.Header == nil {
		t.Errorf("Expected default Header to be non-nil, but got nil")
	}
	if len(req.Header) != 0 {
		t.Errorf("Expected default Header to be empty, but got %v", req.Header)
	}
}

func TestWithMethod(t *testing.T) {
	req := NewRequest(WithMethod(RequestTypePost))
	if req.Method != RequestTypePost {
		t.Errorf("Expected method POST, got %s", req.Method)
	}
}

func TestWithCustomMethod(t *testing.T) {
	customMethod := "CUSTOM"
	req := NewRequest(WithCustomMethod(customMethod))
	if string(req.Method) != customMethod {
		t.Errorf("Expected method %s, got %s", customMethod, req.Method)
	}
}

func TestWithBody(t *testing.T) {
	body := []byte("test body")
	contentType := "text/plain"
	req := NewRequest(WithBody(body, contentType))
	if !reflect.DeepEqual(req.Body, body) {
		t.Errorf("Expected body %s, got %s", body, req.Body)
	}
	if req.ContentType != contentType {
		t.Errorf("Expected contentType %s, got %s", contentType, req.ContentType)
	}
}

func TestWithHeaders(t *testing.T) {
	headers := make(http.Header)
	headers.Set("X-Test", "value")

	req := NewRequest(WithHeaders(headers))

	if req.Header.Get("X-Test") != "value" {
		t.Errorf("Expected header 'X-Test' to be 'value', got '%s'", req.Header.Get("X-Test"))
	}

	headers.Set("X-Another", "new_value")
	headers.Add("X-Test", "another_value")

	if req.Header.Get("X-Another") != "" {
		t.Errorf("Modification to original header map should not affect request's headers, but 'X-Another' was found with value '%s'", req.Header.Get("X-Another"))
	}
	if len(req.Header["X-Test"]) != 1 {
		t.Errorf("Expected request to have 1 value for X-Test, but it was modified externally. Got %d values.", len(req.Header["X-Test"]))
	}
}

func TestWithSetHeader(t *testing.T) {
	req := NewRequest(
		WithSetHeader("X-Test", "value1"),
		WithSetHeader("X-Test", "value2"),
	)
	if req.Header == nil {
		t.Fatal("Header is nil after WithSetHeader")
	}
	if val := req.Header.Get("X-Test"); val != "value2" {
		t.Errorf("Expected header X-Test to be 'value2', got '%s'", val)
	}
	if len(req.Header["X-Test"]) != 1 {
		t.Errorf("Expected 1 value for X-Test, got %d", len(req.Header["X-Test"]))
	}
}

func TestWithAddHeader(t *testing.T) {
	req := NewRequest(
		WithAddHeader("X-Test-Add", "value1"),
		WithAddHeader("X-Test-Add", "value2"),
	)
	if req.Header == nil {
		t.Fatal("Header is nil after WithAddHeader")
	}
	vals := req.Header["X-Test-Add"]
	expectedVals := []string{"value1", "value2"}
	if !reflect.DeepEqual(vals, expectedVals) {
		t.Errorf("Expected header X-Test-Add to be %v, got %v", expectedVals, vals)
	}
}

func TestWithContentType(t *testing.T) {
	contentType := "application/json"
	req := NewRequest(WithContentType(contentType))
	if req.ContentType != contentType {
		t.Errorf("Expected contentType %s, got %s", contentType, req.ContentType)
	}
}

func TestWithBoundary(t *testing.T) {
	boundary := "myboundary"
	expectedContentType := "multipart/form-data; boundary=" + boundary
	req := NewRequest(WithBoundary(boundary))
	if req.ContentType != expectedContentType {
		t.Errorf("Expected contentType %s, got %s", expectedContentType, req.ContentType)
	}
}

func TestWithCustomPath(t *testing.T) {
	path := "/custom/path"
	req := NewRequest(WithPath(path))
	if req.RawPath != path {
		t.Errorf("Expected RawPath %s, got %s", path, req.RawPath)
	}
}

func TestRequestOptionsChaining(t *testing.T) {
	body := []byte("data")
	req := NewRequest(
		WithMethod(RequestTypePut),
		WithBody(body, "app/data"),
		WithSetHeader("Authorization", "Bearer token"),
		WithPath("/api/v1/resource"),
		WithAddHeader("X-Multi", "v1"),
		WithAddHeader("X-Multi", "v2"),
	)

	if req.Method != RequestTypePut {
		t.Errorf("Chained: Expected method PUT, got %s", req.Method)
	}
	if !reflect.DeepEqual(req.Body, body) {
		t.Errorf("Chained: Expected body %s, got %s", body, req.Body)
	}
	if req.ContentType != "app/data" {
		t.Errorf("Chained: Expected contentType 'app/data', got %s", req.ContentType)
	}
	if req.Header == nil {
		t.Fatal("Chained: Header is nil")
	}
	if auth := req.Header.Get("Authorization"); auth != "Bearer token" {
		t.Errorf("Chained: Expected Authorization header 'Bearer token', got '%s'", auth)
	}
	expectedMulti := []string{"v1", "v2"}
	if !reflect.DeepEqual(req.Header["X-Multi"], expectedMulti) {
		t.Errorf("Chained: Expected X-Multi header %v, got %v", expectedMulti, req.Header["X-Multi"])
	}
	if req.RawPath != "/api/v1/resource" {
		t.Errorf("Chained: Expected RawPath '/api/v1/resource', got %s", req.RawPath)
	}
}
