package swifthttp

import (
	"github.com/SyNdicateFoundation/fastrand"
	"reflect"
	"testing"
	"time"

	"github.com/SyNdicateFoundation/legitagent"
	"github.com/SyNdicateFoundation/singproxy"
	utls "github.com/refraction-networking/utls"
)

func TestNewHttpClient_DefaultOptions(t *testing.T) {
	client := NewHttpClient()
	if client == nil {
		t.Fatal("NewHttpClient returned nil")
	}

	expectedTimeout := HttpTimeout{
		Dial:    time.Second * 5,
		Request: time.Second * 10,
	}
	if !reflect.DeepEqual(client.timeout, expectedTimeout) {
		t.Errorf("Default timeout mismatch. Got %+v, want %+v", client.timeout, expectedTimeout)
	}

	if client.httpVersion != HttpVersion1_1 {
		t.Errorf("Default httpVersion mismatch. Got %s, want %s", client.httpVersion, HttpVersion1_1)
	}

	if client.proxy != nil {
		t.Errorf("Default proxy should be nil, got %+v", client.proxy)
	}
	if client.legitAgentGenerator != nil {
		t.Error("Default legitAgentGenerator should be nil")
	}
	if client.ipSpoofing != nil {
		t.Error("Default ipSpoofing should be nil")
	}
	if client.tls == nil {
		t.Error("Default tls should not be nil")
	}
	if client.randomizer != nil {
		t.Errorf("Default randomizer should be false, got %v", client.randomizer)
	}
	if client.enableReaderLoop != false {
		t.Errorf("Default enableCache should be false, got %v", client.enableReaderLoop)
	}
}

func TestWithTimeout(t *testing.T) {
	timeout := HttpTimeout{Dial: 3 * time.Second, Request: 6 * time.Second}
	client := NewHttpClient(WithTimeout(timeout))
	if !reflect.DeepEqual(client.timeout, timeout) {
		t.Errorf("WithTimeout mismatch. Got %+v, want %+v", client.timeout, timeout)
	}
}

func TestWithIpSpoofer(t *testing.T) {
	client := NewHttpClient(WithIpSpoofer(true, true))
	if client.ipSpoofing == nil {
		t.Fatal("ipSpoofing is nil after WithIpSpoofer")
	}
	if !client.ipSpoofing.enabled {
		t.Error("Expected enabled to be true")
	}
	if !client.ipSpoofing.perSessionIp {
		t.Error("Expected perSessionIp to be true")
	}
	if !client.ipSpoofing.useIpv6 {
		t.Error("Expected useIpv6 to be true")
	}
}

func TestWithAgentGenerator(t *testing.T) {
	gen := legitagent.NewGenerator()

	client := NewHttpClient(WithAgentGenerator(gen))
	if client.legitAgentGenerator == nil {
		t.Fatal("legitAgentGenerator is nil after WithAgentGenerator")
	}
}

func TestWithProxy(t *testing.T) {
	proxy := singproxy.Direct
	client := NewHttpClient(WithProxy(proxy))
	if client.proxy == nil {
		t.Fatal("proxy is nil after WithProxy")
	}
}

func TestWithCustomTLSConfig(t *testing.T) {
	tlsConfig := &HttpTLSConfig{TLSMode: HttpTlsModeForever, OptimizedConn: true}
	client := NewHttpClient(WithCustomTLSConfig(tlsConfig))
	if !reflect.DeepEqual(client.tls, tlsConfig) {
		t.Errorf("WithCustomTLSConfig mismatch. Got %+v, want %+v", client.tls, tlsConfig)
	}
}

func TestWithTLSCustomConfig(t *testing.T) {
	utlsConf := &utls.Config{ServerName: "example.com"}
	client := NewHttpClient(WithTLSCustomConfig(utlsConf))

	if client.tls == nil || !reflect.DeepEqual(client.tls.UTLSConfig, utlsConf) {
		t.Errorf("WithTLSCustomConfig (utls) incorrect: tls=%+v, want UTLSConfig=%+v", client.tls, utlsConf)
	}
}

func TestWithRandomizer(t *testing.T) {
	client := NewHttpClient(WithRandomizer(fastrand.NewEngine()))
	if client.randomizer == nil {
		t.Error("Expected randomizer to be true")
	}
}

func TestWithVersion(t *testing.T) {
	client := NewHttpClient(WithVersion(HttpVersion2_0))
	if client.httpVersion != HttpVersion2_0 {
		t.Errorf("httpVersion mismatch. Got %s, want %s", client.httpVersion, HttpVersion2_0)
	}
}
