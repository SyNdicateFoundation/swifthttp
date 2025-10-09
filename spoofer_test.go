package swifthttp

import (
	"fmt"
	"net"
	"net/http"
	"regexp"
	"testing"
)

const cfRayPatternMarker = "MATCH_CF_RAY_PATTERN"

var cfRayRegex = regexp.MustCompile(`^[a-f0-9]{16}-XXX$`)

func TestApplyIpSpoof(t *testing.T) {
	host := "example.com"
	scheme := "https"

	tests := []struct {
		name         string
		addr         net.IP
		http2        bool
		initialHdrs  http.Header
		expectedHdrs map[string]string
	}{
		{
			name:        "IPv4, HTTP/1.1",
			addr:        net.ParseIP("1.2.3.4"),
			http2:       false,
			initialHdrs: http.Header{},
			expectedHdrs: map[string]string{
				"X-Forwarded-For":          "1.2.3.4",
				"X-Forwarded-Host":         host,
				"X-Forwarded-Proto":        scheme,
				"X-Real-IP":                "1.2.3.4",
				"CF-Connecting-IP":         "1.2.3.4",
				"CF-IPCountry":             "XX",
				"CF-RAY":                   cfRayPatternMarker,
				"True-Client-IP":           "1.2.3.4",
				"X-Client-IP":              "1.2.3.4",
				"Via":                      fmt.Sprintf("1.1 %s", host),
				"X-Via":                    fmt.Sprintf("1.1 %s", host),
				"Forwarded":                fmt.Sprintf("for=%s;host=%s;proto=%s", "1.2.3.4", host, scheme),
				"X-Original-Forwarded-For": "1.2.3.4",
				"X-Coming-From":            "1.2.3.4",
				"X-Cluster-Client-IP":      "1.2.3.4",
				"Proxy-Client-IP":          "1.2.3.4",
				"WL-Proxy-Client-IP":       "1.2.3.4",
			},
		},
		{
			name:        "IPv6, HTTP/2",
			addr:        net.ParseIP("2001:db8::1"),
			http2:       true,
			initialHdrs: http.Header{},
			expectedHdrs: map[string]string{
				"x-forwarded-for":          "2001:db8::1",
				"x-forwarded-host":         host,
				"x-forwarded-proto":        scheme,
				"x-real-ip":                "2001:db8::1",
				"cf-connecting-ip":         "2001:db8::1",
				"cf-ipcountry":             "XX",
				"cf-ray":                   cfRayPatternMarker,
				"true-client-ip":           "2001:db8::1",
				"x-client-ip":              "2001:db8::1",
				"via":                      fmt.Sprintf("1.1 %s", host),
				"x-via":                    fmt.Sprintf("1.1 %s", host),
				"forwarded":                fmt.Sprintf("for=%s;host=%s;proto=%s", "2001:db8::1", host, scheme),
				"x-original-forwarded-for": "2001:db8::1",
				"x-coming-from":            "2001:db8::1",
				"x-cluster-client-ip":      "2001:db8::1",
				"proxy-client-ip":          "2001:db8::1",
				"wl-proxy-client-ip":       "2001:db8::1",
			},
		},
		{
			name:  "IPv4, HTTP/1.1, X-Forwarded-For pre-exists",
			addr:  net.ParseIP("5.6.7.8"),
			http2: false,
			initialHdrs: http.Header{
				"X-Forwarded-For": {"original-ip, 10.0.0.1"},
				"Via":             {"original-via-proxy"},
			},
			expectedHdrs: map[string]string{
				"X-Forwarded-For":   "original-ip, 10.0.0.1",
				"X-Forwarded-Host":  host,
				"X-Forwarded-Proto": scheme,
				"X-Real-IP":         "5.6.7.8",
				"CF-Connecting-IP":  "5.6.7.8",
				"CF-IPCountry":      "XX",
				"CF-RAY":            cfRayPatternMarker,
				"Via":               "original-via-proxy",
				"X-Via":             fmt.Sprintf("1.1 %s", host),
			},
		},
		{
			name:  "IPv4, HTTP/2, x-forwarded-for pre-exists (lowercase in initialHdrs)",
			addr:  net.ParseIP("5.6.7.8"),
			http2: true,
			initialHdrs: http.Header{
				"x-forwarded-for": {"original-ip, 10.0.0.1"},
			},
			expectedHdrs: map[string]string{
				"x-forwarded-for":   "original-ip, 10.0.0.1",
				"x-real-ip":         "5.6.7.8",
				"cf-connecting-ip":  "5.6.7.8",
				"cf-ipcountry":      "XX",
				"cf-ray":            cfRayPatternMarker,
				"x-forwarded-host":  host,
				"x-forwarded-proto": scheme,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			headers := make(http.Header)
			for k, v := range tt.initialHdrs {
				for _, val := range v {
					headers.Add(k, val)
				}
			}

			applyIpSpoof(headers, tt.addr, host, scheme, tt.http2)

			allExpectedKeysFound := true
			for keyFromExpected, expectedPatternOrValue := range tt.expectedHdrs {
				actualValue := headers.Get(keyFromExpected)

				if actualValue == "" && expectedPatternOrValue != "" && expectedPatternOrValue != cfRayPatternMarker {
					t.Errorf("Header %s: expected '%s', but was empty or not found", keyFromExpected, expectedPatternOrValue)
					allExpectedKeysFound = false
					continue
				}

				isCfRayKey := keyFromExpected == "CF-RAY" || keyFromExpected == "cf-ray"

				if isCfRayKey && expectedPatternOrValue == cfRayPatternMarker {
					if actualValue == "" {
						t.Errorf("Header %s: expected to match pattern '%s', but was empty", keyFromExpected, cfRayRegex.String())
						allExpectedKeysFound = false
					} else if !cfRayRegex.MatchString(actualValue) {
						t.Errorf("Header %s: expected to match pattern '%s', got '%s'", keyFromExpected, cfRayRegex.String(), actualValue)
						allExpectedKeysFound = false
					}
				} else {
					if actualValue != expectedPatternOrValue {
						t.Errorf("Header %s: expected '%s', got '%s'", keyFromExpected, expectedPatternOrValue, actualValue)
						allExpectedKeysFound = false
					}
				}
			}
			if !allExpectedKeysFound {
				t.Logf("Resulting headers for test '%s': %v", tt.name, headers)
			}
		})
	}
}
