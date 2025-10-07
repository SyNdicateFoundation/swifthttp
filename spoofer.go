package swifthttp

import (
	"crypto/rand"
	"fmt"
	"net"
	"net/http"
	"strings"
)

func applyIpSpoof(headers http.Header, addr net.IP, host string, scheme string, http2 bool) {
	ipStr := addr.String()
	viaEntry := fmt.Sprintf("1.1 %s", host)
	forwardedValue := fmt.Sprintf("for=%s;host=%s;proto=%s", ipStr, host, scheme)

	rayBytes := make([]byte, 8)
	rand.Read(rayBytes)
	cfRay := fmt.Sprintf("%x-XXX", rayBytes)

	headerValues := map[string]string{
		"X-Forwarded-For":          ipStr,
		"X-Forwarded-Host":         host,
		"X-Forwarded-Proto":        scheme,
		"X-Real-IP":                ipStr,
		"CF-Connecting-IP":         ipStr,
		"CF-IPCountry":             "XX",
		"CF-RAY":                   cfRay,
		"True-Client-IP":           ipStr,
		"X-Client-IP":              ipStr,
		"Via":                      viaEntry,
		"X-Via":                    viaEntry,
		"Forwarded":                forwardedValue,
		"X-Original-Forwarded-For": ipStr,
		"X-Coming-From":            ipStr,
		"X-Cluster-Client-IP":      ipStr,
		"Proxy-Client-IP":          ipStr,
		"WL-Proxy-Client-IP":       ipStr,
	}

	for key, value := range headerValues {
		if headers.Get(key) == "" {
			finalKey := key
			if http2 {
				finalKey = strings.ToLower(key)
			}
			headers.Set(finalKey, value)
		}
	}
}
