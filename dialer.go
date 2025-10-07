package swifthttp

import (
	"context"
	"fmt"
	"net"
)

func (hc *Client) dial(ctx context.Context, addr *net.TCPAddr) (net.Conn, error) {
	if hc.timeout.Dial > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, hc.timeout.Dial)
		defer cancel()
	}

	network := "tcp"
	if hc.httpVersion == HttpVersion3_0 {
		network = "udp"
	}

	if hc.proxy != nil {
		conn, err := hc.proxy.DialContext(ctx, network, addr)
		if err != nil {
			return nil, fmt.Errorf("dial via proxy failed: %v", err)
		}
		return conn, nil
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, network, addr.String())
	if err != nil {
		return nil, fmt.Errorf("direct %s dial failed: %w", network, err)
	}
	return conn, nil
}
