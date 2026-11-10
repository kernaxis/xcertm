package config

import (
	"context"
	"net"
	"sync/atomic"
)

func newResolver(addresses []string) *net.Resolver {
	var next atomic.Uint64
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		address := addresses[(next.Add(1)-1)%uint64(len(addresses))]
		return (&net.Dialer{}).DialContext(ctx, network, address)
	}}
}
