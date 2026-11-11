package main

import (
	"context"
	"net"
	"os"
	"runtime"
	"sync/atomic"
)

// No Android não existe /etc/resolv.conf (o DNS é do daemon netd) e o
// resolvedor puro do Go cairia em localhost:53. Nesse caso as consultas vão
// direto para resolvedores públicos, alternando entre eles a cada tentativa.
func init() {
	if runtime.GOOS == "windows" {
		return
	}
	if _, err := os.Stat("/etc/resolv.conf"); err == nil {
		return
	}

	servers := [...]string{"1.1.1.1:53", "8.8.8.8:53"}
	var attempt atomic.Uint32

	net.DefaultResolver = &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			var d net.Dialer
			next := servers[int(attempt.Add(1)-1)%len(servers)]
			return d.DialContext(ctx, network, next)
		},
	}
}
