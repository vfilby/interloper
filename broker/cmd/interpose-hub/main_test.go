package main

import "testing"

func TestCheckTransport(t *testing.T) {
	for _, tc := range []struct {
		name string
		c    config
		ok   bool
	}{
		{"defaults", config{apiAddr: "127.0.0.1:8740", hubURL: "http://127.0.0.1:8740"}, true},
		{"loopback v6", config{apiAddr: "[::1]:8740", hubURL: "http://[::1]:8740"}, true},
		{"all interfaces, https behind a proxy", config{apiAddr: ":8740", hubURL: "https://hub.home.example"}, true},
		{"container, https behind a proxy", config{apiAddr: "0.0.0.0:8740", hubURL: "https://hub.home.example"}, true},
		{"all interfaces over http", config{apiAddr: ":8740", hubURL: "http://hub.home.example:8740"}, false},
		{"LAN address over http", config{apiAddr: "192.168.1.5:8740", hubURL: "http://192.168.1.5:8740"}, false},
		{"localhost name is not an address", config{apiAddr: "localhost:8740", hubURL: "http://localhost:8740"}, false},
		{"url without scheme", config{apiAddr: "127.0.0.1:8740", hubURL: "hub.home.example"}, false},
		{"https redirect", config{apiAddr: "127.0.0.1:8740", hubURL: "http://127.0.0.1:8740",
			redirect: "https://interpose-hub.home.example/oidc/callback"}, true},
		{"http redirect on loopback", config{apiAddr: "127.0.0.1:8740", hubURL: "http://127.0.0.1:8740",
			redirect: "http://localhost:8741/oidc/callback"}, true},
		{"http redirect off loopback", config{apiAddr: "127.0.0.1:8740", hubURL: "http://127.0.0.1:8740",
			redirect: "http://interpose-hub.home.example/oidc/callback"}, false},
		{"relative redirect", config{apiAddr: "127.0.0.1:8740", hubURL: "http://127.0.0.1:8740",
			redirect: "/oidc/callback"}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkTransport(tc.c); (err == nil) != tc.ok {
				t.Fatalf("checkTransport(%+v) = %v, want ok=%v", tc.c, err, tc.ok)
			}
		})
	}
}
