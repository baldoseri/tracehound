package main

import "testing"

// TestListenScope covers the distinction browseURL cannot make. browseURL
// rewrites a wildcard bind to localhost so the operator has something to click,
// which previously left the startup banner saying the dashboard was on loopback
// when it was on every interface.
func TestListenScope(t *testing.T) {
	tests := []struct {
		addr        string
		wantDesc    string
		wantExposed bool
	}{
		{":8080", "all interfaces", true},
		{"0.0.0.0:8080", "all interfaces", true},
		{"[::]:8080", "all interfaces", true},

		{"127.0.0.1:8080", "loopback only", false},
		{"[::1]:8080", "loopback only", false},
		{"127.0.0.53:8080", "loopback only", false},

		{"10.0.0.5:8080", "10.0.0.5", true},
		{"192.168.1.10:9090", "192.168.1.10", true},

		// A hostname is not resolved during startup, so it is assumed to be
		// reachable rather than quietly treated as safe.
		{"sensor.internal:8080", "sensor.internal", true},

		// Unparseable input must not be reported as safe.
		{"garbage", "unknown interface", true},
	}
	for _, tc := range tests {
		desc, exposed := listenScope(tc.addr)
		if desc != tc.wantDesc || exposed != tc.wantExposed {
			t.Errorf("listenScope(%q) = (%q, %v), want (%q, %v)",
				tc.addr, desc, exposed, tc.wantDesc, tc.wantExposed)
		}
	}
}

// TestBrowseURLStaysClickable pins the behaviour listenScope exists to
// compensate for, so a later reader does not "fix" it and break the link.
func TestBrowseURLStaysClickable(t *testing.T) {
	for addr, want := range map[string]string{
		":8080":          "http://localhost:8080",
		"0.0.0.0:8080":   "http://localhost:8080",
		"127.0.0.1:8080": "http://127.0.0.1:8080",
		"10.0.0.5:9090":  "http://10.0.0.5:9090",
	} {
		if got := browseURL(addr); got != want {
			t.Errorf("browseURL(%q) = %q, want %q", addr, got, want)
		}
	}
}
