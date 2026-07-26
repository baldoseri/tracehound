package api

import (
	"net/http/httptest"
	"testing"
)

// TestIntParamClamps is a white-box test because the damage is done before any
// response is produced, so it cannot be observed from outside.
//
// Table.Snapshot narrows only when limit < len(flows), so an oversized limit
// used to mean no limit: the handler copied the entire flow table while holding
// the read lock that Observe needs to take for writing on every packet. The
// cost of that request is chosen by whoever sends it.
func TestIntParamClamps(t *testing.T) {
	tests := []struct {
		query string
		def   int
		want  int
	}{
		// Absent or unusable falls back to the default.
		{"", 200, 200},
		{"?limit=", 200, 200},
		{"?limit=abc", 200, 200},
		{"?limit=0", 200, 200},
		{"?limit=-5", 200, 200},

		// Ordinary values pass through untouched.
		{"?limit=1", 200, 1},
		{"?limit=200", 200, 200},
		{"?limit=4999", 200, 4999},

		// At and above the cap, the cap wins.
		{"?limit=5000", 200, maxLimit},
		{"?limit=5001", 200, maxLimit},
		{"?limit=99999999", 200, maxLimit},
		{"?limit=2147483647", 200, maxLimit},
	}
	for _, tc := range tests {
		r := httptest.NewRequest("GET", "/api/flows"+tc.query, nil)
		if got := intParam(r, "limit", tc.def); got != tc.want {
			t.Errorf("intParam(%q) = %d, want %d", tc.query, got, tc.want)
		}
	}
}
