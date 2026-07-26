package pipeline_test

import (
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/pipeline"
)

// TestFingerprintingSurvivesConstantEviction runs the whole sensor with both
// bounds set absurdly low, so the flow table evicts on nearly every packet and
// the reassemblers sit at capacity throughout.
//
// It is worth being precise about what this does and does not show. It does not
// reproduce the eviction leak: the demo capture's hellos arrive complete in one
// segment, so they are parsed and dropped on the first feed and never become
// pending, and a leak needs a handshake that is started and abandoned. The
// tests that do reproduce it are TestEvictedFlowReleasesHandshakeState, which
// drives the condition directly, and TestReassemblerAtCapacityStillFingerprints.
//
// What this covers is the integration: the eviction callback runs on the packet
// path, under the flow table's lock discipline, without deadlocking or losing
// detections. That is worth a test of its own, because the callback is invoked
// from inside Observe and calls into three other locks.
func TestFingerprintingSurvivesConstantEviction(t *testing.T) {
	_, alerts, stats := replayDemoOpts(t, pipeline.Options{
		TickInterval:         30 * time.Second,
		FlowIdleTimeout:      2 * time.Minute,
		MaxFlows:             8,
		MaxPendingHandshakes: 4,
	})

	if stats.Fingerprints == 0 {
		t.Fatal("no client fingerprints survived constant eviction")
	}
	if len(alerts) == 0 {
		t.Error("no alerts at all under eviction pressure")
	}
	t.Logf("%d client and %d server fingerprints, %d alerts, with MaxFlows=8 and MaxPendingHandshakes=4",
		stats.Fingerprints, stats.ServerFingerprints, len(alerts))
}
