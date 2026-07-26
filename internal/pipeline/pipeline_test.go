package pipeline_test

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/capture"
	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/model"
	"github.com/baldoseri/tracehound/internal/pcapgen"
	"github.com/baldoseri/tracehound/internal/pipeline"
)

// captureStart is fixed so the generated file — and therefore every assertion
// below — is byte-for-byte reproducible on any machine.
var captureStart = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

// replayDemo generates the scenario capture and runs it through a full
// pipeline, returning the ground truth alongside what was actually detected.
func replayDemo(t *testing.T) (pcapgen.Summary, []model.Alert, pipeline.Stats) {
	t.Helper()
	return replayDemoOpts(t, pipeline.Options{
		TickInterval:    30 * time.Second,
		FlowIdleTimeout: 2 * time.Minute,
	})
}

// replayDemoOpts is replayDemo with the pipeline options exposed, so a test can
// put the sensor under conditions the defaults never reach.
func replayDemoOpts(t *testing.T, opts pipeline.Options) (pcapgen.Summary, []model.Alert, pipeline.Stats) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "demo.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatalf("create capture: %v", err)
	}
	sum, err := pcapgen.Write(f, captureStart)
	if err != nil {
		f.Close()
		t.Fatalf("generate capture: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close capture: %v", err)
	}

	src, err := capture.OpenFile(path)
	if err != nil {
		t.Fatalf("open capture: %v", err)
	}
	defer src.Close()

	var alerts []model.Alert
	// A cooldown longer than the capture collapses the repeat reports a growing
	// body of evidence produces, so the assertions below are about whether a
	// behaviour was found at all rather than how many times it was restated.
	engine := detect.NewEngine(
		detect.Config{AlertCooldown: 24 * time.Hour},
		func(a model.Alert) { alerts = append(alerts, a) },
	)
	engine.Register(detect.NewBeacon(detect.BeaconConfig{}))
	engine.Register(detect.NewDNSTunnel(detect.DNSTunnelConfig{}))
	engine.Register(detect.NewScan(detect.ScanConfig{}))
	engine.Register(detect.NewExfil(detect.ExfilConfig{}))
	engine.Register(detect.NewInventory(detect.InventoryConfig{}))

	p := pipeline.New(engine, opts)

	stats, err := p.Run(context.Background(), src)
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	return sum, alerts, stats
}

// TestReplayFindsEveryPlantedBehaviour is the detection-quality gate: the
// generator declares what it hid in the capture, and every one of those has to
// come back out with the right source attributed.
func TestReplayFindsEveryPlantedBehaviour(t *testing.T) {
	sum, alerts, _ := replayDemo(t)

	if len(sum.Expected) == 0 {
		t.Fatal("the generator declared no expectations; the test would pass vacuously")
	}

	for _, exp := range sum.Expected {
		var found *model.Alert
		for i := range alerts {
			if alerts[i].RuleID == exp.RuleID && alerts[i].Src.String() == exp.Src {
				found = &alerts[i]
				break
			}
		}
		if found == nil {
			t.Errorf("MISSED %s from %s\n      planted: %s", exp.RuleID, exp.Src, exp.Note)
			continue
		}
		if exp.Dst != "" && found.Dst.IsValid() && found.Dst.String() != exp.Dst {
			t.Errorf("%s: destination = %s, want %s", exp.RuleID, found.Dst, exp.Dst)
		}
		if found.Score <= 0 || found.Score > 1 {
			t.Errorf("%s: score %.3f outside [0,1]", exp.RuleID, found.Score)
		}
		if len(found.Evidence) == 0 {
			t.Errorf("%s: fired with no supporting evidence", exp.RuleID)
		}
		t.Logf("found %s  %-9s sev=%-6s score=%.2f  %s",
			exp.RuleID, found.Src, found.Severity, found.Score, found.Title)
	}
}

// TestReplayDoesNotAccuseBenignHosts is the false-positive gate.
//
// This is the assertion that matters most. Any detector can be made to fire by
// lowering its threshold; the hard part is not firing on the ordinary traffic
// sitting right next to the attack. The capture deliberately contains six hosts
// browsing normally, and none of them may be reported.
func TestReplayDoesNotAccuseBenignHosts(t *testing.T) {
	sum, alerts, _ := replayDemo(t)

	guilty := make(map[string]bool, len(sum.Expected))
	for _, e := range sum.Expected {
		guilty[e.Src] = true
	}

	benign := make([]string, 0, len(sum.Hosts))
	for _, h := range sum.Hosts {
		if !guilty[h] {
			benign = append(benign, h)
		}
	}
	if len(benign) == 0 {
		t.Fatal("no benign hosts in the scenario; this test would pass vacuously")
	}
	benignSet := make(map[string]bool, len(benign))
	for _, h := range benign {
		benignSet[h] = true
	}

	for _, a := range alerts {
		// Informational inventory events are expected for every host.
		if a.Severity < model.SevLow {
			continue
		}
		if benignSet[a.Src.String()] {
			t.Errorf("FALSE POSITIVE: %s (%s) accused benign host %s\n      %s",
				a.RuleID, a.Detector, a.Src, a.Title)
		}
	}
	t.Logf("%d benign hosts, none reported above info severity", len(benign))
}

// TestReplayIsDeterministic guards the property the whole testing strategy
// rests on: the same capture must always yield the same findings.
func TestReplayIsDeterministic(t *testing.T) {
	_, first, _ := replayDemo(t)
	_, second, _ := replayDemo(t)

	if len(first) != len(second) {
		t.Fatalf("alert count differs between runs: %d vs %d", len(first), len(second))
	}
	for i := range first {
		if first[i].RuleID != second[i].RuleID || first[i].Src != second[i].Src {
			t.Fatalf("alert %d differs between runs: %s/%s vs %s/%s",
				i, first[i].RuleID, first[i].Src, second[i].RuleID, second[i].Src)
		}
		if first[i].Score != second[i].Score {
			t.Errorf("alert %d (%s) score differs: %v vs %v",
				i, first[i].RuleID, first[i].Score, second[i].Score)
		}
	}
}

// TestReplayDecodesEverything checks the capture layer end to end: a
// well-formed file must decode completely, and every TLS client in it must be
// fingerprinted.
func TestReplayDecodesEverything(t *testing.T) {
	sum, _, stats := replayDemo(t)

	if got, want := stats.Packets, uint64(sum.Packets); got != want {
		t.Errorf("processed %d packets, capture contains %d", got, want)
	}
	if stats.Undecodable != 0 {
		t.Errorf("%d packets failed to decode; the generator writes only well-formed frames", stats.Undecodable)
	}
	if stats.Fingerprints == 0 {
		t.Error("no TLS clients fingerprinted, but the capture is full of ClientHellos")
	}
	if stats.ServerFingerprints == 0 {
		t.Error("no TLS servers fingerprinted, but the capture contains ServerHellos")
	}
	// Server fingerprints must trail client ones: QUIC flows contribute a JA4
	// but never a JA4S, because a QUIC server's reply is encrypted under keys a
	// passive observer never sees.
	if stats.ServerFingerprints >= stats.Fingerprints {
		t.Errorf("server fingerprints (%d) did not trail client fingerprints (%d); "+
			"the QUIC flows should contribute a JA4 with no JA4S",
			stats.ServerFingerprints, stats.Fingerprints)
	}
	if stats.Flow.Created == 0 {
		t.Error("no flows assembled")
	}
	if stats.Flow.Active != 0 {
		t.Errorf("%d flows still open after the run; end-of-capture drain did not happen", stats.Flow.Active)
	}
	// Packet timestamps must be non-decreasing: a capture that steps backwards
	// starves detectors of their scoring cycle, which is a bug this generator
	// had and the test now prevents from returning.
	if !stats.LastPacket.After(stats.FirstPacket) {
		t.Errorf("capture spans no time: %s .. %s", stats.FirstPacket, stats.LastPacket)
	}
	t.Logf("%d packets, %d flows, %d client + %d server fingerprints, %.0f packets/sec",
		stats.Packets, stats.Flow.Created, stats.Fingerprints,
		stats.ServerFingerprints, stats.PacketsPerSecond())
}

func BenchmarkReplayThroughput(b *testing.B) {
	path := filepath.Join(b.TempDir(), "demo.pcap")
	f, err := os.Create(path)
	if err != nil {
		b.Fatal(err)
	}
	sum, err := pcapgen.Write(f, captureStart)
	f.Close()
	if err != nil {
		b.Fatal(err)
	}

	b.SetBytes(int64(sum.Bytes))
	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		src, err := capture.OpenFile(path)
		if err != nil {
			b.Fatal(err)
		}
		engine := detect.NewEngine(detect.Config{}, func(model.Alert) {})
		engine.Register(detect.NewBeacon(detect.BeaconConfig{}))
		engine.Register(detect.NewDNSTunnel(detect.DNSTunnelConfig{}))
		engine.Register(detect.NewScan(detect.ScanConfig{}))
		engine.Register(detect.NewExfil(detect.ExfilConfig{}))
		engine.Register(detect.NewInventory(detect.InventoryConfig{SilenceNewDevice: true}))

		p := pipeline.New(engine, pipeline.Options{TickInterval: 30 * time.Second})
		if _, err := p.Run(context.Background(), src); err != nil {
			b.Fatal(err)
		}
		src.Close()
	}
}
