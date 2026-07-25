package store

import (
	"context"
	"net/netip"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

var base = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

func openTemp(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"), Options{FlushInterval: 20 * time.Millisecond})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func alert(id string, sev model.Severity, at time.Time) model.Alert {
	return model.Alert{
		ID:          id,
		Time:        at,
		RuleID:      "TH-0001",
		Detector:    "beaconing",
		Title:       "Periodic beaconing",
		Description: "evidence-bearing description",
		Severity:    sev,
		Score:       0.96,
		Src:         netip.MustParseAddr("10.0.0.66"),
		Dst:         netip.MustParseAddr("198.51.100.23"),
		DstPort:     443,
		Proto:       "tcp",
		Techniques:  []model.Technique{{ID: "T1071.001", Name: "Web Protocols", Tactic: "command-and-control"}},
		Evidence:    map[string]any{"connections": float64(28), "jitter_pct": 5.9},
	}
}

// TestRoundTrip is the property the whole package exists for: what went in
// comes back out intact after the process that wrote it is gone.
func TestRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "roundtrip.db")

	s, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	in := alert("abc123", model.SevHigh, base)
	s.Enqueue(in)
	// Close flushes the queue, so this is also the durability assertion.
	if err := s.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	// Reopen the same file, which is what a restart does.
	reopened, err := Open(path, Options{})
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	defer reopened.Close()

	got, err := reopened.Alerts(context.Background(), Query{})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d alerts after reopen, want 1", len(got))
	}
	a := got[0]

	if a.ID != in.ID || a.RuleID != in.RuleID || a.Detector != in.Detector {
		t.Errorf("identity fields differ: %+v", a)
	}
	if !a.Time.Equal(in.Time) {
		t.Errorf("time = %v, want %v", a.Time, in.Time)
	}
	if a.Severity != in.Severity {
		t.Errorf("severity = %v, want %v", a.Severity, in.Severity)
	}
	if a.Src != in.Src || a.Dst != in.Dst || a.DstPort != in.DstPort {
		t.Errorf("endpoints = %v -> %v:%d", a.Src, a.Dst, a.DstPort)
	}
	if len(a.Techniques) != 1 || a.Techniques[0].ID != "T1071.001" {
		t.Errorf("techniques = %+v", a.Techniques)
	}
	if a.Evidence["connections"] != float64(28) {
		t.Errorf("evidence = %+v", a.Evidence)
	}
}

func TestAlertsAreDeduplicatedByID(t *testing.T) {
	s := openTemp(t)

	// The same alert offered twice, which happens whenever a run is repeated
	// over the same capture.
	a := alert("same-id", model.SevMedium, base)
	s.Enqueue(a)
	s.Enqueue(a)
	waitForWrites(t, s, 1)

	n, err := s.CountAlerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Errorf("stored %d rows for one alert id, want 1", n)
	}
}

func TestQueryFilters(t *testing.T) {
	s := openTemp(t)

	s.Enqueue(alert("a", model.SevInfo, base))
	s.Enqueue(alert("b", model.SevMedium, base.Add(time.Minute)))
	high := alert("c", model.SevHigh, base.Add(2*time.Minute))
	high.RuleID = "TH-0002"
	high.Src = netip.MustParseAddr("10.0.0.99")
	s.Enqueue(high)
	waitForWrites(t, s, 3)

	ctx := context.Background()

	got, err := s.Alerts(ctx, Query{MinSeverity: model.SevMedium})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("severity filter returned %d, want 2", len(got))
	}
	// Newest first is the order an analyst triages in.
	if len(got) == 2 && !got[0].Time.After(got[1].Time) {
		t.Error("results are not newest first")
	}

	got, err = s.Alerts(ctx, Query{RuleID: "TH-0002"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "c" {
		t.Errorf("rule filter returned %+v", got)
	}

	got, err = s.Alerts(ctx, Query{Src: "10.0.0.99"})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ID != "c" {
		t.Errorf("src filter returned %d rows", len(got))
	}

	got, err = s.Alerts(ctx, Query{Since: base.Add(90 * time.Second)})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Errorf("since filter returned %d, want 1", len(got))
	}

	got, err = s.Alerts(ctx, Query{Limit: 2})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Errorf("limit returned %d rows, want 2", len(got))
	}
}

func TestDevicesUpsert(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	first := []model.Device{{
		Addr:      netip.MustParseAddr("10.0.0.10"),
		MAC:       "02:00:0a:00:00:0a",
		FirstSeen: base.Add(5 * time.Minute),
		LastSeen:  base.Add(6 * time.Minute),
		JA4s:      []string{"t13d1516h2_aaaa_bbbb"},
		BytesSent: 100,
		Flows:     2,
	}}
	if err := s.SaveDevices(ctx, first); err != nil {
		t.Fatal(err)
	}

	// A later save with an earlier first_seen and a later last_seen: the
	// stored range must widen rather than being overwritten, or a device's
	// history would shrink every time the sensor restarted.
	second := []model.Device{{
		Addr:      netip.MustParseAddr("10.0.0.10"),
		MAC:       "02:00:0a:00:00:0a",
		FirstSeen: base,
		LastSeen:  base.Add(30 * time.Minute),
		JA4s:      []string{"t13d1516h2_aaaa_bbbb", "q13d0306h3_cccc_dddd"},
		BytesSent: 500,
		Flows:     9,
	}}
	if err := s.SaveDevices(ctx, second); err != nil {
		t.Fatal(err)
	}

	got, err := s.Devices(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d devices, want 1", len(got))
	}
	d := got[0]
	if !d.FirstSeen.Equal(base) {
		t.Errorf("first_seen = %v, want the earlier value %v", d.FirstSeen, base)
	}
	if !d.LastSeen.Equal(base.Add(30 * time.Minute)) {
		t.Errorf("last_seen = %v, want the later value", d.LastSeen)
	}
	if len(d.JA4s) != 2 {
		t.Errorf("ja4s = %v, want both fingerprints", d.JA4s)
	}
	if d.Flows != 9 || d.BytesSent != 500 {
		t.Errorf("counters = %d flows / %d bytes", d.Flows, d.BytesSent)
	}
}

// TestEnqueueNeverBlocks is the guarantee the capture path depends on. A full
// queue must drop and count, not stall the packet loop.
func TestEnqueueNeverBlocks(t *testing.T) {
	s, err := Open(filepath.Join(t.TempDir(), "small.db"), Options{
		QueueSize:     4,
		BatchSize:     1000, // never fills, so the writer stays idle
		FlushInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 10_000; i++ {
			s.Enqueue(alert("id", model.SevLow, base))
		}
	}()

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Enqueue blocked; the packet loop would have stalled behind storage")
	}
	if s.Stats().Dropped == 0 {
		t.Error("nothing was dropped despite overfilling a queue of 4")
	}
}

func TestConcurrentEnqueueAndQuery(t *testing.T) {
	s := openTemp(t)
	ctx := context.Background()

	var wg sync.WaitGroup
	stop := make(chan struct{})

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			s.Enqueue(alert(string(rune('a'+i%26))+string(rune('a'+i/26%26))+time.Duration(i).String(),
				model.SevMedium, base.Add(time.Duration(i)*time.Second)))
		}
		close(stop)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			if _, err := s.Alerts(ctx, Query{Limit: 20}); err != nil {
				t.Errorf("concurrent query failed: %v", err)
				return
			}
		}
	}()

	wg.Wait()
}

func TestMigrationIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.db")

	for i := 0; i < 3; i++ {
		s, err := Open(path, Options{})
		if err != nil {
			t.Fatalf("open %d: %v", i, err)
		}
		s.Enqueue(alert("keep"+string(rune('0'+i)), model.SevLow, base))
		if err := s.Close(); err != nil {
			t.Fatalf("close %d: %v", i, err)
		}
	}

	s, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()

	n, err := s.CountAlerts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 {
		t.Errorf("after three open/close cycles there are %d alerts, want 3", n)
	}
}

func TestRefusesNewerSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "future.db")
	s, err := Open(path, Options{})
	if err != nil {
		t.Fatal(err)
	}
	// Pretend a newer build wrote this file.
	if _, err := s.db.Exec(`PRAGMA user_version = 999`); err != nil {
		t.Fatal(err)
	}
	s.Close()

	if _, err := Open(path, Options{}); err == nil {
		t.Error("opened a database from a newer schema version instead of refusing")
	}
}

// waitForWrites blocks until the background writer has committed n alerts.
func waitForWrites(t *testing.T, s *Store, n uint64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if s.Stats().Written >= n {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("writer committed %d alerts, waited for %d", s.Stats().Written, n)
}

func BenchmarkEnqueue(b *testing.B) {
	s, err := Open(filepath.Join(b.TempDir(), "bench.db"), Options{})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()

	a := alert("bench", model.SevMedium, base)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Enqueue(a)
	}
}
