package api_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/api"
	"github.com/baldoseri/tracehound/internal/capture"
	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/model"
	"github.com/baldoseri/tracehound/internal/pcapgen"
	"github.com/baldoseri/tracehound/internal/pipeline"
	"github.com/baldoseri/tracehound/internal/rules"
)

var captureStart = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)

// newSensor wires a complete sensor plus its HTTP surface, exactly as the CLI
// does, and returns a function that runs the capture through it.
func newSensor(t *testing.T) (*api.Server, func()) {
	t.Helper()

	path := filepath.Join(t.TempDir(), "demo.pcap")
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := pcapgen.Write(f, captureStart); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()

	pack, err := rules.Builtin()
	if err != nil {
		t.Fatal(err)
	}
	detectors, inventory, err := pack.Detectors()
	if err != nil {
		t.Fatal(err)
	}

	var srv *api.Server
	engine := detect.NewEngine(
		detect.Config{AlertCooldown: time.Minute, Policy: pack.Policy()},
		func(a model.Alert) { srv.Publish(a) },
	)
	for _, d := range detectors {
		engine.Register(d)
	}

	p := pipeline.New(engine, pipeline.Options{TickInterval: 15 * time.Second})
	srv = api.New(p, engine, inventory, 0)

	run := func() {
		src, err := capture.OpenFile(path)
		if err != nil {
			t.Error(err)
			return
		}
		defer src.Close()
		if _, err := p.Run(context.Background(), src); err != nil {
			t.Error(err)
		}
	}
	return srv, run
}

// TestAPIServesWhilePipelineRuns is the test the earlier suite was missing.
//
// Every other test either runs the pipeline or exercises the API, never both at
// once, so nothing could catch the pipeline writing a flow's fingerprint while
// an HTTP handler read the same record. Run this under -race and that write is
// exactly what it reports.
func TestAPIServesWhilePipelineRuns(t *testing.T) {
	srv, run := newSensor(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	endpoints := []string{
		"/api/flows?limit=200",
		"/api/devices",
		"/api/alerts?limit=100",
		"/api/stats",
		"/api/attack",
		"/healthz",
	}
	for _, ep := range endpoints {
		wg.Add(1)
		go func(path string) {
			defer wg.Done()
			client := &http.Client{Timeout: 5 * time.Second}
			for {
				select {
				case <-stop:
					return
				default:
				}
				resp, err := client.Get(ts.URL + path)
				if err != nil {
					continue // the server is shutting down
				}
				body, _ := io.ReadAll(resp.Body)
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					t.Errorf("%s returned %d", path, resp.StatusCode)
					return
				}
				// JSON endpoints must stay parseable under concurrent mutation.
				if path != "/healthz" {
					var v any
					if err := json.Unmarshal(body, &v); err != nil {
						t.Errorf("%s returned invalid JSON: %v", path, err)
						return
					}
				}
			}
		}(ep)
	}

	run()
	close(stop)
	wg.Wait()

	// The run really did produce something for the readers to race against.
	resp, err := http.Get(ts.URL + "/api/stats")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var stats struct {
		Packets      uint64 `json:"packets"`
		Fingerprints uint64 `json:"fingerprints"`
		AlertsTotal  int    `json:"alerts_total"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&stats); err != nil {
		t.Fatal(err)
	}
	if stats.Packets == 0 || stats.Fingerprints == 0 || stats.AlertsTotal == 0 {
		t.Errorf("pipeline produced nothing to race against: %+v", stats)
	}
	t.Logf("%d packets, %d fingerprints, %d alerts served concurrently",
		stats.Packets, stats.Fingerprints, stats.AlertsTotal)
}

// TestSubscriberChurnDoesNotPanic covers a crash that a dashboard user could
// trigger by closing a browser tab.
//
// Publish copies the subscriber set under the lock and sends outside it, so it
// can hold a channel that the stream handler has already unsubscribed. When the
// handler also closed that channel, the send became a send-on-closed-channel
// panic and took the process with it.
func TestSubscriberChurnDoesNotPanic(t *testing.T) {
	srv, _ := newSensor(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	stop := make(chan struct{})
	var wg sync.WaitGroup

	// Publish continuously.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stop:
				return
			default:
			}
			srv.Publish(model.Alert{
				ID:       "test",
				RuleID:   "TH-0001",
				Title:    "synthetic",
				Severity: model.SevMedium,
				Time:     captureStart,
			})
		}
	}()

	// Connect and disconnect repeatedly, which is what closing a tab does.
	for i := 0; i < 60; i++ {
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Millisecond)
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/stream", nil)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		resp, err := http.DefaultClient.Do(req)
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
		cancel()
	}

	close(stop)
	wg.Wait()
	// Reaching here without a panic is the assertion.
}

// TestStreamDeliversAlerts checks the SSE path actually carries events, so the
// churn test above cannot pass by never delivering anything.
func TestStreamDeliversAlerts(t *testing.T) {
	srv, _ := newSensor(t)
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, ts.URL+"/api/stream", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	if ct := resp.Header.Get("Content-Type"); ct != "text/event-stream" {
		t.Errorf("Content-Type = %q, want text/event-stream", ct)
	}

	// Give the handler a moment to register before publishing.
	time.Sleep(50 * time.Millisecond)
	go func() {
		for i := 0; i < 20; i++ {
			srv.Publish(model.Alert{
				ID: "abc", RuleID: "TH-0002", Title: "streamed finding",
				Severity: model.SevHigh, Time: captureStart,
			})
			time.Sleep(5 * time.Millisecond)
		}
	}()

	buf := make([]byte, 4096)
	deadline := time.Now().Add(3 * time.Second)
	var got string
	for time.Now().Before(deadline) {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			got += string(buf[:n])
			if len(got) > 0 && containsAll(got, "event: alert", "streamed finding") {
				return // delivered
			}
		}
		if err != nil {
			break
		}
	}
	t.Errorf("no alert arrived on the stream; got %q", got)
}

func containsAll(s string, subs ...string) bool {
	for _, sub := range subs {
		found := false
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
