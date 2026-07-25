// Package api serves the alert feed, asset inventory, and live dashboard.
//
// The dashboard is embedded in the binary with go:embed rather than built by a
// JavaScript toolchain and served from disk. That is a deliberate constraint:
// the point of this project is a single static binary with no runtime
// dependencies, and a UI that needs `npm install` before it will start would
// undo that for the sake of a framework nobody looking at a network sensor
// cares about.
package api

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/model"
	"github.com/baldoseri/tracehound/internal/pipeline"
)

//go:embed web
var webFS embed.FS

// DefaultMaxAlerts bounds the in-memory alert ring.
const DefaultMaxAlerts = 5000

// Server exposes the sensor's state over HTTP.
type Server struct {
	pipe *pipeline.Pipeline
	inv  *detect.Inventory
	eng  *detect.Engine

	mu        sync.RWMutex
	alerts    []model.Alert
	maxAlerts int
	subs      map[chan model.Alert]struct{}

	started time.Time
}

// New returns a server backed by a running pipeline.
func New(pipe *pipeline.Pipeline, eng *detect.Engine, inv *detect.Inventory, maxAlerts int) *Server {
	if maxAlerts <= 0 {
		maxAlerts = DefaultMaxAlerts
	}
	return &Server{
		pipe:      pipe,
		eng:       eng,
		inv:       inv,
		maxAlerts: maxAlerts,
		subs:      make(map[chan model.Alert]struct{}),
		started:   time.Now(),
	}
}

// Publish records an alert and fans it out to live subscribers. It is safe to
// call from the pipeline goroutine and never blocks on a slow HTTP client.
func (s *Server) Publish(a model.Alert) {
	s.mu.Lock()
	s.alerts = append(s.alerts, a)
	if len(s.alerts) > s.maxAlerts {
		// Drop from the front. Copying rather than reslicing keeps the backing
		// array from growing without bound over a long capture.
		s.alerts = append(s.alerts[:0], s.alerts[len(s.alerts)-s.maxAlerts:]...)
	}
	subs := make([]chan model.Alert, 0, len(s.subs))
	for ch := range s.subs {
		subs = append(subs, ch)
	}
	s.mu.Unlock()

	for _, ch := range subs {
		select {
		case ch <- a:
		default:
			// A subscriber that cannot keep up loses this event rather than
			// stalling packet processing. Detection must never wait on a UI.
		}
	}
}

// Handler builds the HTTP routes.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /api/alerts", s.handleAlerts)
	mux.HandleFunc("GET /api/devices", s.handleDevices)
	mux.HandleFunc("GET /api/flows", s.handleFlows)
	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/attack", s.handleAttack)
	mux.HandleFunc("GET /api/stream", s.handleStream)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		fmt.Fprintln(w, "ok")
	})

	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		panic("api: embedded web assets missing: " + err.Error())
	}
	mux.Handle("GET /", http.FileServerFS(sub))

	return mux
}

// ListenAndServe runs the server until ctx is cancelled.
func (s *Server) ListenAndServe(ctx context.Context, addr string) error {
	srv := &http.Server{
		Addr:              addr,
		Handler:           s.Handler(),
		ReadHeaderTimeout: 10 * time.Second,
	}

	errc := make(chan error, 1)
	go func() {
		err := srv.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		errc <- err
	}()

	select {
	case err := <-errc:
		return err
	case <-ctx.Done():
		shutdown, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		return srv.Shutdown(shutdown)
	}
}

// --- handlers ---------------------------------------------------------------

func (s *Server) handleAlerts(w http.ResponseWriter, r *http.Request) {
	limit := intParam(r, "limit", 200)
	minSev := model.SevInfo
	if v := r.URL.Query().Get("min_severity"); v != "" {
		if err := minSev.UnmarshalText([]byte(v)); err != nil {
			httpError(w, http.StatusBadRequest, err)
			return
		}
	}

	s.mu.RLock()
	// Newest first, which is the order an analyst triages in.
	out := make([]model.Alert, 0, min(limit, len(s.alerts)))
	for i := len(s.alerts) - 1; i >= 0 && len(out) < limit; i-- {
		if s.alerts[i].Severity >= minSev {
			out = append(out, s.alerts[i])
		}
	}
	s.mu.RUnlock()

	writeJSON(w, out)
}

func (s *Server) handleDevices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.inv.Devices())
}

func (s *Server) handleFlows(w http.ResponseWriter, r *http.Request) {
	flows := s.pipe.Table().Snapshot(intParam(r, "limit", 200))
	// model.Flow keeps Proto unexported in JSON, so project it into a shape the
	// dashboard can render directly.
	type flowView struct {
		model.Flow
		Proto    string `json:"proto"`
		Bytes    uint64 `json:"bytes"`
		Packets  uint64 `json:"packets"`
		Duration string `json:"duration"`
	}
	out := make([]flowView, len(flows))
	for i, f := range flows {
		out[i] = flowView{
			Flow:     f,
			Proto:    f.ProtoString(),
			Bytes:    f.Bytes(),
			Packets:  f.Packets(),
			Duration: f.Duration().Round(time.Millisecond).String(),
		}
	}
	writeJSON(w, out)
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	st := s.pipe.Stats()

	s.mu.RLock()
	counts := map[string]int{}
	for _, a := range s.alerts {
		counts[a.Severity.String()]++
	}
	total := len(s.alerts)
	s.mu.RUnlock()

	writeJSON(w, map[string]any{
		"packets":            st.Packets,
		"bytes":              st.Bytes,
		"undecodable":        st.Undecodable,
		"fingerprints":       st.Fingerprints,
		"flows":              st.Flow,
		"detect":             st.Detect,
		"first_packet":       st.FirstPacket,
		"last_packet":        st.LastPacket,
		"packets_per_sec":    st.PacketsPerSecond(),
		"alerts_total":       total,
		"alerts_by_severity": counts,
		"uptime_seconds":     int(time.Since(s.started).Seconds()),
		"detectors":          s.eng.Detectors(),
	})
}

// handleAttack summarises ATT&CK coverage: which techniques this sensor has
// actually observed, which is the question a detection engineer asks first.
func (s *Server) handleAttack(w http.ResponseWriter, r *http.Request) {
	type entry struct {
		model.Technique
		Count int `json:"count"`
	}

	s.mu.RLock()
	byID := map[string]*entry{}
	for _, a := range s.alerts {
		for _, t := range a.Techniques {
			e, ok := byID[t.ID]
			if !ok {
				e = &entry{Technique: t}
				byID[t.ID] = e
			}
			e.Count++
		}
	}
	s.mu.RUnlock()

	out := make([]entry, 0, len(byID))
	for _, e := range byID {
		out = append(out, *e)
	}
	writeJSON(w, out)
}

// handleStream is a server-sent events endpoint carrying alerts as they fire.
//
// SSE rather than WebSockets: the traffic is strictly one-way, it survives
// proxies that mangle upgrades, and browsers reconnect automatically. A
// WebSocket here would be more machinery for no additional capability.
func (s *Server) handleStream(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		httpError(w, http.StatusInternalServerError, errors.New("streaming unsupported"))
		return
	}

	ch := make(chan model.Alert, 64)
	s.mu.Lock()
	s.subs[ch] = struct{}{}
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.subs, ch)
		s.mu.Unlock()
		close(ch)
	}()

	h := w.Header()
	h.Set("Content-Type", "text/event-stream")
	h.Set("Cache-Control", "no-cache")
	h.Set("Connection", "keep-alive")
	h.Set("X-Accel-Buffering", "no") // stop nginx from buffering the stream
	w.WriteHeader(http.StatusOK)
	fmt.Fprint(w, ": connected\n\n")
	flusher.Flush()

	// A periodic comment keeps intermediaries from timing out an idle stream.
	keepalive := time.NewTicker(20 * time.Second)
	defer keepalive.Stop()

	enc := json.NewEncoder(w)
	for {
		select {
		case <-r.Context().Done():
			return
		case <-keepalive.C:
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
		case a := <-ch:
			fmt.Fprint(w, "event: alert\ndata: ")
			if err := enc.Encode(a); err != nil {
				return
			}
			fmt.Fprint(w, "\n")
			flusher.Flush()
		}
	}
}

// --- helpers ----------------------------------------------------------------

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	enc := json.NewEncoder(w)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		// The status line is already sent by now; log-free failure is the only
		// option left, and the client will see a truncated body.
		return
	}
}

func httpError(w http.ResponseWriter, code int, err error) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func intParam(r *http.Request, name string, def int) int {
	v := r.URL.Query().Get(name)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil || n <= 0 {
		return def
	}
	return n
}
