// Package store persists findings so they survive a restart.
//
// Two properties drive the design.
//
// The packet loop must never wait on a disk. A sensor that stalls when storage
// gets slow drops traffic, and dropped traffic is undetected traffic, so alerts
// are handed to a buffered queue and written by a background goroutine. If the
// queue fills, alerts are dropped and counted rather than allowed to back up
// into the capture path. Losing a record of a finding is bad; losing the packets
// that would have produced the next one is worse.
//
// And it stays cgo-free. modernc.org/sqlite is a pure-Go translation of SQLite,
// so `CGO_ENABLED=0 go build` still produces the static binary the rest of the
// project depends on. The alternative, mattn/go-sqlite3, is faster and would
// have cost the single-binary property outright.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite" // pure-Go driver, registered as "sqlite"

	"github.com/baldoseri/tracehound/internal/model"
)

// Tuning for the background writer.
const (
	// DefaultQueueSize is how many alerts may be waiting to be written. Sized
	// so that a burst of findings during an incident is absorbed rather than
	// dropped, while still bounding memory.
	DefaultQueueSize = 4096
	// DefaultBatchSize is how many alerts go into one transaction. Committing
	// per alert makes SQLite fsync per alert, which is roughly two orders of
	// magnitude slower than batching.
	DefaultBatchSize = 256
	// DefaultFlushInterval bounds how long an alert can sit unwritten when
	// traffic is quiet and no batch fills up.
	DefaultFlushInterval = 2 * time.Second
)

// Options configures a Store.
type Options struct {
	QueueSize     int
	BatchSize     int
	FlushInterval time.Duration
}

func (o Options) withDefaults() Options {
	if o.QueueSize <= 0 {
		o.QueueSize = DefaultQueueSize
	}
	if o.BatchSize <= 0 {
		o.BatchSize = DefaultBatchSize
	}
	if o.FlushInterval <= 0 {
		o.FlushInterval = DefaultFlushInterval
	}
	return o
}

// Store is a SQLite-backed record of alerts and observed devices.
type Store struct {
	db   *sql.DB
	opts Options

	queue chan model.Alert
	done  chan struct{}

	written atomic.Uint64
	dropped atomic.Uint64
	failed  atomic.Uint64

	closeOnce sync.Once
	closeErr  error
}

// Open prepares a database at path, creating and migrating it as needed.
func Open(path string, opts Options) (*Store, error) {
	opts = opts.withDefaults()

	// WAL lets the dashboard read history while the writer is committing.
	// synchronous=NORMAL trades a fsync per commit for one per checkpoint,
	// which is the right trade for telemetry: losing the last few seconds of
	// alerts to a power cut is survivable, halving throughput is not.
	dsn := path + "?_pragma=journal_mode(WAL)" +
		"&_pragma=synchronous(NORMAL)" +
		"&_pragma=busy_timeout(5000)" +
		"&_pragma=foreign_keys(ON)"

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	// One writer, because SQLite serialises writes anyway and a pool of them
	// only produces SQLITE_BUSY contention.
	db.SetMaxOpenConns(1)

	if err := db.PingContext(context.Background()); err != nil {
		db.Close()
		return nil, fmt.Errorf("store: open %s: %w", path, err)
	}
	if err := migrate(db); err != nil {
		db.Close()
		return nil, err
	}

	s := &Store{
		db:    db,
		opts:  opts,
		queue: make(chan model.Alert, opts.QueueSize),
		done:  make(chan struct{}),
	}
	go s.writeLoop()
	return s, nil
}

// Close flushes anything queued and closes the database.
func (s *Store) Close() error {
	s.closeOnce.Do(func() {
		close(s.queue)
		<-s.done // let the writer drain
		s.closeErr = s.db.Close()
	})
	return s.closeErr
}

// Stats reports what the writer has done.
type Stats struct {
	Written uint64 `json:"written"`
	Dropped uint64 `json:"dropped"`
	Failed  uint64 `json:"failed"`
	Queued  int    `json:"queued"`
}

// Stats returns the writer counters.
func (s *Store) Stats() Stats {
	return Stats{
		Written: s.written.Load(),
		Dropped: s.dropped.Load(),
		Failed:  s.failed.Load(),
		Queued:  len(s.queue),
	}
}

// Enqueue hands an alert to the background writer. It never blocks.
//
// This is called from the packet-processing goroutine, so blocking here would
// stall capture. A full queue means storage cannot keep up, and the honest
// response is to drop the record and count it rather than to stop detecting.
func (s *Store) Enqueue(a model.Alert) {
	select {
	case s.queue <- a:
	default:
		s.dropped.Add(1)
	}
}

// writeLoop batches queued alerts into transactions.
func (s *Store) writeLoop() {
	defer close(s.done)

	batch := make([]model.Alert, 0, s.opts.BatchSize)
	ticker := time.NewTicker(s.opts.FlushInterval)
	defer ticker.Stop()

	flush := func() {
		if len(batch) == 0 {
			return
		}
		if err := s.writeBatch(batch); err != nil {
			s.failed.Add(uint64(len(batch)))
		} else {
			s.written.Add(uint64(len(batch)))
		}
		batch = batch[:0]
	}

	for {
		select {
		case a, ok := <-s.queue:
			if !ok {
				flush() // drain on Close
				return
			}
			batch = append(batch, a)
			if len(batch) >= s.opts.BatchSize {
				flush()
			}
		case <-ticker.C:
			flush()
		}
	}
}

// writeBatch commits one transaction.
func (s *Store) writeBatch(batch []model.Alert) error {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck // no-op once Commit succeeds

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO alerts
			(id, ts, rule_id, detector, title, description, severity, score,
			 src, dst, dst_port, proto, techniques, evidence)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)
		ON CONFLICT(id) DO NOTHING`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range batch {
		a := &batch[i]
		techniques, err := json.Marshal(a.Techniques)
		if err != nil {
			return err
		}
		evidence, err := json.Marshal(a.Evidence)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx,
			a.ID, a.Time.UTC().UnixNano(), a.RuleID, a.Detector, a.Title, a.Description,
			int(a.Severity), a.Score, addrText(a.Src), addrText(a.Dst),
			int(a.DstPort), a.Proto, string(techniques), string(evidence),
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Query filters a history lookup. The zero value returns the most recent
// alerts at any severity.
type Query struct {
	Limit       int
	MinSeverity model.Severity
	Since       time.Time
	RuleID      string
	Src         string
}

// Alerts returns stored alerts, newest first.
func (s *Store) Alerts(ctx context.Context, q Query) ([]model.Alert, error) {
	if q.Limit <= 0 {
		q.Limit = 100
	}

	var (
		where []string
		args  []any
	)
	if q.MinSeverity > model.SevInfo {
		where = append(where, "severity >= ?")
		args = append(args, int(q.MinSeverity))
	}
	if !q.Since.IsZero() {
		where = append(where, "ts >= ?")
		args = append(args, q.Since.UTC().UnixNano())
	}
	if q.RuleID != "" {
		where = append(where, "rule_id = ?")
		args = append(args, q.RuleID)
	}
	if q.Src != "" {
		where = append(where, "src = ?")
		args = append(args, q.Src)
	}

	sqlText := `SELECT id, ts, rule_id, detector, title, description, severity,
	                   score, src, dst, dst_port, proto, techniques, evidence
	            FROM alerts`
	if len(where) > 0 {
		sqlText += " WHERE " + strings.Join(where, " AND ")
	}
	sqlText += " ORDER BY ts DESC LIMIT ?"
	args = append(args, q.Limit)

	rows, err := s.db.QueryContext(ctx, sqlText, args...)
	if err != nil {
		return nil, fmt.Errorf("store: query alerts: %w", err)
	}
	defer rows.Close()

	var out []model.Alert
	for rows.Next() {
		var (
			a          model.Alert
			ts         int64
			sev, port  int
			src, dst   string
			techniques string
			evidence   string
		)
		if err := rows.Scan(&a.ID, &ts, &a.RuleID, &a.Detector, &a.Title, &a.Description,
			&sev, &a.Score, &src, &dst, &port, &a.Proto, &techniques, &evidence); err != nil {
			return nil, err
		}
		a.Time = time.Unix(0, ts).UTC()
		a.Severity = model.Severity(sev)
		a.DstPort = uint16(port)
		a.Src = parseAddr(src)
		a.Dst = parseAddr(dst)
		if err := json.Unmarshal([]byte(techniques), &a.Techniques); err != nil {
			return nil, err
		}
		if err := json.Unmarshal([]byte(evidence), &a.Evidence); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SaveDevices upserts the asset inventory.
//
// Written in one transaction on a cadence rather than per change: a device's
// byte counters move on every packet, and persisting that would turn the
// inventory into the busiest table in the database for no analytical gain.
func (s *Store) SaveDevices(ctx context.Context, devices []model.Device) error {
	if len(devices) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback() //nolint:errcheck

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO devices (addr, mac, hostname, first_seen, last_seen, ja4s,
		                     bytes_sent, bytes_recv, flows)
		VALUES (?,?,?,?,?,?,?,?,?)
		ON CONFLICT(addr) DO UPDATE SET
			mac        = excluded.mac,
			hostname   = excluded.hostname,
			first_seen = MIN(devices.first_seen, excluded.first_seen),
			last_seen  = MAX(devices.last_seen,  excluded.last_seen),
			ja4s       = excluded.ja4s,
			bytes_sent = excluded.bytes_sent,
			bytes_recv = excluded.bytes_recv,
			flows      = excluded.flows`)
	if err != nil {
		return err
	}
	defer stmt.Close()

	for i := range devices {
		d := &devices[i]
		ja4s, err := json.Marshal(d.JA4s)
		if err != nil {
			return err
		}
		if _, err := stmt.ExecContext(ctx,
			d.Addr.String(), d.MAC, d.Hostname,
			d.FirstSeen.UTC().UnixNano(), d.LastSeen.UTC().UnixNano(),
			string(ja4s), d.BytesSent, d.BytesRecv, d.Flows,
		); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Devices returns the stored inventory, ordered by address.
func (s *Store) Devices(ctx context.Context) ([]model.Device, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT addr, mac, hostname, first_seen, last_seen, ja4s,
		       bytes_sent, bytes_recv, flows
		FROM devices ORDER BY addr`)
	if err != nil {
		return nil, fmt.Errorf("store: query devices: %w", err)
	}
	defer rows.Close()

	var out []model.Device
	for rows.Next() {
		var (
			d                 model.Device
			addr, ja4s        string
			firstSeen, lastAt int64
		)
		if err := rows.Scan(&addr, &d.MAC, &d.Hostname, &firstSeen, &lastAt,
			&ja4s, &d.BytesSent, &d.BytesRecv, &d.Flows); err != nil {
			return nil, err
		}
		d.Addr = parseAddr(addr)
		d.FirstSeen = time.Unix(0, firstSeen).UTC()
		d.LastSeen = time.Unix(0, lastAt).UTC()
		if err := json.Unmarshal([]byte(ja4s), &d.JA4s); err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// CountAlerts reports how many alerts are stored.
func (s *Store) CountAlerts(ctx context.Context) (int, error) {
	var n int
	err := s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&n)
	return n, err
}

// addrText renders an address for storage, using empty string for the zero
// value so that "no destination" is queryable rather than the literal
// "invalid IP".
func addrText(a netip.Addr) string {
	if !a.IsValid() {
		return ""
	}
	return a.String()
}

func parseAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}
	}
	return a
}
