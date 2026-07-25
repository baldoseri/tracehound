// Package flow maintains the live table of bidirectional conversations
// assembled from the packet stream.
//
// The table is the memory of the sensor: detectors ask it "what has this host
// been doing" rather than trying to reason about individual packets. Because it
// sits on the hot path — every single packet touches it — its cost model
// matters more than anything else in the program.
package flow

import (
	"sync"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// Default table tuning. These are deliberately conservative: a mid-range host
// running tracehound on a busy /24 sits comfortably inside them.
const (
	DefaultIdleTimeout = 2 * time.Minute
	DefaultMaxFlows    = 500_000
)

// entry is a flow plus its position in the recency list.
//
// The list is intrusive (prev/next live inside the entry) so that touching a
// flow costs no allocation and no map lookup beyond the one we already did.
type entry struct {
	flow       model.Flow
	prev, next *entry
}

// Options configures a Table.
type Options struct {
	// IdleTimeout is how long a flow may go unobserved before it is reaped.
	IdleTimeout time.Duration
	// MaxFlows caps table size. When exceeded, the least-recently-touched
	// flows are evicted early. This bounds memory against a scan or a flood
	// that would otherwise create millions of one-packet flows.
	MaxFlows int
}

func (o Options) withDefaults() Options {
	if o.IdleTimeout <= 0 {
		o.IdleTimeout = DefaultIdleTimeout
	}
	if o.MaxFlows <= 0 {
		o.MaxFlows = DefaultMaxFlows
	}
	return o
}

// Table is a concurrent map of active flows ordered by recency.
//
// Expiry is the interesting part. The obvious implementation scans every entry
// on a timer, which is O(n) per sweep and degrades exactly when the table is
// large — i.e. during the scan or flood you most want to detect. Instead the
// table threads every entry onto a doubly-linked list ordered by touch time.
// Reaping then pops from the head while the head is too old, costing O(expired)
// rather than O(total), and capacity eviction is the same pop from the head.
//
// The ordering assumption is that packet timestamps are non-decreasing. That
// holds for live capture and for well-formed PCAPs; badly reordered input can
// leave a flow reaped slightly early, which is harmless (it is re-created on
// the next packet) and is why Reap compares against LastSeen rather than
// trusting list position alone.
type Table struct {
	mu    sync.RWMutex
	flows map[model.FlowKey]*entry
	head  *entry // least recently touched
	tail  *entry // most recently touched
	opts  Options

	// Counters exposed via Stats.
	created uint64
	evicted uint64
	expired uint64
}

// New returns an empty flow table.
func New(opts Options) *Table {
	return &Table{
		flows: make(map[model.FlowKey]*entry),
		opts:  opts.withDefaults(),
	}
}

// Stats reports table counters for the /healthz endpoint and benchmarks.
type Stats struct {
	Active  int    `json:"active"`
	Created uint64 `json:"created"`
	Expired uint64 `json:"expired"`
	Evicted uint64 `json:"evicted"`
}

// Stats returns a snapshot of the table counters.
func (t *Table) Stats() Stats {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return Stats{
		Active:  len(t.flows),
		Created: t.created,
		Expired: t.expired,
		Evicted: t.evicted,
	}
}

// Len returns the number of active flows.
func (t *Table) Len() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.flows)
}

// Observe folds a packet into its flow, creating the flow if needed.
//
// The returned pointer is owned by the table and is only safe to read while the
// caller is still on the packet-processing goroutine; callers that need to keep
// a flow must copy it. isNew reports whether this packet created the flow,
// which detectors use as the "new conversation" signal.
func (t *Table) Observe(p *model.Packet) (f *model.Flow, isNew bool) {
	key, _ := model.KeyFor(p)

	t.mu.Lock()
	defer t.mu.Unlock()

	e, ok := t.flows[key]
	if !ok {
		e = &entry{}
		e.flow.Key = key
		t.flows[key] = e
		t.created++
		isNew = true
	} else {
		t.unlink(e)
	}
	e.flow.Observe(p)
	t.pushBack(e)

	// Evict from the cold end if we are over capacity. Done inline rather than
	// on the reaper's schedule so a burst cannot outrun the bound.
	for len(t.flows) > t.opts.MaxFlows && t.head != nil && t.head != e {
		victim := t.head
		t.unlink(victim)
		delete(t.flows, victim.flow.Key)
		t.evicted++
	}

	return &e.flow, isNew
}

// Reap removes every flow untouched since now-IdleTimeout and returns them.
//
// Returned flows are copies, so the caller may hand them to detectors or
// storage on another goroutine without racing the table.
func (t *Table) Reap(now time.Time) []model.Flow {
	cutoff := now.Add(-t.opts.IdleTimeout)

	t.mu.Lock()
	defer t.mu.Unlock()

	var out []model.Flow
	for t.head != nil && !t.head.flow.LastSeen.After(cutoff) {
		e := t.head
		t.unlink(e)
		delete(t.flows, e.flow.Key)
		t.expired++
		out = append(out, e.flow)
	}
	return out
}

// Drain removes and returns every remaining flow. Used at end-of-capture so
// that flows still open when a PCAP runs out are not silently dropped.
func (t *Table) Drain() []model.Flow {
	t.mu.Lock()
	defer t.mu.Unlock()

	out := make([]model.Flow, 0, len(t.flows))
	for e := t.head; e != nil; e = e.next {
		out = append(out, e.flow)
	}
	t.flows = make(map[model.FlowKey]*entry)
	t.head, t.tail = nil, nil
	return out
}

// Snapshot copies the active flows, most recently touched first. limit <= 0
// means no limit. This backs the API's flow listing.
func (t *Table) Snapshot(limit int) []model.Flow {
	t.mu.RLock()
	defer t.mu.RUnlock()

	n := len(t.flows)
	if limit > 0 && limit < n {
		n = limit
	}
	out := make([]model.Flow, 0, n)
	for e := t.tail; e != nil && len(out) < n; e = e.prev {
		out = append(out, e.flow)
	}
	return out
}

// --- intrusive list helpers; all callers must hold t.mu ---

func (t *Table) unlink(e *entry) {
	if e.prev != nil {
		e.prev.next = e.next
	} else if t.head == e {
		t.head = e.next
	}
	if e.next != nil {
		e.next.prev = e.prev
	} else if t.tail == e {
		t.tail = e.prev
	}
	e.prev, e.next = nil, nil
}

func (t *Table) pushBack(e *entry) {
	e.prev, e.next = t.tail, nil
	if t.tail != nil {
		t.tail.next = e
	}
	t.tail = e
	if t.head == nil {
		t.head = e
	}
}
