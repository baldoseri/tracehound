package main

import (
	"context"
	"os"
	"sync/atomic"
	"testing"
	"time"
)

// TestWatchSignalsStaysQuietOnNormalCompletion is the regression test for a
// message that appeared on every successful run.
//
// The earlier version waited on ctx.Done() alone. A signal cancels the context
// and so does the deferred cancel on the ordinary path, so a replay that simply
// finished announced that it was stopping and invited the operator to press
// Ctrl-C again to abort something that had already ended.
func TestWatchSignalsStaysQuietOnNormalCompletion(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	sigc := make(chan os.Signal, 1)

	var announced atomic.Bool
	done := make(chan struct{})
	go func() {
		watchSignals(ctx, sigc, cancel, func() { announced.Store(true) })
		close(done)
	}()

	cancel() // the run finished on its own

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchSignals did not return when the run completed")
	}
	if announced.Load() {
		t.Error("a completed run announced that it was stopping")
	}
}

// TestWatchSignalsActsOnASignal covers the other half: an actual interrupt has
// to cancel the run and say so.
func TestWatchSignalsActsOnASignal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sigc := make(chan os.Signal, 1)

	var announced atomic.Bool
	done := make(chan struct{})
	go func() {
		watchSignals(ctx, sigc, cancel, func() { announced.Store(true) })
		close(done)
	}()

	sigc <- os.Interrupt

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("watchSignals did not return after a signal")
	}
	if ctx.Err() == nil {
		t.Error("the signal did not cancel the run")
	}
	if !announced.Load() {
		t.Error("the signal was handled without telling the operator")
	}
}
