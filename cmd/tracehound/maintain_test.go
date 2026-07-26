package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/model"
	"github.com/baldoseri/tracehound/internal/store"
)

// seedInventory drives one packet through an inventory so it holds a device.
func seedInventory(t *testing.T) *detect.Inventory {
	t.Helper()

	inv := detect.NewInventory(detect.InventoryConfig{SilenceNewDevice: true})
	e := detect.NewEngine(detect.Config{}, func(model.Alert) {})
	e.Register(inv)

	p := model.Packet{
		Timestamp:  time.Now(),
		Src:        netip.MustParseAddr("10.0.0.42"),
		Dst:        netip.MustParseAddr("93.184.216.34"),
		SrcPort:    51000,
		DstPort:    443,
		Proto:      model.ProtoTCP,
		TCPFlags:   model.TCPSyn,
		WireLength: 74,
	}
	f := model.Flow{
		Client: p.Src, ClientPort: p.SrcPort,
		Server: p.Dst, ServerPort: p.DstPort,
		Proto: model.ProtoTCP,
	}
	e.Packet(&p, &f, true)

	if len(inv.Devices()) == 0 {
		t.Fatal("the inventory recorded no device, so the rest of the test proves nothing")
	}
	return inv
}

// TestMaintainPersistsTheInventoryDuringARun is the behaviour the README
// already described and the code did not do.
//
// SaveDevices ran only after Run returned, so "sniff -db findings.db" followed
// by "query -db findings.db -devices" returned nothing for as long as the
// sensor was up, and a process killed rather than stopped lost the inventory
// altogether.
func TestMaintainPersistsTheInventoryDuringARun(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "findings.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	inv := seedInventory(t)

	// Nothing has been written yet: this is the state a query would have found.
	if got, err := db.Devices(context.Background()); err != nil {
		t.Fatal(err)
	} else if len(got) != 0 {
		t.Fatalf("store already holds %d devices before maintenance ran", len(got))
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go maintain(ctx, db, inv, commonFlags{}, 10*time.Millisecond, time.Hour)

	deadline := time.Now().Add(10 * time.Second)
	for {
		got, err := db.Devices(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		if len(got) > 0 {
			if got[0].Addr.String() != "10.0.0.42" {
				t.Errorf("persisted device %q, want 10.0.0.42", got[0].Addr)
			}
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("the inventory was never written while the run was in progress")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestMaintainStopsWithItsContext guards against leaving the loop running after
// the capture ends.
func TestMaintainStopsWithItsContext(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "findings.db"), store.Options{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		maintain(ctx, db, seedInventory(t), commonFlags{}, time.Hour, time.Hour)
		close(done)
	}()

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("maintain outlived its context")
	}
}
