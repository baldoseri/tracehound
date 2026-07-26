// Command tracehound is a passive network sensor: it reads packets from a
// capture file or an interface, assembles them into flows, fingerprints TLS
// clients, and reports attacker behaviour mapped to MITRE ATT&CK.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"slices"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/baldoseri/tracehound/internal/api"
	"github.com/baldoseri/tracehound/internal/capture"
	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/model"
	"github.com/baldoseri/tracehound/internal/pcapgen"
	"github.com/baldoseri/tracehound/internal/pipeline"
	"github.com/baldoseri/tracehound/internal/rules"
	"github.com/baldoseri/tracehound/internal/store"
)

// version is set for the release archives with -ldflags "-X main.version=...".
// Every other build leaves it empty and resolveVersion recovers what it can.
var version string

// resolveVersion reports the build as precisely as the build itself allows.
//
//	-ldflags "-X main.version=v0.3.0"  ->  "v0.3.0"                 release archives
//	go install ...@v0.3.0              ->  "v0.3.0"                 module version
//	go build from a checkout           ->  "devel (6bc3fd6)"        commit, + ", modified" if dirty
//	no build info at all               ->  "unknown"
//
// The middle case is the one worth the code. It is the install the README
// recommends, ldflags never reach it, and a binary that cannot name its own
// version wastes the first exchange of every bug report filed against it.
func resolveVersion() string {
	if version != "" {
		return version
	}
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	// "(devel)" is what the toolchain records for a build that did not come
	// from a tagged module, so it is a placeholder rather than an answer.
	if v := bi.Main.Version; v != "" && v != "(devel)" {
		return v
	}
	var rev, dirty string
	for _, s := range bi.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = ", modified"
			}
		}
	}
	if rev == "" {
		return "devel"
	}
	if len(rev) > 7 {
		rev = rev[:7]
	}
	return "devel (" + rev + dirty + ")"
}

const usageText = `tracehound - passive network sensor and detection engine

USAGE
  tracehound <command> [flags]

COMMANDS
  replay <file.pcap>   Analyse a capture file
  sniff  -i <iface>    Capture live from an interface (Linux; needs CAP_NET_RAW)
  gen-demo <file.pcap> Write a synthetic capture containing known attacks
  rules                List the loaded detection rules
  query -db <file.db>  Read findings back out of a database
  version              Print the version

Run "tracehound <command> -h" for the flags of a command.

EXAMPLE
  tracehound gen-demo demo.pcap && tracehound replay demo.pcap

TUNING
  tracehound rules -dump ./rules     copy the built-in rules out for editing
  tracehound replay x.pcap -rules ./rules
`

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usageText)
		os.Exit(2)
	}

	var err error
	switch os.Args[1] {
	case "replay":
		err = replayCmd(os.Args[2:])
	case "sniff":
		err = sniffCmd(os.Args[2:])
	case "gen-demo":
		err = genDemoCmd(os.Args[2:])
	case "rules":
		err = rulesCmd(os.Args[2:])
	case "query":
		err = queryCmd(os.Args[2:])
	case "version", "-v", "--version":
		fmt.Printf("tracehound %s\n", resolveVersion())
	case "help", "-h", "--help":
		fmt.Print(usageText)
	default:
		fmt.Fprintf(os.Stderr, "tracehound: unknown command %q\n\n%s", os.Args[1], usageText)
		os.Exit(2)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "tracehound: %v\n", err)
		os.Exit(1)
	}
}

// parseArgs parses flags that may appear before, after, or between positional
// arguments, returning the positionals.
//
// Go's flag package stops at the first non-flag argument, so a perfectly
// natural "tracehound replay capture.pcap -json" would silently treat "-json"
// as a second filename and fail with a confusing message. Parsing in a loop —
// consume flags, take one positional, repeat — accepts either ordering, which
// is what every user expects from a command-line tool.
func parseArgs(fs *flag.FlagSet, args []string) ([]string, error) {
	var positional []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		if fs.NArg() == 0 {
			return positional, nil
		}
		positional = append(positional, fs.Arg(0))
		args = fs.Args()[1:]
	}
}

// commonFlags are shared by the analysis commands.
type commonFlags struct {
	jsonOut     bool
	quiet       bool
	homeNets    string
	tick        time.Duration
	idleTimeout time.Duration
	minSeverity string
	listen      string
	speed       float64
	rulesDir    string
	dbPath      string
	dbRetention time.Duration
	dbMaxAlerts int
}

func (c *commonFlags) register(fs *flag.FlagSet) {
	fs.BoolVar(&c.jsonOut, "json", false, "emit alerts as JSON lines instead of text")
	fs.BoolVar(&c.quiet, "quiet", false, "suppress the run summary")
	fs.StringVar(&c.homeNets, "home-nets", "", "comma-separated CIDRs to treat as internal (default: RFC1918 + link-local)")
	fs.DurationVar(&c.tick, "tick", 30*time.Second, "detector scoring interval, in capture time")
	fs.DurationVar(&c.idleTimeout, "flow-timeout", 2*time.Minute, "how long a flow may be idle before it is closed")
	fs.StringVar(&c.listen, "listen", "", "serve the live dashboard and JSON API on this address (e.g. :8080)")
	fs.Float64Var(&c.speed, "speed", 0, "replay at this multiple of real time (0 = as fast as possible)")
	fs.StringVar(&c.rulesDir, "rules", "", "directory of YAML rules (default: the built-in pack)")
	fs.StringVar(&c.dbPath, "db", "", "persist findings to this SQLite file so they survive a restart")
	fs.DurationVar(&c.dbRetention, "db-retention", 0, "discard stored findings older than this, e.g. 720h (0 = keep everything)")
	fs.IntVar(&c.dbMaxAlerts, "db-max-alerts", 0, "hard ceiling on stored findings, newest kept (0 = no ceiling)")
	// Defaults to low rather than info: the inventory emits an event for every
	// host it sees, which on a scanned subnet is hundreds of lines that bury
	// the findings. They are still counted in the summary, and -min-severity
	// info shows them.
	fs.StringVar(&c.minSeverity, "min-severity", "low", "only report alerts at or above this severity (info|low|medium|high|critical)")
}

func replayCmd(args []string) error {
	fs := flag.NewFlagSet("replay", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: tracehound replay [flags] <file.pcap>\n\nflags:\n")
		fs.PrintDefaults()
	}
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return errors.New("replay requires exactly one capture file")
	}

	src, err := capture.OpenFile(pos[0])
	if err != nil {
		return err
	}
	defer src.Close()

	return run(src, cf, fmt.Sprintf("replaying %s (%s)", pos[0], src.LinkType()))
}

func sniffCmd(args []string) error {
	fs := flag.NewFlagSet("sniff", flag.ExitOnError)
	var cf commonFlags
	cf.register(fs)
	iface := fs.String("i", "", "interface to capture from (required)")
	promisc := fs.Bool("promiscuous", true, "put the interface into promiscuous mode")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: tracehound sniff [flags] -i <interface>\n\nflags:\n")
		fs.PrintDefaults()
	}
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}
	if *iface == "" {
		fs.Usage()
		return errors.New("sniff requires -i <interface>")
	}

	src, err := capture.OpenLive(*iface, *promisc)
	if err != nil {
		return err
	}
	defer src.Close()

	return run(src, cf, fmt.Sprintf("capturing on %s (ctrl-c to stop)", *iface))
}

func genDemoCmd(args []string) error {
	fs := flag.NewFlagSet("gen-demo", flag.ExitOnError)
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: tracehound gen-demo <file.pcap>\n")
	}
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	if len(pos) != 1 {
		fs.Usage()
		return errors.New("gen-demo requires an output path")
	}

	out := pos[0]
	if dir := filepath.Dir(out); dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(out)
	if err != nil {
		return err
	}
	defer f.Close()

	// A fixed start time keeps the generated capture byte-identical between
	// runs, so it can be committed and diffed like any other test fixture.
	start := time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	sum, err := pcapgen.Write(f, start)
	if err != nil {
		return err
	}

	fmt.Printf("wrote %s\n", out)
	fmt.Printf("  %d packets, %s of traffic over %s of capture time\n",
		sum.Packets, humanBytes(sum.Bytes), sum.Duration.Round(time.Second))
	fmt.Printf("  %d hosts\n\n", len(sum.Hosts))
	fmt.Println("planted behaviour (ground truth):")
	for _, e := range sum.Expected {
		dst := ""
		if e.Dst != "" {
			dst = " -> " + e.Dst
		}
		fmt.Printf("  %-8s %s%s\n           %s\n", e.RuleID, e.Src, dst, e.Note)
	}
	fmt.Printf("\nnow run:  tracehound replay %s\n", out)
	return nil
}

// rulesCmd lists the loaded rule pack, or writes the built-in pack to disk so
// it can be edited.
func rulesCmd(args []string) error {
	fs := flag.NewFlagSet("rules", flag.ExitOnError)
	dir := fs.String("rules", "", "directory of YAML rules to load (default: built-in)")
	dump := fs.String("dump", "", "write the built-in rules to this directory and exit")
	verbose := fs.Bool("v", false, "include descriptions and exceptions")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: tracehound rules [-rules <dir>] [-dump <dir>] [-v]\n\nflags:\n")
		fs.PrintDefaults()
	}
	if _, err := parseArgs(fs, args); err != nil {
		return err
	}

	if *dump != "" {
		written, err := rules.Dump(*dump)
		if err != nil {
			return err
		}
		for _, p := range written {
			fmt.Printf("wrote %s\n", p)
		}
		fmt.Printf("\nedit them, then run:  tracehound replay <file.pcap> -rules %s\n", *dump)
		return nil
	}

	pack, err := rules.Load(*dir)
	if err != nil {
		return err
	}

	fmt.Printf("%d rules from %s, %d enabled\n\n", pack.Len(), pack.Origin, pack.Enabled())
	for _, r := range pack.All() {
		state := "enabled"
		if !r.IsEnabled() {
			state = "DISABLED"
		}
		sev := "detector default"
		if r.Severity != nil {
			sev = r.Severity.String()
		}
		fmt.Printf("%-9s %-34s %-13s %-16s %s\n", r.ID, r.Name, r.Detector, sev, state)

		ids := make([]string, len(r.Techniques))
		for i, t := range r.Techniques {
			ids[i] = t.ID
		}
		if len(ids) > 0 {
			fmt.Printf("          ATT&CK: %s\n", strings.Join(ids, ", "))
		}
		if *verbose {
			if d := strings.TrimSpace(r.Description); d != "" {
				fmt.Printf("          %s\n", wrap(d, 88, "          "))
			}
			for _, e := range r.Exceptions {
				fmt.Printf("          except: %s\n", e.Description)
			}
			fmt.Println()
		}
	}
	return nil
}

// run builds the engine and pipeline, consumes the source, and reports.
func run(src capture.Source, cf commonFlags, banner string) error {
	minSev, err := parseSeverity(cf.minSeverity)
	if err != nil {
		return err
	}
	homeNets, err := parseHomeNets(cf.homeNets)
	if err != nil {
		return err
	}

	// Ctrl-C stops the capture cleanly so the summary still prints — a sensor
	// that loses its findings when you stop it is not much use.
	//
	// Deliberately not signal.NotifyContext. That gives back only a context,
	// and a context cancelled by a signal is indistinguishable from one
	// cancelled by the deferred stop on the ordinary path, so anything reacting
	// to cancellation also fires on a run that simply finished. Watching the
	// channel says which happened.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigc := make(chan os.Signal, 1)
	signal.Notify(sigc, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sigc)

	go watchSignals(ctx, sigc, cancel, func() {
		if !cf.quiet {
			fmt.Fprintln(os.Stderr, "\nstopping; press ctrl-c again to abort")
		}
	})

	enc := json.NewEncoder(os.Stdout)
	counts := map[model.Severity]int{}
	total := 0

	// Both are assigned below, before Run starts. The sink runs on the pipeline
	// goroutine, so reading them here without synchronisation is safe.
	var (
		dash *api.Server
		db   *store.Store
	)

	if cf.dbPath != "" {
		var err error
		if db, err = store.Open(cf.dbPath, store.Options{}); err != nil {
			return err
		}
		defer db.Close()

		// Enforced once at startup so an operator who lowers a limit sees it
		// take effect immediately, and then again on a timer for the whole run.
		// See maintain: a limit that only holds between runs does not bound
		// anything on a sensor that is meant to stay up.
		if n, err := applyRetention(ctx, db, cf); err != nil {
			return err
		} else if n > 0 && !cf.quiet {
			fmt.Fprintf(os.Stderr, "retention:  %d older findings discarded\n", n)
		}
	}

	sink := func(a model.Alert) {
		total++
		counts[a.Severity]++
		if db != nil {
			// Never blocks: a full write queue drops and counts rather than
			// stalling packet processing behind a disk.
			db.Enqueue(a)
		}
		if dash != nil {
			dash.Publish(a)
		}
		if a.Severity < minSev {
			return
		}
		if cf.jsonOut {
			_ = enc.Encode(a)
			return
		}
		printAlert(a)
	}

	pack, err := rules.Load(cf.rulesDir)
	if err != nil {
		return err
	}
	// The detectors are built from the rule pack's tuning, and the pack's
	// policy governs which of their findings survive.
	detectors, inventory, err := pack.Detectors()
	if err != nil {
		return err
	}

	cfg := detect.Config{
		HomeNets:      homeNets,
		AlertCooldown: 10 * time.Minute,
		Policy:        pack.Policy(),
	}
	engine := detect.NewEngine(cfg, sink)
	for _, d := range detectors {
		engine.Register(d)
	}

	p := pipeline.New(engine, pipeline.Options{
		FlowIdleTimeout: cf.idleTimeout,
		TickInterval:    cf.tick,
		Detect:          cfg,
		Speed:           cf.speed,
	})

	if !cf.quiet && !cf.jsonOut {
		fmt.Fprintf(os.Stderr, "tracehound %s: %s\n", resolveVersion(), banner)
		fmt.Fprintf(os.Stderr, "detectors:  %s\n", strings.Join(engine.Detectors(), ", "))
		fmt.Fprintf(os.Stderr, "rules:      %d of %d enabled (%s)\n", pack.Enabled(), pack.Len(), pack.Origin)
	}

	if cf.listen != "" {
		dash = api.New(p, engine, inventory, 0)
		// Replay stored findings into the dashboard so a restarted sensor
		// opens showing what it already knows instead of an empty page.
		if db != nil {
			if n, err := seedFromStore(ctx, dash, db); err != nil {
				fmt.Fprintf(os.Stderr, "tracehound: could not load history: %v\n", err)
			} else if n > 0 && !cf.quiet {
				fmt.Fprintf(os.Stderr, "history:    %d earlier findings loaded from %s\n", n, cf.dbPath)
			}
		}
		go func() {
			if err := dash.ListenAndServe(ctx, cf.listen); err != nil {
				fmt.Fprintf(os.Stderr, "tracehound: dashboard: %v\n", err)
			}
		}()
		scope, exposed := listenScope(cf.listen)
		fmt.Fprintf(os.Stderr, "dashboard:  %s (%s)\n", browseURL(cf.listen), scope)
		if exposed {
			fmt.Fprintf(os.Stderr, "            warning: the dashboard and API are unauthenticated and\n")
			fmt.Fprintf(os.Stderr, "            serve this network's inventory. Bind 127.0.0.1 and use an\n")
			fmt.Fprintf(os.Stderr, "            authenticating proxy to reach it from elsewhere.\n")
		}
	}
	if !cf.quiet && !cf.jsonOut {
		fmt.Fprintln(os.Stderr)
	}

	// Periodic upkeep runs alongside the capture and stops with it. A device's
	// byte counters move on every packet, so the inventory is still written on
	// a cadence rather than per change, which would make it the busiest table
	// in the database for no analytical gain.
	if db != nil {
		maintainCtx, stopMaintain := context.WithCancel(ctx)
		defer stopMaintain()
		go maintain(maintainCtx, db, inventory, cf, saveDevicesEvery, applyRetentionEvery)
	}

	stats, err := p.Run(ctx, src)
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	// And once more at the end, so the last observations are not lost to
	// whatever fraction of the interval had not elapsed.
	saveDevices(ctx, db, inventory)

	if !cf.quiet && !cf.jsonOut {
		printSummary(stats, counts, total)
		if db != nil {
			// Flush before reporting, so the numbers describe what is on disk
			// rather than what is still queued.
			if err := db.Close(); err != nil {
				fmt.Fprintf(os.Stderr, "tracehound: closing database: %v\n", err)
			}
			st := db.Stats()
			fmt.Fprintf(os.Stderr, "stored     %d findings in %s", st.Written, cf.dbPath)
			if st.Dropped > 0 || st.Failed > 0 {
				fmt.Fprintf(os.Stderr, " (%d dropped, %d failed)", st.Dropped, st.Failed)
			}
			fmt.Fprintln(os.Stderr)
		}
	}

	// A replay finishes in milliseconds; without this the dashboard would
	// vanish before it could be opened. Keep serving the finished analysis
	// until the operator stops it.
	if cf.listen != "" && ctx.Err() == nil {
		fmt.Fprintf(os.Stderr, "\ncapture complete - dashboard still serving at %s (ctrl-c to stop)\n", browseURL(cf.listen))
		<-ctx.Done()
	}
	return nil
}

// Cadences for the periodic work. Both are far slower than anything on the
// packet path and each does a single indexed statement, so neither competes
// with capture for the disk in any way that matters.
const (
	saveDevicesEvery    = time.Minute
	applyRetentionEvery = 5 * time.Minute
)

// maintain does the work a sensor that stays up has to do repeatedly.
//
// Both of these used to happen once and never again, which is the wrong shape
// for the deployment the flags exist for. The inventory was written only after
// Run returned, so the README's own sequence of "sniff -db" followed by "query
// -db -devices" returned nothing for as long as the sensor was running, and a
// process that was killed rather than stopped lost the inventory entirely.
// Retention ran only at startup, so -db-max-alerts was described as a hard
// ceiling while being nothing of the kind during a run: the compose deployment
// restarts unless stopped, and between restarts the file grew without limit.
//
// The original reasoning for doing this at startup was to keep a long-lived
// sensor from competing with its own packet loop for the disk. That argument
// holds for VACUUM, which is why compaction is still a separate manual command,
// but not for a bounded DELETE on an indexed column once every five minutes.
// The intervals are parameters rather than read from the constants directly so
// a test can drive several cycles without waiting minutes for them.
func maintain(ctx context.Context, db *store.Store, inv *detect.Inventory, cf commonFlags,
	deviceEvery, retentionEvery time.Duration,
) {
	devices := time.NewTicker(deviceEvery)
	defer devices.Stop()
	retention := time.NewTicker(retentionEvery)
	defer retention.Stop()

	for {
		select {
		case <-ctx.Done():
			return

		case <-devices.C:
			saveDevices(ctx, db, inv)

		case <-retention.C:
			if cf.dbRetention <= 0 && cf.dbMaxAlerts <= 0 {
				continue
			}
			// Reported even under -quiet and -json. Those suppress the summary
			// and choose an output format; neither is a request to hide a
			// database that has stopped accepting writes.
			if _, err := applyRetention(ctx, db, cf); err != nil && ctx.Err() == nil {
				fmt.Fprintf(os.Stderr, "tracehound: retention: %v\n", err)
			}
		}
	}
}

// saveDevices persists the asset inventory.
//
// Given its own context rather than the run's, so a shutdown triggered by
// Ctrl-C still gets the inventory written instead of cancelling the write that
// was the point of shutting down cleanly.
func saveDevices(ctx context.Context, db *store.Store, inv *detect.Inventory) {
	if db == nil || inv == nil {
		return
	}
	saveCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)
	defer cancel()
	if err := db.SaveDevices(saveCtx, inv.Devices()); err != nil {
		fmt.Fprintf(os.Stderr, "tracehound: could not save inventory: %v\n", err)
	}
}

// applyRetention trims the store to the configured age and count limits.
//
// Both are applied when both are set: an age cutoff expresses how far back an
// analyst wants to look, while a count ceiling is what actually bounds the file
// during an incident, when one hour can produce more findings than a normal month.
func applyRetention(ctx context.Context, db *store.Store, cf commonFlags) (int64, error) {
	var total int64

	if cf.dbRetention > 0 {
		n, err := db.Prune(ctx, time.Now().Add(-cf.dbRetention))
		if err != nil {
			return total, err
		}
		total += n
	}
	if cf.dbMaxAlerts > 0 {
		n, err := db.PruneToCount(ctx, cf.dbMaxAlerts)
		if err != nil {
			return total, err
		}
		total += n
	}
	return total, nil
}

// seedFromStore loads recent findings into the dashboard's ring buffer.
//
// Loaded newest-first and published in reverse, so the ring ends up in the same
// order a live run would have produced.
func seedFromStore(ctx context.Context, dash *api.Server, db *store.Store) (int, error) {
	history, err := db.Alerts(ctx, store.Query{Limit: api.DefaultMaxAlerts})
	if err != nil {
		return 0, err
	}
	for i := len(history) - 1; i >= 0; i-- {
		dash.Publish(history[i])
	}
	return len(history), nil
}

// queryCmd reads findings back out of a database.
func queryCmd(args []string) error {
	fs := flag.NewFlagSet("query", flag.ExitOnError)
	dbPath := fs.String("db", "", "SQLite file written by -db (required)")
	limit := fs.Int("limit", 50, "maximum findings to show")
	minSev := fs.String("min-severity", "info", "only show alerts at or above this severity")
	rule := fs.String("rule", "", "only show one rule, e.g. TH-0001")
	src := fs.String("src", "", "only show findings from one source address")
	since := fs.Duration("since", 0, "only show findings newer than this, e.g. 24h")
	jsonOut := fs.Bool("json", false, "emit JSON lines instead of text")
	devices := fs.Bool("devices", false, "list the stored asset inventory instead of alerts")
	vacuum := fs.Bool("vacuum", false, "compact the database and exit, returning freed space to the filesystem")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "usage: tracehound query -db <file.db> [flags]\n\nflags:\n")
		fs.PrintDefaults()
	}
	pos, err := parseArgs(fs, args)
	if err != nil {
		return err
	}
	// Accept the database as a bare argument too, since that reads naturally.
	if *dbPath == "" && len(pos) == 1 {
		*dbPath = pos[0]
	}
	if *dbPath == "" {
		fs.Usage()
		return errors.New("query requires -db <file.db>")
	}

	sev, err := parseSeverity(*minSev)
	if err != nil {
		return err
	}

	db, err := store.Open(*dbPath, store.Options{})
	if err != nil {
		return err
	}
	defer db.Close()

	ctx := context.Background()
	enc := json.NewEncoder(os.Stdout)

	if *vacuum {
		before, err := db.SizeOnDisk(ctx)
		if err != nil {
			return err
		}
		if err := db.Vacuum(ctx); err != nil {
			return err
		}
		after, err := db.SizeOnDisk(ctx)
		if err != nil {
			return err
		}
		fmt.Printf("compacted %s: %s -> %s\n", *dbPath, humanBytes(uint64(before)), humanBytes(uint64(after)))
		return nil
	}

	if *devices {
		hosts, err := db.Devices(ctx)
		if err != nil {
			return err
		}
		for _, d := range hosts {
			if *jsonOut {
				_ = enc.Encode(d)
				continue
			}
			// The MAC and the fingerprints both come off the wire.
			fmt.Printf("%-16s %-18s %6d flows  %10s sent  %s\n",
				d.Addr, sanitizeTerminal(orNone(d.MAC)), d.Flows, humanBytes(d.BytesSent),
				sanitizeTerminal(strings.Join(d.JA4s, " ")))
		}
		fmt.Fprintf(os.Stderr, "\n%d devices in %s\n", len(hosts), *dbPath)
		return nil
	}

	q := store.Query{Limit: *limit, MinSeverity: sev, RuleID: *rule, Src: *src}
	if *since > 0 {
		q.Since = time.Now().Add(-*since)
	}
	alerts, err := db.Alerts(ctx, q)
	if err != nil {
		return err
	}
	for _, a := range alerts {
		if *jsonOut {
			_ = enc.Encode(a)
			continue
		}
		printAlert(a)
	}

	total, err := db.CountAlerts(ctx)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "%d shown of %d stored in %s\n", len(alerts), total, *dbPath)
	return nil
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// watchSignals cancels the run on the first signal and stays quiet when the run
// simply finished.
//
// Split out because the difference between those two cases is the whole point
// and it is easy to lose. An earlier version waited on ctx.Done() alone, which
// a signal and an ordinary return both trigger, so every completed replay
// announced that it was stopping and offered a way to abort it.
//
// On a real signal it also unregisters the handler, handing the next one back
// to the runtime. While the handler stays installed, every further Ctrl-C goes
// into a one-deep channel nobody reads and the default behaviour is disabled,
// so a shutdown that is itself stuck cannot be abandoned and the only way out
// is SIGKILL, which loses the run summary and the device inventory.
func watchSignals(ctx context.Context, sigc chan os.Signal, cancel context.CancelFunc, announce func()) {
	select {
	case <-sigc:
		cancel()
		signal.Stop(sigc)
		announce()
	case <-ctx.Done():
	}
}

// browseURL turns a listen address into something clickable in a terminal.
//
// A wildcard bind is rewritten to localhost because that is the URL the
// operator can actually click, not because it describes what is listening.
// Anything printing this must say which it is: see listenScope.
func browseURL(addr string) string {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "http://" + addr
	}
	if host == "" || host == "0.0.0.0" || host == "::" {
		host = "localhost"
	}
	return "http://" + net.JoinHostPort(host, port)
}

// listenScope describes who can reach a listen address.
//
// This exists because browseURL prints "localhost" for a wildcard bind, which
// told the operator the dashboard was on loopback while it was in fact on every
// interface. The dashboard serves the internal address inventory, the MAC
// addresses, the JA4s and a live feed of what has been detected, with no
// authentication, and README's own live-sensor example uses a bare -listen. A
// sensor that quietly publishes its findings to the network it is watching is
// worth one line of output.
func listenScope(addr string) (desc string, exposed bool) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return "unknown interface", true
	}
	switch host {
	case "", "0.0.0.0", "::", "[::]":
		return "all interfaces", true
	}
	if ip, err := netip.ParseAddr(strings.Trim(host, "[]")); err == nil {
		if ip.IsLoopback() {
			return "loopback only", false
		}
		return host, true
	}
	// A hostname. Resolving it to decide would mean a DNS lookup during
	// startup, so assume the worse of the two and let the operator confirm.
	return host, true
}

// sanitizeTerminal escapes control bytes so wire-controlled text cannot drive
// the terminal it is printed to.
//
// Alert text carries bytes chosen by whoever sent the traffic. An SNI is copied
// verbatim out of a ClientHello, and a JA4's ALPN field is one or two bytes
// copied out of one, neither of which is validated. The JA4 case is deliberate
// and must stay that way: the fingerprint's only purpose is to match other
// tooling byte for byte, and FoxIO's reference does not filter these either. So
// an ALPN of "\x1bc" puts ESC c, a full terminal reset, inside a fingerprint
// that "tracehound query -devices" prints straight to a console.
//
// That makes the terminal the right layer to defend, and the only one that
// needs it: the JSON encoder escapes control characters, SQLite takes the
// bytes as parameters, and the dashboard escapes what it renders.
//
// The check is per byte rather than per rune on purpose. Every ASCII control
// character is a single byte below 0x20, DEL is 0x7f, and every byte of a
// multi-byte UTF-8 sequence is 0x80 or above, so legitimate non-ASCII text
// passes through untouched.
func sanitizeTerminal(s string) string {
	dirty := false
	for i := 0; i < len(s); i++ {
		if s[i] < 0x20 || s[i] == 0x7f {
			dirty = true
			break
		}
	}
	if !dirty {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 16)
	for i := 0; i < len(s); i++ {
		if c := s[i]; c < 0x20 || c == 0x7f {
			fmt.Fprintf(&b, `\x%02x`, c)
		} else {
			b.WriteByte(c)
		}
	}
	return b.String()
}

func printAlert(a model.Alert) {
	fmt.Printf("[%-8s] %s  %s\n", strings.ToUpper(a.Severity.String()), a.RuleID, sanitizeTerminal(a.Title))

	where := a.Src.String()
	if a.Dst.IsValid() {
		where += " -> " + a.Dst.String()
		if a.DstPort != 0 {
			where += fmt.Sprintf(":%d", a.DstPort)
		}
	}
	fmt.Printf("             %s  %s  score %.2f\n", a.Time.Format(time.RFC3339), where, a.Score)

	if len(a.Techniques) > 0 {
		ids := make([]string, len(a.Techniques))
		for i, tt := range a.Techniques {
			ids[i] = tt.ID
		}
		fmt.Printf("             ATT&CK: %s\n", strings.Join(ids, ", "))
	}
	if a.Description != "" {
		fmt.Printf("             %s\n", wrap(sanitizeTerminal(a.Description), 92, "             "))
	}
	if len(a.Evidence) > 0 {
		keys := make([]string, 0, len(a.Evidence))
		for k := range a.Evidence {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		parts := make([]string, 0, len(keys))
		for _, k := range keys {
			v := a.Evidence[k]
			if s, ok := v.(string); ok && s == "" {
				continue
			}
			parts = append(parts, fmt.Sprintf("%s=%v", k, v))
		}
		// Escaped after joining rather than per value: evidence holds any, so
		// a nested slice or map would otherwise render through %v unchecked.
		fmt.Printf("             %s\n", wrap(sanitizeTerminal(strings.Join(parts, "  ")), 92, "             "))
	}
	fmt.Println()
}

func printSummary(s pipeline.Stats, counts map[model.Severity]int, total int) {
	fmt.Fprintf(os.Stderr, "---\n")
	fmt.Fprintf(os.Stderr, "packets    %d (%s, %d undecodable)\n", s.Packets, humanBytes(s.Bytes), s.Undecodable)
	if !s.FirstPacket.IsZero() {
		fmt.Fprintf(os.Stderr, "capture    %s .. %s (%s)\n",
			s.FirstPacket.Format(time.RFC3339), s.LastPacket.Format(time.RFC3339),
			s.LastPacket.Sub(s.FirstPacket).Round(time.Second))
	}
	fmt.Fprintf(os.Stderr, "flows      %d seen, %d active at end\n", s.Flow.Created, s.Flow.Active)
	// Servers are reported alongside clients, and the gap between the two is
	// worth seeing rather than hiding: a QUIC flow yields a JA4 but never a
	// JA4S, because the server's reply is encrypted under keys a passive
	// observer never holds. A run where the two numbers are far apart is
	// mostly QUIC, which is a fact about the network, not a fault.
	fmt.Fprintf(os.Stderr, "tls        %d clients, %d servers fingerprinted\n",
		s.Fingerprints, s.ServerFingerprints)
	fmt.Fprintf(os.Stderr, "throughput %.0f packets/sec (%s wall)\n", s.PacketsPerSecond(), s.Elapsed.Round(time.Millisecond))

	order := []model.Severity{model.SevCritical, model.SevHigh, model.SevMedium, model.SevLow, model.SevInfo}
	parts := make([]string, 0, len(order))
	for _, sev := range order {
		if n := counts[sev]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, sev))
		}
	}
	if len(parts) == 0 {
		parts = append(parts, "none")
	}
	fmt.Fprintf(os.Stderr, "alerts     %d (%s), %d suppressed as duplicates, %d filtered by rules\n",
		total, strings.Join(parts, ", "), s.Detect.Suppressed, s.Detect.Filtered)
}

func parseSeverity(s string) (model.Severity, error) {
	var sev model.Severity
	if err := sev.UnmarshalText([]byte(strings.ToLower(strings.TrimSpace(s)))); err != nil {
		return 0, fmt.Errorf("--min-severity: %w (want info|low|medium|high|critical)", err)
	}
	return sev, nil
}

func parseHomeNets(s string) ([]netip.Prefix, error) {
	if strings.TrimSpace(s) == "" {
		return nil, nil // engine substitutes its defaults
	}
	var out []netip.Prefix
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		p, err := netip.ParsePrefix(part)
		if err != nil {
			return nil, fmt.Errorf("--home-nets: %q: %w", part, err)
		}
		out = append(out, p)
	}
	return slices.Clip(out), nil
}

// wrap reflows text to width, indenting continuation lines.
func wrap(s string, width int, indent string) string {
	words := strings.Fields(s)
	if len(words) == 0 {
		return ""
	}
	var b strings.Builder
	lineLen := 0
	for i, w := range words {
		if i > 0 {
			if lineLen+1+len(w) > width {
				b.WriteString("\n" + indent)
				lineLen = 0
			} else {
				b.WriteByte(' ')
				lineLen++
			}
		}
		b.WriteString(w)
		lineLen += len(w)
	}
	return b.String()
}

func humanBytes(n uint64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := uint64(unit), 0
	for v := n / unit; v >= unit && exp < 4; v /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTP"[exp])
}
