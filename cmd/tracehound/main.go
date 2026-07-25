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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

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

		// Retention is enforced before the run rather than during it, so a
		// long-lived sensor never competes with its own packet loop for the
		// disk, and so an operator who lowers the limit sees it take effect on
		// the next start rather than at some unpredictable later moment.
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
		fmt.Fprintf(os.Stderr, "dashboard:  %s\n", browseURL(cf.listen))
	}
	if !cf.quiet && !cf.jsonOut {
		fmt.Fprintln(os.Stderr)
	}

	stats, err := p.Run(ctx, src)
	if err != nil && !errors.Is(err, context.Canceled) {
		return err
	}

	// The inventory is written once, at the end. A device's byte counters move
	// on every packet, so persisting each change would make this the busiest
	// table in the database for no analytical gain.
	if db != nil {
		saveCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		if err := db.SaveDevices(saveCtx, inventory.Devices()); err != nil {
			fmt.Fprintf(os.Stderr, "tracehound: could not save inventory: %v\n", err)
		}
		cancel()
	}

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
			fmt.Printf("%-16s %-18s %6d flows  %10s sent  %s\n",
				d.Addr, orNone(d.MAC), d.Flows, humanBytes(d.BytesSent),
				strings.Join(d.JA4s, " "))
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

// browseURL turns a listen address into something clickable in a terminal.
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

func printAlert(a model.Alert) {
	fmt.Printf("[%-8s] %s  %s\n", strings.ToUpper(a.Severity.String()), a.RuleID, a.Title)

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
		fmt.Printf("             %s\n", wrap(a.Description, 92, "             "))
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
		fmt.Printf("             %s\n", wrap(strings.Join(parts, "  "), 92, "             "))
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
