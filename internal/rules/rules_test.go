package rules

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// --- the shipped pack -------------------------------------------------------

// TestBuiltinPackIsValid is the guard that matters most for the embedded rules:
// they are compiled into the binary, so a malformed one is a shipping defect
// that no amount of user testing would catch first.
func TestBuiltinPackIsValid(t *testing.T) {
	pack, err := Builtin()
	if err != nil {
		t.Fatalf("built-in pack failed to load: %v", err)
	}
	if pack.Len() == 0 {
		t.Fatal("built-in pack is empty")
	}

	seen := map[string]bool{}
	for _, r := range pack.All() {
		if seen[r.ID] {
			t.Errorf("duplicate rule id %s", r.ID)
		}
		seen[r.ID] = true

		if !KnownDetectors[r.Detector] {
			t.Errorf("%s targets unknown detector %q", r.ID, r.Detector)
		}
		if strings.TrimSpace(r.Description) == "" {
			t.Errorf("%s has no description; an operator reading an alert has nothing to go on", r.ID)
		}
		for _, e := range r.Exceptions {
			if strings.TrimSpace(e.Description) == "" {
				t.Errorf("%s has an undocumented exception", r.ID)
			}
		}
	}

	// Every rule the detectors can emit must exist in the pack, or its alerts
	// would pass through unpoliced.
	for _, id := range []string{"TH-0001", "TH-0002", "TH-0003", "TH-0004", "TH-0005", "TH-0006", "TH-0007"} {
		if _, ok := pack.Get(id); !ok {
			t.Errorf("built-in pack is missing %s", id)
		}
	}
}

// TestBuiltinTuningMatchesDefaults checks that the shipped YAML does not
// silently change behaviour relative to the compiled-in defaults. If a value
// here drifts, one of the two is wrong and the operator cannot tell which.
func TestBuiltinTuningMatchesDefaults(t *testing.T) {
	pack, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}

	beacon, err := pack.beaconConfig()
	if err != nil {
		t.Fatal(err)
	}
	if beacon.MinConnections != 8 || beacon.Threshold != 0.75 {
		t.Errorf("beacon tuning = %+v", beacon)
	}
	if beacon.MaxInterval != 6*time.Hour {
		t.Errorf("beacon MaxInterval = %v, want 6h", beacon.MaxInterval)
	}

	// TH-0003 and TH-0004 drive one detector; their tuning must merge rather
	// than one overwriting the other with a zero value.
	scan, err := pack.scanConfig()
	if err != nil {
		t.Fatal(err)
	}
	if scan.VerticalPorts != 20 {
		t.Errorf("VerticalPorts = %d, want 20 (from TH-0003)", scan.VerticalPorts)
	}
	if scan.HorizontalHosts != 25 {
		t.Errorf("HorizontalHosts = %d, want 25 (from TH-0004)", scan.HorizontalHosts)
	}
	if scan.Window != 5*time.Minute {
		t.Errorf("Window = %v, want 5m", scan.Window)
	}
}

// --- loading and validation -------------------------------------------------

func writePack(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

func TestLoadRejectsBadRules(t *testing.T) {
	cases := []struct {
		name string
		yaml string
		want string
	}{
		{
			name: "unknown detector",
			yaml: "id: TH-9001\nname: x\ndetector: telepathy\n",
			want: "unknown detector",
		},
		{
			name: "malformed id",
			yaml: "id: beacon\nname: x\ndetector: beaconing\n",
			want: "must look like",
		},
		{
			name: "missing name",
			yaml: "id: TH-9001\ndetector: beaconing\n",
			want: "missing name",
		},
		{
			name: "unknown top-level key",
			yaml: "id: TH-9001\nname: x\ndetector: beaconing\nsevrity: high\n",
			want: "field sevrity not found",
		},
		{
			// The failure this prevents: an operator raises a threshold, the key
			// is misspelled, the tool silently keeps the old value, and they
			// believe they have tuned something.
			name: "unknown tuning key",
			yaml: "id: TH-9001\nname: x\ndetector: beaconing\ntuning:\n  treshold: 0.9\n",
			want: "not found",
		},
		{
			name: "bad duration",
			yaml: "id: TH-9001\nname: x\ndetector: beaconing\ntuning:\n  history: 6 hours\n",
			want: "invalid duration",
		},
		{
			name: "exception with no conditions",
			yaml: "id: TH-9001\nname: x\ndetector: beaconing\nexceptions:\n  - description: everything\n",
			want: "matches everything",
		},
		{
			name: "exception with no description",
			yaml: "id: TH-9001\nname: x\ndetector: beaconing\nexceptions:\n  - src: 10.0.0.1\n",
			want: "needs a description",
		},
		{
			name: "bad CIDR",
			yaml: "id: TH-9001\nname: x\ndetector: beaconing\nexceptions:\n  - description: y\n    src: 10.0.0.0/99\n",
			want: "src:",
		},
		{
			name: "bad severity",
			yaml: "id: TH-9001\nname: x\ndetector: beaconing\nseverity: catastrophic\n",
			want: "severity",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := writePack(t, map[string]string{"r.yaml": tc.yaml})
			_, err := LoadDir(dir)
			if err == nil {
				t.Fatalf("expected an error mentioning %q, got none", tc.want)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error = %q, want it to mention %q", err, tc.want)
			}
		})
	}
}

func TestLoadRejectsDuplicateIDs(t *testing.T) {
	dir := writePack(t, map[string]string{
		"a.yaml": "id: TH-9001\nname: first\ndetector: beaconing\n",
		"b.yaml": "id: TH-9001\nname: second\ndetector: beaconing\n",
	})
	_, err := LoadDir(dir)
	if err == nil || !strings.Contains(err.Error(), "duplicate id") {
		t.Fatalf("error = %v, want a duplicate-id complaint", err)
	}
}

func TestLoadMultipleDocumentsInOneFile(t *testing.T) {
	dir := writePack(t, map[string]string{
		"pack.yaml": "id: TH-9001\nname: a\ndetector: beaconing\n---\nid: TH-9002\nname: b\ndetector: dns-tunnel\n",
	})
	pack, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if pack.Len() != 2 {
		t.Errorf("loaded %d rules, want 2", pack.Len())
	}
}

func TestLoadEmptyDirIsAnError(t *testing.T) {
	if _, err := LoadDir(t.TempDir()); err == nil {
		t.Error("an empty rules directory loaded successfully; that is almost certainly a wrong -rules path")
	}
}

// --- policy -----------------------------------------------------------------

func alert(rule string, src, dst string, port uint16) *model.Alert {
	a := &model.Alert{RuleID: rule, Severity: model.SevMedium, DstPort: port}
	if src != "" {
		a.Src = netip.MustParseAddr(src)
	}
	if dst != "" {
		a.Dst = netip.MustParseAddr(dst)
	}
	return a
}

func TestPolicyDisabledRuleDropsAlerts(t *testing.T) {
	dir := writePack(t, map[string]string{
		"r.yaml": "id: TH-0001\nname: x\ndetector: beaconing\nenabled: false\n",
	})
	pack, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if pack.Policy()(alert("TH-0001", "10.0.0.5", "1.1.1.1", 443)) {
		t.Error("a disabled rule still emitted")
	}
}

func TestPolicyPassesUnknownRuleIDs(t *testing.T) {
	pack, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	// A detector emitting an ID nobody wrote a rule for is a gap in the pack.
	// Dropping it would turn a documentation problem into a blind spot.
	if !pack.Policy()(alert("TH-9999", "10.0.0.5", "1.1.1.1", 443)) {
		t.Error("an alert with no matching rule was dropped")
	}
}

func TestPolicyExceptions(t *testing.T) {
	dir := writePack(t, map[string]string{
		"r.yaml": `
id: TH-0001
name: x
detector: beaconing
exceptions:
  - description: subnet allowlist
    src: 10.0.90.0/24
  - description: exact host and port
    dst: 203.0.113.9
    dst_port: 8443
  - description: domain suffix
    domain: updates.example.com
  - description: known tool fingerprint
    ja4: t13d1516h2_aaaa_bbbb
`,
	})
	pack, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	policy := pack.Policy()

	tests := []struct {
		name  string
		a     *model.Alert
		allow bool
	}{
		{"inside allowlisted subnet", alert("TH-0001", "10.0.90.7", "1.1.1.1", 443), false},
		{"outside allowlisted subnet", alert("TH-0001", "10.0.91.7", "1.1.1.1", 443), true},
		{"exact host and port", alert("TH-0001", "10.0.0.5", "203.0.113.9", 8443), false},
		{"right host wrong port", alert("TH-0001", "10.0.0.5", "203.0.113.9", 443), true},
	}
	for _, tc := range tests {
		if got := policy(tc.a); got != tc.allow {
			t.Errorf("%s: allowed = %v, want %v", tc.name, got, tc.allow)
		}
	}

	// Domain exceptions match as a suffix, so a subdomain is covered too.
	for _, domain := range []string{"updates.example.com", "eu.updates.example.com"} {
		a := alert("TH-0001", "10.0.0.5", "1.1.1.1", 443)
		a.Evidence = map[string]any{"domain": domain}
		if policy(a) {
			t.Errorf("domain %q was not covered by the suffix exception", domain)
		}
	}
	// A domain that merely ends in the same letters must not match.
	a := alert("TH-0001", "10.0.0.5", "1.1.1.1", 443)
	a.Evidence = map[string]any{"domain": "notupdates.example.com"}
	if !policy(a) {
		t.Error("suffix matching was too loose: notupdates.example.com should not match updates.example.com")
	}

	fp := alert("TH-0001", "10.0.0.5", "1.1.1.1", 443)
	fp.Evidence = map[string]any{"ja4": "t13d1516h2_aaaa_bbbb"}
	if policy(fp) {
		t.Error("ja4 exception did not match")
	}
}

func TestPolicyOverridesSeverityAndTechniques(t *testing.T) {
	dir := writePack(t, map[string]string{
		"r.yaml": `
id: TH-0001
name: x
detector: beaconing
severity: critical
techniques:
  - id: T9999
    name: Custom
    tactic: impact
`,
	})
	pack, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}

	a := alert("TH-0001", "10.0.0.5", "1.1.1.1", 443)
	a.Techniques = []model.Technique{{ID: "T1071.001"}}
	if !pack.Policy()(a) {
		t.Fatal("alert was dropped")
	}
	if a.Severity != model.SevCritical {
		t.Errorf("severity = %s, want critical", a.Severity)
	}
	if len(a.Techniques) != 1 || a.Techniques[0].ID != "T9999" {
		t.Errorf("techniques = %+v, want the rule's override", a.Techniques)
	}
}

// --- tuning reaches the detectors -------------------------------------------

func TestTuningOverridesDefaults(t *testing.T) {
	dir := writePack(t, map[string]string{
		"r.yaml": `
id: TH-0001
name: x
detector: beaconing
tuning:
  min_connections: 42
  threshold: 0.9
  max_interval: 90m
`,
	})
	pack, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pack.beaconConfig()
	if err != nil {
		t.Fatal(err)
	}
	if cfg.MinConnections != 42 {
		t.Errorf("MinConnections = %d, want 42", cfg.MinConnections)
	}
	if cfg.Threshold != 0.9 {
		t.Errorf("Threshold = %v, want 0.9", cfg.Threshold)
	}
	if cfg.MaxInterval != 90*time.Minute {
		t.Errorf("MaxInterval = %v, want 90m", cfg.MaxInterval)
	}
	// Omitted keys must stay zero so the detector applies its own default,
	// rather than being silently pinned to zero by the rule file.
	if cfg.MinInterval != 0 {
		t.Errorf("MinInterval = %v, want 0 so the detector default applies", cfg.MinInterval)
	}
}

func TestDisablingNewDeviceRuleSilencesInventory(t *testing.T) {
	dir := writePack(t, map[string]string{
		"r.yaml": "id: TH-0006\nname: x\ndetector: inventory\nenabled: false\n",
	})
	pack, err := LoadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := pack.inventoryConfig()
	if err != nil {
		t.Fatal(err)
	}
	if !cfg.SilenceNewDevice {
		t.Error("disabling TH-0006 did not silence the inventory's new-device events")
	}
}

func TestDetectorsBuildsEverything(t *testing.T) {
	pack, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	detectors, inventory, err := pack.Detectors()
	if err != nil {
		t.Fatal(err)
	}
	if len(detectors) != 5 {
		t.Errorf("built %d detectors, want 5", len(detectors))
	}
	if inventory == nil {
		t.Error("inventory was not returned; the API needs it for the device table")
	}
	names := map[string]bool{}
	for _, d := range detectors {
		names[d.Name()] = true
	}
	for want := range KnownDetectors {
		if !names[want] {
			t.Errorf("detector %q was not built", want)
		}
	}
}

// --- dump -------------------------------------------------------------------

func TestDumpWritesAndRefusesToOverwrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "rules")

	written, err := Dump(dir)
	if err != nil {
		t.Fatalf("dump: %v", err)
	}
	if len(written) == 0 {
		t.Fatal("dump wrote nothing")
	}

	// What was written must load cleanly, or the on-ramp is broken.
	pack, err := LoadDir(dir)
	if err != nil {
		t.Fatalf("dumped pack does not load: %v", err)
	}
	builtin, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	if pack.Len() != builtin.Len() {
		t.Errorf("dumped %d rules, built-in has %d", pack.Len(), builtin.Len())
	}

	// A second dump would overwrite an operator's tuning, so it must refuse.
	if _, err := Dump(dir); err == nil {
		t.Error("dump overwrote an existing rules directory")
	}
}
