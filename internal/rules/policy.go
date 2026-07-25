package rules

import (
	"github.com/baldoseri/tracehound/internal/detect"
	"github.com/baldoseri/tracehound/internal/model"
)

// Policy returns the function the detection engine consults before emitting an
// alert. It applies, in order: rule enablement, exceptions, and then any
// metadata the rule overrides.
//
// An alert whose rule ID is not in the pack is allowed through unchanged. That
// is the safe direction: a detector emitting a rule ID nobody has written a
// rule for is a gap in the pack, and silently discarding its findings would
// turn a documentation problem into a blind spot.
func (s *Set) Policy() func(*model.Alert) bool {
	return func(a *model.Alert) bool {
		r, ok := s.byID[a.RuleID]
		if !ok {
			return true
		}
		if !r.IsEnabled() {
			return false
		}
		for i := range r.Exceptions {
			if r.Exceptions[i].Matches(a) {
				return false
			}
		}

		// Severity is a deployment judgement, not a property of the traffic:
		// a port scan is routine on a pentest subnet and urgent in a payment
		// environment. Let the rule override what the detector computed.
		if r.Severity != nil {
			a.Severity = *r.Severity
		}
		// Techniques may be extended without recompiling, which is the whole
		// point of carrying the ATT&CK mapping in the rule file.
		if len(r.Techniques) > 0 {
			a.Techniques = r.Techniques
		}
		return true
	}
}

// Validate decodes every tuning block, surfacing malformed keys and durations.
//
// This runs at load time rather than when the detectors are built. Tuning is
// decoded lazily by the config builders, so without an eager pass a misspelled
// key would go unreported until a detector happened to be constructed — and
// `tracehound rules`, which builds no detectors at all, would cheerfully print
// a rule that is silently broken.
func (s *Set) Validate() error {
	if _, err := s.beaconConfig(); err != nil {
		return err
	}
	if _, err := s.dnsTunnelConfig(); err != nil {
		return err
	}
	if _, err := s.scanConfig(); err != nil {
		return err
	}
	if _, err := s.exfilConfig(); err != nil {
		return err
	}
	if _, err := s.inventoryConfig(); err != nil {
		return err
	}
	return nil
}

// Detectors builds the detector set described by the pack.
//
// Tuning is merged per detector rather than per rule, because several rules can
// share one detector: the vertical and horizontal scan rules are separate
// findings produced by the same code, and each tunes its own threshold.
func (s *Set) Detectors() ([]detect.Detector, *detect.Inventory, error) {
	beacon, err := s.beaconConfig()
	if err != nil {
		return nil, nil, err
	}
	dns, err := s.dnsTunnelConfig()
	if err != nil {
		return nil, nil, err
	}
	scan, err := s.scanConfig()
	if err != nil {
		return nil, nil, err
	}
	exfil, err := s.exfilConfig()
	if err != nil {
		return nil, nil, err
	}
	inv, err := s.inventoryConfig()
	if err != nil {
		return nil, nil, err
	}

	inventory := detect.NewInventory(inv)
	return []detect.Detector{
		detect.NewBeacon(beacon),
		detect.NewDNSTunnel(dns),
		detect.NewScan(scan),
		detect.NewExfil(exfil),
		inventory,
	}, inventory, nil
}

// --- per-detector tuning ----------------------------------------------------
//
// Each struct mirrors a detector's config with YAML names. Zero values mean
// "unset", which is exactly how the detector constructors already treat them,
// so an omitted key falls through to the compiled-in default with no extra
// machinery.

type beaconTuning struct {
	MinConnections int      `yaml:"min_connections"`
	MinInterval    Duration `yaml:"min_interval"`
	MaxInterval    Duration `yaml:"max_interval"`
	Threshold      float64  `yaml:"threshold"`
	History        Duration `yaml:"history"`
	MaxTracked     int      `yaml:"max_tracked"`
}

func (s *Set) beaconConfig() (detect.BeaconConfig, error) {
	var t beaconTuning
	if err := s.decodeTuning("beaconing", &t); err != nil {
		return detect.BeaconConfig{}, err
	}
	return detect.BeaconConfig{
		MinConnections: t.MinConnections,
		MinInterval:    t.MinInterval.Std(),
		MaxInterval:    t.MaxInterval.Std(),
		Threshold:      t.Threshold,
		History:        t.History.Std(),
		MaxTracked:     t.MaxTracked,
	}, nil
}

type dnsTuning struct {
	MinQueries     int      `yaml:"min_queries"`
	Threshold      float64  `yaml:"threshold"`
	History        Duration `yaml:"history"`
	MaxTracked     int      `yaml:"max_tracked"`
	MaxUniqueNames int      `yaml:"max_unique_names"`
}

func (s *Set) dnsTunnelConfig() (detect.DNSTunnelConfig, error) {
	var t dnsTuning
	if err := s.decodeTuning("dns-tunnel", &t); err != nil {
		return detect.DNSTunnelConfig{}, err
	}
	return detect.DNSTunnelConfig{
		MinQueries:     t.MinQueries,
		Threshold:      t.Threshold,
		History:        t.History.Std(),
		MaxTracked:     t.MaxTracked,
		MaxUniqueNames: t.MaxUniqueNames,
	}, nil
}

type scanTuning struct {
	VerticalPorts     int      `yaml:"vertical_ports"`
	HorizontalHosts   int      `yaml:"horizontal_hosts"`
	Window            Duration `yaml:"window"`
	MaxTracked        int      `yaml:"max_tracked"`
	MaxPortsPerTarget int      `yaml:"max_ports_per_target"`
	MaxTargetsPerPort int      `yaml:"max_targets_per_port"`
}

func (s *Set) scanConfig() (detect.ScanConfig, error) {
	var t scanTuning
	if err := s.decodeTuning("port-scan", &t); err != nil {
		return detect.ScanConfig{}, err
	}
	return detect.ScanConfig{
		VerticalPorts:     t.VerticalPorts,
		HorizontalHosts:   t.HorizontalHosts,
		Window:            t.Window.Std(),
		MaxTracked:        t.MaxTracked,
		MaxPortsPerTarget: t.MaxPortsPerTarget,
		MaxTargetsPerPort: t.MaxTargetsPerPort,
	}, nil
}

type exfilTuning struct {
	MinBytesOut uint64  `yaml:"min_bytes_out"`
	MinRatio    float64 `yaml:"min_ratio"`
}

func (s *Set) exfilConfig() (detect.ExfilConfig, error) {
	var t exfilTuning
	if err := s.decodeTuning("exfiltration", &t); err != nil {
		return detect.ExfilConfig{}, err
	}
	return detect.ExfilConfig{MinBytesOut: t.MinBytesOut, MinRatio: t.MinRatio}, nil
}

type inventoryTuning struct {
	MinHostsForRarity        int      `yaml:"min_hosts_for_rarity"`
	MinFingerprintsForRarity int      `yaml:"min_fingerprints_for_rarity"`
	MinSharedFingerprints    int      `yaml:"min_shared_fingerprints"`
	MinObservations          int      `yaml:"min_observations"`
	MinAge                   Duration `yaml:"min_age"`
	MaxDevices               int      `yaml:"max_devices"`
	SilenceNewDevice         bool     `yaml:"silence_new_device"`
}

func (s *Set) inventoryConfig() (detect.InventoryConfig, error) {
	var t inventoryTuning
	if err := s.decodeTuning("inventory", &t); err != nil {
		return detect.InventoryConfig{}, err
	}
	cfg := detect.InventoryConfig{
		MinHostsForRarity:        t.MinHostsForRarity,
		MinFingerprintsForRarity: t.MinFingerprintsForRarity,
		MinSharedFingerprints:    t.MinSharedFingerprints,
		MinObservations:          t.MinObservations,
		MinAge:                   t.MinAge.Std(),
		MaxDevices:               t.MaxDevices,
		SilenceNewDevice:         t.SilenceNewDevice,
	}
	// A disabled new-device rule and a silenced one should behave the same, so
	// the operator does not have to know which knob the tool happens to use.
	if r, ok := s.byID["TH-0006"]; ok && !r.IsEnabled() {
		cfg.SilenceNewDevice = true
	}
	return cfg, nil
}

// decodeTuning merges the tuning blocks of every rule targeting a detector.
func (s *Set) decodeTuning(detector string, into any) error {
	for _, r := range s.byDetector[detector] {
		if err := decodeStrict(&r.Tuning, into); err != nil {
			return &TuningError{Rule: r.ID, Source: r.Source, Err: err}
		}
	}
	return nil
}

// TuningError reports a malformed tuning block, naming the rule so the operator
// knows which file to open.
type TuningError struct {
	Rule   string
	Source string
	Err    error
}

func (e *TuningError) Error() string {
	return "rules: " + e.Source + ": rule " + e.Rule + ": tuning: " + e.Err.Error()
}

func (e *TuningError) Unwrap() error { return e.Err }
