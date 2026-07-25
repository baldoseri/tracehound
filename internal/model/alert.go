package model

import (
	"net/netip"
	"time"
)

// Severity ranks an alert for triage. The string forms match the vocabulary
// used by Sigma and most SIEMs so rule packs port across cleanly.
type Severity int

const (
	SevInfo Severity = iota
	SevLow
	SevMedium
	SevHigh
	SevCritical
)

var severityNames = [...]string{"info", "low", "medium", "high", "critical"}

func (s Severity) String() string {
	if s < 0 || int(s) >= len(severityNames) {
		return "unknown"
	}
	return severityNames[s]
}

// MarshalText renders severity as its lowercase name in JSON and YAML.
func (s Severity) MarshalText() ([]byte, error) { return []byte(s.String()), nil }

// UnmarshalText parses a severity name, so rule files can say `severity: high`.
func (s *Severity) UnmarshalText(b []byte) error {
	for i, name := range severityNames {
		if string(b) == name {
			*s = Severity(i)
			return nil
		}
	}
	return &ParseError{Field: "severity", Value: string(b)}
}

// ParseError reports an unrecognised enum value in a rule file.
type ParseError struct {
	Field string
	Value string
}

func (e *ParseError) Error() string { return "invalid " + e.Field + ": " + e.Value }

// Technique is a MITRE ATT&CK technique reference attached to an alert.
//
// Mapping every detection to ATT&CK is not decoration: it is what lets a SOC
// answer "which parts of the kill chain can we actually see?" and it is the
// first thing a detection engineer will look for in a tool like this.
type Technique struct {
	ID     string `json:"id" yaml:"id"`         // e.g. "T1071.004"
	Name   string `json:"name" yaml:"name"`     // e.g. "Application Layer Protocol: DNS"
	Tactic string `json:"tactic" yaml:"tactic"` // e.g. "command-and-control"
}

// Alert is a single detection emitted by a detector.
//
// Evidence carries the detector-specific numbers that justify the verdict --
// the periodicity score, the entropy value, the ports touched. An analyst who
// cannot see why a tool fired will stop trusting the tool, so every detector in
// tracehound is required to show its work.
type Alert struct {
	ID          string      `json:"id"`
	Time        time.Time   `json:"time"`
	RuleID      string      `json:"rule_id"`
	Detector    string      `json:"detector"`
	Title       string      `json:"title"`
	Description string      `json:"description,omitempty"`
	Severity    Severity    `json:"severity"`
	Techniques  []Technique `json:"techniques,omitempty"`

	Src     netip.Addr `json:"src,omitzero"`
	Dst     netip.Addr `json:"dst,omitzero"`
	DstPort uint16     `json:"dst_port,omitempty"`
	Proto   string     `json:"proto,omitempty"`

	// Score is the detector's confidence in [0,1]. It is deliberately separate
	// from Severity: severity is how bad this would be if true, score is how
	// sure we are that it is true.
	Score float64 `json:"score"`

	// Evidence holds the supporting measurements. Values are restricted to
	// JSON-native types so the API can pass them through untouched.
	Evidence map[string]any `json:"evidence,omitempty"`
}

// Common ATT&CK techniques referenced by the built-in detectors, defined once
// so rule authors and detectors cannot drift on naming.
var (
	TechAppLayerWebProto = Technique{ID: "T1071.001", Name: "Application Layer Protocol: Web Protocols", Tactic: "command-and-control"}
	TechAppLayerDNS      = Technique{ID: "T1071.004", Name: "Application Layer Protocol: DNS", Tactic: "command-and-control"}
	TechExfilOverC2      = Technique{ID: "T1041", Name: "Exfiltration Over C2 Channel", Tactic: "exfiltration"}
	TechExfilDNS         = Technique{ID: "T1048.003", Name: "Exfiltration Over Alternative Protocol", Tactic: "exfiltration"}
	TechNetworkScan      = Technique{ID: "T1046", Name: "Network Service Discovery", Tactic: "discovery"}
	TechRemoteSysDiscov  = Technique{ID: "T1018", Name: "Remote System Discovery", Tactic: "discovery"}
	TechEncryptedChannel = Technique{ID: "T1573", Name: "Encrypted Channel", Tactic: "command-and-control"}
	TechNonStandardPort  = Technique{ID: "T1571", Name: "Non-Standard Port", Tactic: "command-and-control"}
	TechProtocolTunnel   = Technique{ID: "T1572", Name: "Protocol Tunneling", Tactic: "command-and-control"}
)
