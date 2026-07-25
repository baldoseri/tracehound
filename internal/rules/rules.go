// Package rules loads the YAML rule pack that governs detection policy.
//
// The split between this package and internal/detect is deliberate. A detector
// answers "is this traffic periodic?" — a question about arithmetic, which
// changes rarely and is worth testing exhaustively. A rule answers "do I care,
// on this network, today?" — a question about policy, which changes constantly
// and belongs in a file an analyst can edit at 2am without a Go toolchain.
//
// Mixing the two is how detection engines become unmaintainable: the tuning
// ends up compiled in, so the only way to silence a false positive is a
// release, and the only way to record why something was silenced is a comment
// nobody reads.
package rules

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/baldoseri/tracehound/internal/model"
)

// KnownDetectors is the set of detector names a rule may target. Rules naming
// anything else are rejected at load time rather than silently ignored — a
// typo in `detector:` would otherwise disable a rule without saying so.
var KnownDetectors = map[string]bool{
	"beaconing":    true,
	"dns-tunnel":   true,
	"port-scan":    true,
	"exfiltration": true,
	"inventory":    true,
}

var idPattern = regexp.MustCompile(`^[A-Z]{2,8}-[0-9]{4}$`)

// Duration is a time.Duration that reads Go duration strings from YAML,
// so a rule can say `max_interval: 6h` instead of a count of nanoseconds.
type Duration time.Duration

// UnmarshalYAML implements yaml.Unmarshaler.
func (d *Duration) UnmarshalYAML(n *yaml.Node) error {
	var s string
	if err := n.Decode(&s); err != nil {
		return fmt.Errorf("line %d: duration must be a string like \"30s\" or \"6h\"", n.Line)
	}
	v, err := time.ParseDuration(s)
	if err != nil {
		return fmt.Errorf("line %d: invalid duration %q: %w", n.Line, s, err)
	}
	if v < 0 {
		return fmt.Errorf("line %d: duration %q must not be negative", n.Line, s)
	}
	*d = Duration(v)
	return nil
}

// Std converts to a standard library duration.
func (d Duration) Std() time.Duration { return time.Duration(d) }

// Exception silences a rule for traffic the operator has already judged.
//
// Every field that is set must match for the exception to apply, so an
// exception is an AND of its conditions. Recording a Description is required:
// an undocumented exception is indistinguishable from a bug six months later.
type Exception struct {
	Description string `yaml:"description"`
	Src         string `yaml:"src,omitempty"`      // IP or CIDR
	Dst         string `yaml:"dst,omitempty"`      // IP or CIDR
	DstPort     uint16 `yaml:"dst_port,omitempty"` // 0 means any
	Domain      string `yaml:"domain,omitempty"`   // suffix match
	JA4         string `yaml:"ja4,omitempty"`      // exact match

	srcPrefix netip.Prefix
	dstPrefix netip.Prefix
}

// compile parses and validates the address fields once, at load time, so
// matching on the hot path is a prefix test rather than a string parse.
func (e *Exception) compile() error {
	if strings.TrimSpace(e.Description) == "" {
		return errors.New("every exception needs a description explaining why it exists")
	}
	if e.Src == "" && e.Dst == "" && e.DstPort == 0 && e.Domain == "" && e.JA4 == "" {
		return errors.New("exception matches everything; set at least one of src, dst, dst_port, domain, ja4")
	}

	var err error
	if e.Src != "" {
		if e.srcPrefix, err = parsePrefix(e.Src); err != nil {
			return fmt.Errorf("src: %w", err)
		}
	}
	if e.Dst != "" {
		if e.dstPrefix, err = parsePrefix(e.Dst); err != nil {
			return fmt.Errorf("dst: %w", err)
		}
	}
	return nil
}

// parsePrefix accepts either a bare address or CIDR notation.
func parsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	return netip.PrefixFrom(a, a.BitLen()), nil
}

// Matches reports whether the alert falls under this exception.
func (e *Exception) Matches(a *model.Alert) bool {
	if e.srcPrefix.IsValid() && !e.srcPrefix.Contains(a.Src.Unmap()) {
		return false
	}
	if e.dstPrefix.IsValid() && !e.dstPrefix.Contains(a.Dst.Unmap()) {
		return false
	}
	if e.DstPort != 0 && a.DstPort != e.DstPort {
		return false
	}
	if e.Domain != "" && !matchesDomain(a, e.Domain) {
		return false
	}
	if e.JA4 != "" && evidenceString(a, "ja4") != e.JA4 {
		return false
	}
	return true
}

// matchesDomain tests the alert's domain evidence as a suffix, so an exception
// for "example.com" also covers "cdn.example.com".
func matchesDomain(a *model.Alert, suffix string) bool {
	suffix = strings.ToLower(strings.TrimPrefix(suffix, "."))
	for _, key := range []string{"domain", "server_name"} {
		v := strings.ToLower(evidenceString(a, key))
		if v == "" {
			continue
		}
		if v == suffix || strings.HasSuffix(v, "."+suffix) {
			return true
		}
	}
	return false
}

func evidenceString(a *model.Alert, key string) string {
	if a.Evidence == nil {
		return ""
	}
	s, _ := a.Evidence[key].(string)
	return s
}

// Rule is one entry in the pack.
type Rule struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Detector    string            `yaml:"detector"`
	Enabled     *bool             `yaml:"enabled,omitempty"`
	Severity    *model.Severity   `yaml:"severity,omitempty"`
	Description string            `yaml:"description,omitempty"`
	References  []string          `yaml:"references,omitempty"`
	Techniques  []model.Technique `yaml:"techniques,omitempty"`
	Tuning      yaml.Node         `yaml:"tuning,omitempty"`
	Exceptions  []Exception       `yaml:"exceptions,omitempty"`

	// Source records which file the rule came from, for error messages.
	Source string `yaml:"-"`
}

// IsEnabled reports whether the rule is active. Absent means enabled: a rule
// pack should not need boilerplate to express the common case.
func (r *Rule) IsEnabled() bool { return r.Enabled == nil || *r.Enabled }

// validate checks a rule in isolation.
func (r *Rule) validate() error {
	switch {
	case strings.TrimSpace(r.ID) == "":
		return errors.New("missing id")
	case !idPattern.MatchString(r.ID):
		return fmt.Errorf("id %q must look like TH-0001", r.ID)
	case strings.TrimSpace(r.Name) == "":
		return errors.New("missing name")
	case strings.TrimSpace(r.Detector) == "":
		return errors.New("missing detector")
	case !KnownDetectors[r.Detector]:
		return fmt.Errorf("unknown detector %q (known: %s)", r.Detector, knownDetectorList())
	}

	for i := range r.Techniques {
		if strings.TrimSpace(r.Techniques[i].ID) == "" {
			return fmt.Errorf("technique %d has no id", i+1)
		}
	}
	for i := range r.Exceptions {
		if err := r.Exceptions[i].compile(); err != nil {
			return fmt.Errorf("exception %d: %w", i+1, err)
		}
	}
	return nil
}

func knownDetectorList() string {
	names := make([]string, 0, len(KnownDetectors))
	for n := range KnownDetectors {
		names = append(names, n)
	}
	// Stable order for deterministic error text.
	for i := 0; i < len(names); i++ {
		for j := i + 1; j < len(names); j++ {
			if names[j] < names[i] {
				names[i], names[j] = names[j], names[i]
			}
		}
	}
	return strings.Join(names, ", ")
}

// decodeStrict decodes a YAML node into a typed struct, rejecting unknown keys.
//
// Strictness matters more here than almost anywhere else in the program: a
// misspelled tuning key that is silently ignored leaves an operator convinced
// they have raised a threshold when they have not, and the tool quietly keeps
// alerting on the thing they thought they had tuned away.
func decodeStrict(n *yaml.Node, into any) error {
	if n == nil || n.IsZero() {
		return nil
	}
	b, err := yaml.Marshal(n)
	if err != nil {
		return err
	}
	dec := yaml.NewDecoder(bytes.NewReader(b))
	dec.KnownFields(true)
	if err := dec.Decode(into); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
