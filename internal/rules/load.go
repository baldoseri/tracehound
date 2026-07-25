package rules

import (
	"embed"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// builtinFS carries the shipped rule pack so that a bare binary detects
// something useful with no configuration at all. Zero-config has to work: a
// tool that requires a rule file before it does anything will be judged as
// broken by anyone evaluating it in the five minutes they have allotted.
//
//go:embed builtin/*.yaml
var builtinFS embed.FS

// Set is a loaded, validated rule pack.
type Set struct {
	order      []*Rule
	byID       map[string]*Rule
	byDetector map[string][]*Rule
	// Origin describes where the pack came from, for the startup banner.
	Origin string
}

// Load reads rules from dir, or the embedded pack when dir is empty.
func Load(dir string) (*Set, error) {
	if strings.TrimSpace(dir) == "" {
		return Builtin()
	}
	return LoadDir(dir)
}

// Builtin returns the embedded rule pack.
func Builtin() (*Set, error) {
	sub, err := fs.Sub(builtinFS, "builtin")
	if err != nil {
		return nil, err
	}
	s, err := loadFS(sub, "built-in")
	if err != nil {
		// A broken embedded pack is a build defect, not a user error.
		return nil, fmt.Errorf("rules: embedded pack is invalid: %w", err)
	}
	return s, nil
}

// LoadDir reads every .yaml and .yml file in dir.
func LoadDir(dir string) (*Set, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("rules: %w", err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("rules: %s is not a directory", dir)
	}
	return loadFS(os.DirFS(dir), dir)
}

func loadFS(fsys fs.FS, origin string) (*Set, error) {
	names, err := fs.Glob(fsys, "*.y*ml")
	if err != nil {
		return nil, err
	}
	slices.Sort(names) // deterministic load order, so errors are reproducible

	s := &Set{
		byID:       make(map[string]*Rule),
		byDetector: make(map[string][]*Rule),
		Origin:     origin,
	}

	for _, name := range names {
		f, err := fsys.Open(name)
		if err != nil {
			return nil, fmt.Errorf("rules: open %s: %w", name, err)
		}
		rules, err := parseFile(f, name)
		f.Close()
		if err != nil {
			return nil, err
		}
		for _, r := range rules {
			if prev, dup := s.byID[r.ID]; dup {
				return nil, fmt.Errorf("rules: %s: duplicate id %s (already defined in %s)", name, r.ID, prev.Source)
			}
			s.byID[r.ID] = r
			s.byDetector[r.Detector] = append(s.byDetector[r.Detector], r)
			s.order = append(s.order, r)
		}
	}

	if len(s.order) == 0 {
		return nil, fmt.Errorf("rules: no rule files found in %s", origin)
	}
	// Fail here, not later. A rule pack that parses but tunes nothing because
	// of a typo is worse than one that refuses to load.
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return s, nil
}

// parseFile reads one file, which may contain several YAML documents.
func parseFile(r io.Reader, name string) ([]*Rule, error) {
	dec := yaml.NewDecoder(r)
	dec.KnownFields(true)

	var out []*Rule
	for i := 0; ; i++ {
		var rule Rule
		err := dec.Decode(&rule)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("rules: %s: %w", name, err)
		}
		rule.Source = name
		if err := rule.validate(); err != nil {
			return nil, fmt.Errorf("rules: %s: %w", name, err)
		}
		out = append(out, &rule)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("rules: %s contains no rules", name)
	}
	return out, nil
}

// All returns the rules in load order.
func (s *Set) All() []*Rule { return s.order }

// Len reports how many rules were loaded.
func (s *Set) Len() int { return len(s.order) }

// Get returns a rule by ID.
func (s *Set) Get(id string) (*Rule, bool) {
	r, ok := s.byID[id]
	return r, ok
}

// Enabled counts the active rules.
func (s *Set) Enabled() int {
	n := 0
	for _, r := range s.order {
		if r.IsEnabled() {
			n++
		}
	}
	return n
}

// ForDetector returns the rules targeting one detector.
func (s *Set) ForDetector(name string) []*Rule { return s.byDetector[name] }

// Dump writes the embedded pack into dir so it can be edited.
//
// This is the on-ramp: an operator who wants to tune something should not have
// to find the rules in a source tree, and should start from exactly what the
// binary is already running rather than from documentation that may have drifted.
func Dump(dir string) ([]string, error) {
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, err
	}
	entries, err := fs.ReadDir(builtinFS, "builtin")
	if err != nil {
		return nil, err
	}

	var written []string
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := builtinFS.ReadFile("builtin/" + e.Name())
		if err != nil {
			return nil, err
		}
		path := filepath.Join(dir, e.Name())
		if _, err := os.Stat(path); err == nil {
			// Never overwrite: the file being dumped over is, by definition,
			// the operator's tuning.
			return written, fmt.Errorf("rules: %s already exists; refusing to overwrite", path)
		}
		if err := os.WriteFile(path, data, 0o644); err != nil {
			return nil, err
		}
		written = append(written, path)
	}
	return written, nil
}
