package main

import (
	"regexp"
	"strings"
	"testing"
)

// TestResolveVersionPrefersLdflags covers the release archives, where the build
// script passes -X main.version and that value must be reported verbatim.
func TestResolveVersionPrefersLdflags(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = "v9.9.9"
	if got := resolveVersion(); got != "v9.9.9" {
		t.Errorf("resolveVersion() = %q, want the ldflags value v9.9.9", got)
	}
}

// TestResolveVersionWithoutLdflags covers every other build. The exact answer
// depends on how the test binary was produced, so this asserts the properties
// that must hold in all of them rather than one literal string: it never panics,
// never returns empty, and never leaks the toolchain's "(devel)" placeholder to
// a user.
func TestResolveVersionWithoutLdflags(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = ""
	got := resolveVersion()

	if got == "" {
		t.Fatal("resolveVersion() returned an empty string")
	}
	if strings.Contains(got, "(devel)") {
		t.Errorf("resolveVersion() = %q, which leaks the toolchain placeholder", got)
	}
	if strings.TrimSpace(got) != got {
		t.Errorf("resolveVersion() = %q, which has surrounding whitespace", got)
	}

	// Whatever branch was taken, the shape has to be one a human can read back
	// over the phone: a module version, a short commit, or a bare fallback.
	ok := regexp.MustCompile(`^(v[0-9]|devel( \([0-9a-f]{7}(, modified)?\))?$|unknown$)`)
	if !ok.MatchString(got) {
		t.Errorf("resolveVersion() = %q, which matches none of the expected forms", got)
	}
	t.Logf("resolveVersion() = %q for this build", got)
}

// TestResolveVersionShortensRevision guards the one piece of formatting that is
// easy to get wrong: a git revision is 40 characters and printing all of it in
// a banner is noise.
func TestResolveVersionShortensRevision(t *testing.T) {
	old := version
	t.Cleanup(func() { version = old })

	version = ""
	got := resolveVersion()
	if !strings.HasPrefix(got, "devel (") {
		t.Skipf("this build has no VCS stamp to shorten (got %q)", got)
	}
	rev := strings.TrimSuffix(strings.TrimPrefix(got, "devel ("), ")")
	rev = strings.TrimSuffix(rev, ", modified")
	if len(rev) != 7 {
		t.Errorf("revision %q is %d characters, want 7", rev, len(rev))
	}
}
