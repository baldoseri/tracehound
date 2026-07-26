// Command readmegen regenerates the sample output blocks in README.md from the
// program itself, so they cannot drift away from what tracehound actually
// prints.
//
// Both blocks used to be hand-written. They were wrong: they showed alert
// titles that had never existed in the code, counts and timestamps from no
// particular run, and omitted evidence fields the tool does emit. That is worse
// than having no samples, because the README's stated standard is that every
// finding is checkable, and the demo capture is deterministic enough for a
// reader to check it in one command and find the document wrong.
//
// This replaces the region between marker comments:
//
//	<!-- readmegen:begin NAME -->
//	...generated...
//	<!-- readmegen:end NAME -->
//
// It always rewrites the file. CI runs it and then "git diff --exit-code
// README.md", which is the same shape as the existing go.mod tidiness check and
// needs no separate verify mode: if the committed README does not match what
// the program prints, the diff is the error message.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
)

func main() {
	var (
		readme = flag.String("readme", "README.md", "README to rewrite")
		bin    = flag.String("bin", "", "tracehound binary (built into a temp dir if empty)")
		pcap   = flag.String("pcap", "testdata/demo.pcap", "demo capture (generated if missing)")
	)
	flag.Parse()

	if err := run(*readme, *bin, *pcap); err != nil {
		fmt.Fprintln(os.Stderr, "readmegen:", err)
		os.Exit(1)
	}
}

func run(readme, bin, pcap string) error {
	root, err := filepath.Abs(filepath.Dir(readme))
	if err != nil {
		return err
	}

	if bin == "" {
		var cleanup func()
		if bin, cleanup, err = buildBinary(root); err != nil {
			return fmt.Errorf("building tracehound: %w", err)
		}
		defer cleanup()
	}
	if bin, err = filepath.Abs(bin); err != nil {
		return err
	}
	// The Makefile passes ./bin/tracehound, which on Windows is on disk as
	// tracehound.exe and is not executable without the suffix.
	if _, err := os.Stat(bin); err != nil && runtime.GOOS == "windows" {
		if _, err2 := os.Stat(bin + ".exe"); err2 == nil {
			bin += ".exe"
		}
	}
	if _, err := os.Stat(filepath.Join(root, pcap)); err != nil {
		// The capture is generated rather than committed, so a clean checkout
		// has to make one before anything can be replayed.
		if _, err := runCmd(root, bin, "gen-demo", pcap); err != nil {
			return fmt.Errorf("generating %s: %w", pcap, err)
		}
	}

	replay, err := replayBlock(root, bin, pcap)
	if err != nil {
		return err
	}
	harness, err := harnessBlock(root)
	if err != nil {
		return err
	}

	src, err := os.ReadFile(readme)
	if err != nil {
		return err
	}
	out := string(normalise(src))
	for _, s := range []struct{ name, body string }{
		{"replay-high", replay},
		{"detection-harness", harness},
	} {
		if out, err = splice(out, s.name, s.body); err != nil {
			return err
		}
	}
	return os.WriteFile(readme, []byte(out), 0o644)
}

// replayBlock is the verbatim high-severity output of a demo replay.
//
// Nothing is filtered. The capture is byte-deterministic (the start time and
// the generator's seed are both pinned), the banner and run summary go to
// stderr, and the version string goes with them, so stdout is stable across
// machines and across releases.
func replayBlock(root, bin, pcap string) (string, error) {
	out, err := runCmd(root, bin, "replay", pcap, "-min-severity", "high")
	if err != nil {
		return "", fmt.Errorf("replaying %s: %w", pcap, err)
	}
	return strings.TrimRight(out, "\n"), nil
}

var (
	testLogPrefix = regexp.MustCompile(`^(\s*)\S+_test\.go:\d+: `)
	testDuration  = regexp.MustCompile(` \(\d+\.\d+s\)$`)
)

// harnessBlock is the detection harness result: what the ground-truth replay
// test found, and the false-positive gate beside it.
//
// Two things are removed, both because they change between runs and would make
// the CI drift check fail for no reason: the "file_test.go:NN:" prefix the
// testing package puts on t.Log output, and the per-test duration. Everything
// that carries meaning is left exactly as the test printed it.
func harnessBlock(root string) (string, error) {
	out, err := runCmd(root, "go", "test", "./internal/pipeline", "-count=1", "-v",
		"-run", "^(TestReplayFindsEveryPlantedBehaviour|TestReplayDoesNotAccuseBenignHosts)$")
	if err != nil {
		return "", fmt.Errorf("running the detection harness: %w\n%s", err, out)
	}

	var keep []string
	for _, line := range strings.Split(out, "\n") {
		switch {
		case strings.HasPrefix(line, "=== RUN"), strings.HasPrefix(line, "=== PAUSE"),
			strings.HasPrefix(line, "=== CONT"), line == "PASS",
			strings.HasPrefix(line, "ok "), strings.TrimSpace(line) == "":
			continue
		}
		line = testLogPrefix.ReplaceAllString(line, "$1")
		line = testDuration.ReplaceAllString(line, "")
		keep = append(keep, strings.TrimRight(line, " \t"))
	}
	if len(keep) == 0 {
		return "", fmt.Errorf("the harness produced no output to show")
	}
	return strings.Join(keep, "\n"), nil
}

// splice replaces the body between a pair of markers, fences included, so the
// generated region is unambiguous and a stray edit inside it is obvious.
func splice(doc, name, body string) (string, error) {
	var (
		begin = "<!-- readmegen:begin " + name + " -->"
		end   = "<!-- readmegen:end " + name + " -->"
	)
	i := strings.Index(doc, begin)
	if i < 0 {
		return "", fmt.Errorf("marker %q not found in the README", begin)
	}
	j := strings.Index(doc[i:], end)
	if j < 0 {
		return "", fmt.Errorf("marker %q has no matching %q", begin, end)
	}
	j += i

	return doc[:i] + begin + "\n\n```\n" + body + "\n```\n\n" + doc[j:], nil
}

// buildBinary compiles the sensor into a temporary directory and returns a
// function that removes it. CI runs this on every pull request, so leaving the
// directory behind would accumulate a copy of the binary per run.
func buildBinary(root string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "readmegen")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { os.RemoveAll(dir) }

	bin := filepath.Join(dir, "tracehound")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if _, err := runCmd(root, "go", "build", "-o", bin, "./cmd/tracehound"); err != nil {
		cleanup()
		return "", nil, err
	}
	return bin, cleanup, nil
}

func runCmd(dir, name string, args ...string) (string, error) {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	// Only stdout is captured. The sensor writes its banner, run summary and
	// version to stderr, none of which belongs in a stable sample.
	if err := cmd.Run(); err != nil {
		return stderr.String(), err
	}
	return string(normalise(stdout.Bytes())), nil
}

// normalise strips carriage returns so a run on Windows and a run on Linux
// produce the same bytes, which is what the CI drift check compares.
func normalise(b []byte) []byte { return bytes.ReplaceAll(b, []byte("\r\n"), []byte("\n")) }
