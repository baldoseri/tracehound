// Command gifgen renders a terminal session into an animated GIF.
//
// It exists so the README demo is reproducible: rather than a screen recording
// that drifts out of date the moment output changes, `make demo-gif` re-runs
// tracehound and re-renders the animation from whatever it actually printed.
//
// This lives in its own module. Drawing text needs golang.org/x/image, and the
// sensor itself has no business carrying a font rasteriser as a dependency just
// because the documentation has a picture in it.
package main

import (
	"bufio"
	"flag"
	"fmt"
	"image"
	"image/color"
	"image/gif"
	"os"
	"os/exec"
	"strings"

	"golang.org/x/image/font"
	"golang.org/x/image/font/basicfont"
	"golang.org/x/image/math/fixed"
)

// Terminal geometry. basicfont.Face7x13 is a 7x13 bitmap face, so a column is
// exactly 7px wide and a row 16px tall including leading.
const (
	cellW   = 7
	cellH   = 16
	padX    = 14
	padY    = 12
	maxCols = 112
)

// A dark palette close to the dashboard's, so the two read as one product.
var (
	colBG     = color.RGBA{0x0b, 0x0f, 0x14, 0xff}
	colChrome = color.RGBA{0x1e, 0x29, 0x36, 0xff}
	colFG     = color.RGBA{0xdb, 0xe4, 0xee, 0xff}
	colDim    = color.RGBA{0x7d, 0x8e, 0xa3, 0xff}
	colFaint  = color.RGBA{0x4d, 0x5c, 0x6e, 0xff}
	colAccent = color.RGBA{0x4d, 0xa3, 0xff, 0xff}
	colPrompt = color.RGBA{0x3f, 0xa9, 0xa0, 0xff}
	colInfo   = color.RGBA{0x5c, 0x7a, 0x99, 0xff}
	colLow    = color.RGBA{0x3f, 0xa9, 0xa0, 0xff}
	colMedium = color.RGBA{0xd9, 0x9a, 0x2b, 0xff}
	colHigh   = color.RGBA{0xe8, 0x64, 0x3c, 0xff}
	colCrit   = color.RGBA{0xe0, 0x41, 0x7a, 0xff}
)

var palette = color.Palette{
	colBG, colChrome, colFG, colDim, colFaint,
	colAccent, colPrompt, colInfo, colLow, colMedium, colHigh, colCrit,
}

// line is one rendered row with its colour.
type line struct {
	text string
	col  color.Color
}

func main() {
	out := flag.String("o", "docs/demo.gif", "output GIF path")
	bin := flag.String("bin", "./bin/tracehound", "tracehound binary to run")
	pcap := flag.String("pcap", "testdata/demo.pcap", "capture to replay")
	rows := flag.Int("rows", 30, "visible terminal rows")
	flag.Parse()

	session, err := record(*bin, *pcap)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gifgen:", err)
		os.Exit(1)
	}

	g := animate(session, *rows)

	if err := os.MkdirAll(dir(*out), 0o755); err != nil {
		fmt.Fprintln(os.Stderr, "gifgen:", err)
		os.Exit(1)
	}
	f, err := os.Create(*out)
	if err != nil {
		fmt.Fprintln(os.Stderr, "gifgen:", err)
		os.Exit(1)
	}
	defer f.Close()

	if err := gif.EncodeAll(f, g); err != nil {
		fmt.Fprintln(os.Stderr, "gifgen:", err)
		os.Exit(1)
	}
	fmt.Printf("wrote %s (%d frames)\n", *out, len(g.Image))
}

// record runs tracehound and returns the session to animate: a typed command
// followed by the program's real output.
func record(bin, pcap string) ([]line, error) {
	cmd := exec.Command(bin, "replay", pcap, "-min-severity", "medium")
	stdout, err := cmd.Output()
	if err != nil {
		// tracehound writes its summary to stderr and findings to stdout; a
		// non-zero exit is a genuine failure worth surfacing.
		return nil, fmt.Errorf("run %s: %w", bin, err)
	}

	session := []line{
		{"$ tracehound replay demo.pcap", colPrompt},
		{"", colFG},
	}

	sc := bufio.NewScanner(strings.NewReader(string(stdout)))
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		t := sc.Text()
		if len(t) > maxCols {
			t = t[:maxCols-1] + "…"
		}
		session = append(session, line{t, colourFor(t)})
	}
	return session, sc.Err()
}

// colourFor picks a colour from the severity tag a line starts with, falling
// back to dim for the continuation lines that carry evidence.
func colourFor(s string) color.Color {
	switch {
	case strings.HasPrefix(s, "[CRITICAL"):
		return colCrit
	case strings.HasPrefix(s, "[HIGH"):
		return colHigh
	case strings.HasPrefix(s, "[MEDIUM"):
		return colMedium
	case strings.HasPrefix(s, "[LOW"):
		return colLow
	case strings.HasPrefix(s, "[INFO"):
		return colInfo
	case strings.Contains(s, "ATT&CK:"):
		return colAccent
	case strings.HasPrefix(s, "$ "):
		return colPrompt
	case strings.TrimSpace(s) == "":
		return colFG
	default:
		return colDim
	}
}

// animate builds the frame sequence: the command types out, then output lines
// appear one at a time, scrolling once the window is full.
func animate(session []line, rows int) *gif.GIF {
	w := padX*2 + maxCols*cellW
	h := padY*2 + rows*cellH

	g := &gif.GIF{LoopCount: 0}

	// Type the command one character at a time; everything after is line-wise.
	cmd := session[0]
	for i := 1; i <= len(cmd.text); i++ {
		typed := []line{{cmd.text[:i], cmd.col}}
		delay := 3
		if i == len(cmd.text) {
			delay = 60 // pause on the complete command before it "runs"
		}
		appendFrame(g, render(w, h, rows, typed, true), delay)
	}

	for n := 2; n <= len(session); n++ {
		visible := session[:n]
		if len(visible) > rows {
			visible = visible[len(visible)-rows:]
		}
		last := session[n-1].text
		delay := 7
		switch {
		case strings.HasPrefix(last, "["):
			delay = 45 // hold on each new finding so it can be read
		case strings.TrimSpace(last) == "":
			delay = 12
		}
		appendFrame(g, render(w, h, rows, visible, false), delay)
	}

	// Hold the final frame, then loop.
	if len(g.Image) > 0 {
		g.Delay[len(g.Delay)-1] = 400
	}
	return g
}

func appendFrame(g *gif.GIF, img *image.Paletted, delay int) {
	g.Image = append(g.Image, img)
	g.Delay = append(g.Delay, delay)
	g.Disposal = append(g.Disposal, gif.DisposalNone)
}

// render draws one frame.
func render(w, h, rows int, visible []line, cursor bool) *image.Paletted {
	img := image.NewPaletted(image.Rect(0, 0, w, h), palette)

	// Background.
	for y := 0; y < h; y++ {
		for x := 0; x < w; x++ {
			img.Set(x, y, colBG)
		}
	}
	// A one-pixel frame so the terminal reads as a window rather than a void.
	for x := 0; x < w; x++ {
		img.Set(x, 0, colChrome)
		img.Set(x, h-1, colChrome)
	}
	for y := 0; y < h; y++ {
		img.Set(0, y, colChrome)
		img.Set(w-1, y, colChrome)
	}

	d := &font.Drawer{Dst: img, Face: basicfont.Face7x13}
	for i, ln := range visible {
		if i >= rows {
			break
		}
		d.Src = image.NewUniform(ln.col)
		// +11 puts the baseline sensibly inside the 16px row.
		d.Dot = fixed.P(padX, padY+i*cellH+11)
		d.DrawString(ln.text)
	}

	if cursor && len(visible) > 0 {
		i := len(visible) - 1
		x := padX + len(visible[i].text)*cellW
		y := padY + i*cellH
		for dy := 2; dy < 14; dy++ {
			for dx := 0; dx < cellW; dx++ {
				if x+dx < w-1 && y+dy < h-1 {
					img.Set(x+dx, y+dy, colFG)
				}
			}
		}
	}
	return img
}

func dir(p string) string {
	if i := strings.LastIndexAny(p, `/\`); i > 0 {
		return p[:i]
	}
	return "."
}
