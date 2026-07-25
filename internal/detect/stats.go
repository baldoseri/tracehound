package detect

import (
	"math"
	"slices"
)

// Statistical helpers shared by the detectors.
//
// These are kept together and tested directly because the detection quality of
// the whole tool rests on them: "is this traffic periodic" is entirely a
// question of how you measure dispersion, and picking the wrong measure is how
// a beaconing detector ends up alerting on every NTP client on the network.

// mean returns the arithmetic mean, or 0 for an empty slice.
func mean(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, x := range xs {
		sum += x
	}
	return sum / float64(len(xs))
}

// stdDev returns the population standard deviation.
func stdDev(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := mean(xs)
	var sum float64
	for _, x := range xs {
		d := x - m
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(xs)))
}

// coeffVar is the coefficient of variation: standard deviation as a fraction of
// the mean. It is scale-free, which is what makes it the right periodicity
// measure here — a beacon every 5 seconds and a beacon every 5 hours are
// equally periodic, and a raw standard deviation would say otherwise.
func coeffVar(xs []float64) float64 {
	m := mean(xs)
	if m == 0 {
		return 0
	}
	return stdDev(xs) / m
}

// median returns the median. The input is not modified.
func median(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	s := slices.Clone(xs)
	slices.Sort(s)
	n := len(s)
	if n%2 == 1 {
		return s[n/2]
	}
	return (s[n/2-1] + s[n/2]) / 2
}

// madRatio is the median absolute deviation divided by the median.
//
// It answers the same question as coeffVar but is robust to outliers, which
// matters because real beacons miss check-ins: a host that phones home every
// 60s and skips one gap produces a 120s interval that inflates the standard
// deviation enough to hide the pattern. The median shrugs that off, so scoring
// takes whichever measure is more favourable and lets the other act as a check.
func madRatio(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	med := median(xs)
	if med == 0 {
		return 0
	}
	devs := make([]float64, len(xs))
	for i, x := range xs {
		devs[i] = math.Abs(x - med)
	}
	return median(devs) / med
}

// shannonEntropy returns the Shannon entropy of a string in bits per character.
//
// English text sits near 3.5–4.0, base32/base64-encoded data near 5.0+, and
// random hex near 4.0. Encoded data tunnelled through DNS labels shows up as an
// entropy well above what real hostnames produce.
func shannonEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	var counts [256]int
	for i := 0; i < len(s); i++ {
		counts[s[i]]++
	}
	n := float64(len(s))
	var h float64
	for _, c := range counts {
		if c == 0 {
			continue
		}
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

// clamp constrains x to [lo, hi].
func clamp(x, lo, hi float64) float64 {
	return math.Min(math.Max(x, lo), hi)
}

// normalize maps x from [lo, hi] onto [0, 1], saturating outside the range.
func normalize(x, lo, hi float64) float64 {
	if hi <= lo {
		return 0
	}
	return clamp((x-lo)/(hi-lo), 0, 1)
}

// diffsSeconds converts a sorted series of instants into the gaps between them,
// expressed in seconds.
func diffsSeconds(times []float64) []float64 {
	if len(times) < 2 {
		return nil
	}
	out := make([]float64, 0, len(times)-1)
	for i := 1; i < len(times); i++ {
		d := times[i] - times[i-1]
		if d < 0 {
			d = 0 // out-of-order capture; treat as simultaneous
		}
		out = append(out, d)
	}
	return out
}
