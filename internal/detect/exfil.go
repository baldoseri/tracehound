package detect

import (
	"fmt"
	"time"

	"github.com/baldoseri/tracehound/internal/model"
)

// RuleExfil is the rule identifier for large asymmetric outbound transfers.
const RuleExfil = "TH-0005"

// ExfilConfig tunes the data-transfer detector.
type ExfilConfig struct {
	// MinBytesOut is the floor below which a transfer is not worth reporting
	// regardless of how lopsided it is.
	MinBytesOut uint64
	// MinRatio is how many times more data must leave than arrive. Normal
	// client traffic is heavily inbound — you download far more than you
	// upload — so inverting that ratio is the signal.
	MinRatio float64
}

// DefaultExfilConfig returns thresholds tuned to catch a meaningful staging
// transfer without firing on video calls or routine backups.
func DefaultExfilConfig() ExfilConfig {
	return ExfilConfig{
		MinBytesOut: 10 << 20, // 10 MiB
		MinRatio:    20,
	}
}

// Exfil flags flows that move a lot of data out of the network.
//
// This detector is deliberately simple, because the sophisticated version is
// not better — it is just harder to explain. The value is in the direction
// asymmetry: a client that uploads 200 MB while downloading 2 MB has inverted
// the shape of ordinary traffic, and that is worth an analyst's attention
// whether the destination is an attacker's server or an unsanctioned file host.
//
// It runs on flow close rather than per packet so that the verdict is made on
// the complete conversation, which avoids alerting mid-transfer on something
// that turns out to be a symmetric sync.
type Exfil struct {
	cfg ExfilConfig
}

// NewExfil returns a data-transfer detector. A zero config selects the defaults.
func NewExfil(cfg ExfilConfig) *Exfil {
	d := DefaultExfilConfig()
	if cfg.MinBytesOut > 0 {
		d.MinBytesOut = cfg.MinBytesOut
	}
	if cfg.MinRatio > 0 {
		d.MinRatio = cfg.MinRatio
	}
	return &Exfil{cfg: d}
}

// Name implements Detector.
func (e *Exfil) Name() string { return "exfiltration" }

// OnFlowClosed evaluates a completed conversation.
func (e *Exfil) OnFlowClosed(c *Context, f *model.Flow) {
	// Outbound only: a server receiving a large upload is doing its job.
	if !c.Cfg.IsInternal(f.Client) || c.Cfg.IsInternal(f.Server) {
		return
	}
	if f.BytesToServer < e.cfg.MinBytesOut {
		return
	}

	// Guard the division: a flow with no inbound bytes at all is maximally
	// asymmetric, not undefined.
	inbound := f.BytesToClient
	if inbound == 0 {
		inbound = 1
	}
	ratio := float64(f.BytesToServer) / float64(inbound)
	if ratio < e.cfg.MinRatio {
		return
	}

	sev := model.SevMedium
	if f.BytesToServer >= 100<<20 {
		sev = model.SevHigh
	}

	dest := f.Server.String()
	if f.SNI != "" {
		dest = f.SNI
	}

	c.Emit(model.Alert{
		RuleID:   RuleExfil,
		Title:    fmt.Sprintf("Large outbound transfer to %s (%s)", dest, humanBytes(f.BytesToServer)),
		Severity: sev,
		Score:    round3(normalize(ratio, e.cfg.MinRatio, 200)),
		Src:      f.Client,
		Dst:      f.Server,
		DstPort:  f.ServerPort,
		Proto:    f.Proto.String(),
		Description: fmt.Sprintf(
			"%s sent %s to %s:%d while receiving only %s — a %.0f:1 outbound ratio over %s. "+
				"Ordinary client traffic is inbound-dominant; this shape is what staging or upload of collected data looks like.",
			f.Client, humanBytes(f.BytesToServer), dest, f.ServerPort,
			humanBytes(f.BytesToClient), ratio, f.Duration().Round(time.Second)),
		Techniques: []model.Technique{model.TechExfilOverC2},
		Evidence: map[string]any{
			"bytes_out":   f.BytesToServer,
			"bytes_in":    f.BytesToClient,
			"ratio":       round3(ratio),
			"duration_s":  round3(f.Duration().Seconds()),
			"server_name": f.SNI,
			"ja4":         f.JA4,
			"packets_out": f.PacketsToServer,
			"dest_port":   f.ServerPort,
		},
	})
}

// humanBytes renders a byte count for alert text.
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
