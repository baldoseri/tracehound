# tracehound

**A passive network sensor that finds command-and-control traffic, DNS tunnels, and data exfiltration — and shows its arithmetic for every call it makes.**

[![ci](https://github.com/baldoseri/tracehound/actions/workflows/ci.yml/badge.svg)](https://github.com/baldoseri/tracehound/actions/workflows/ci.yml)
[![go report](https://goreportcard.com/badge/github.com/baldoseri/tracehound)](https://goreportcard.com/report/github.com/baldoseri/tracehound)
[![go reference](https://pkg.go.dev/badge/github.com/baldoseri/tracehound.svg)](https://pkg.go.dev/github.com/baldoseri/tracehound)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

tracehound reads packets from a capture file or a live interface, assembles them into
flows, fingerprints TLS clients with **JA4**, and reports attacker behaviour mapped to
**MITRE ATT&CK**. It is a single static binary — no libpcap, no cgo, no runtime
dependencies, and the web dashboard is compiled into the executable.

---

## Try it in thirty seconds

```bash
git clone https://github.com/baldoseri/tracehound && cd tracehound
make demo
```

That builds the binary, generates a synthetic capture containing real attacker
behaviour, and analyses it. No network required, no malware sample to download.

For the live dashboard, replaying 33 minutes of capture in 17 seconds:

```bash
make dashboard   # then open http://localhost:8080
```

Or with Docker, which needs nothing installed but Docker:

```bash
docker compose up demo
```

### What comes out

```
[HIGH    ] TH-0002  Probable DNS tunnelling to exfil.example
             2026-03-14T09:22:47Z  10.0.0.66 -> 10.0.0.1:53  score 0.95
             ATT&CK: T1071.004, T1048.003, T1572
             10.0.0.66 issued 90 queries under exfil.example, 100% of them for names
             never repeated, averaging 46 characters of subdomain at 4.52 bits/char
             entropy. Legitimate resolution reuses names and caches; this pattern only
             makes sense if the name itself is the payload.
             avg_entropy_bits=4.515  avg_subdomain_len=45.889  domain=exfil.example
             max_subdomain_len=46  queries=90  queries_per_min=95.106  txt_null_ratio=1
             unique_names=90  unique_ratio=1

[HIGH    ] TH-0001  Periodic beaconing to 198.51.100.23:443
             2026-03-14T09:27:50Z  10.0.0.66 -> 198.51.100.23:443  score 0.96
             ATT&CK: T1071.001, T1573
             10.0.0.66 opened 28 connections to 198.51.100.23:443 at a mean interval of
             60.7s with 6% jitter. Regularity at this level is characteristic of
             automated check-in rather than user activity.
             connections=28  interval_cv=0.059  interval_mad_ratio=0.048
             interval_mean_s=60.696  jitter_pct=5.931  periodicity_score=0.952
             size_consistency=0.997
```

Every alert carries the numbers that produced it. An analyst who cannot see *why* a
tool fired will stop trusting the tool, so showing the work is a requirement here, not
a nicety.

---

## What it detects

| Rule | Detection | Signal | ATT&CK |
|---|---|---|---|
| `TH-0001` | C2 beaconing | Dispersion of connection intervals, plus request-size consistency | [T1071.001](https://attack.mitre.org/techniques/T1071/001/), [T1573](https://attack.mitre.org/techniques/T1573/) |
| `TH-0002` | DNS tunnelling | Name uniqueness, subdomain length, Shannon entropy, TXT/NULL ratio | [T1071.004](https://attack.mitre.org/techniques/T1071/004/), [T1048.003](https://attack.mitre.org/techniques/T1048/003/), [T1572](https://attack.mitre.org/techniques/T1572/) |
| `TH-0003` | Vertical port scan | Distinct ports touched on one host | [T1046](https://attack.mitre.org/techniques/T1046/) |
| `TH-0004` | Horizontal sweep | Distinct hosts touched on one port | [T1046](https://attack.mitre.org/techniques/T1046/), [T1018](https://attack.mitre.org/techniques/T1018/) |
| `TH-0005` | Data exfiltration | Outbound/inbound byte asymmetry on a completed flow | [T1041](https://attack.mitre.org/techniques/T1041/) |
| `TH-0006` | New device | First traffic from a previously unseen host | — |
| `TH-0007` | Rare TLS stack | A JA4 fingerprint used by exactly one host on a network with a shared baseline | [T1573](https://attack.mitre.org/techniques/T1573/) |

---

## Why JA4 is the interesting part

TLS encrypts the payload, not the handshake. The exact set and ordering of cipher
suites, extensions, and signature algorithms a client offers is a property of its TLS
*stack*, not its traffic — so it survives encryption, proxies, and domain fronting.

In practice a JA4 hash identifies the application. Chrome looks different from curl,
which looks different from the Go runtime, which looks different from a Cobalt Strike
beacon. "A host on this network started speaking TLS with a stack no other host uses"
is one of the highest-signal, lowest-noise things a passive sensor can say.

The ClientHello parser is hand-written against the wire format rather than delegated to
`crypto/tls`, because `crypto/tls` will only parse handshakes it is willing to
negotiate — and the handshakes most worth fingerprinting are the weird ones.

Two details that are easy to get wrong and are handled here:

- **GREASE** (RFC 8701) values are stripped from every list. Clients inject them at
  random specifically to break middleboxes that ignore them; leaving them in makes the
  fingerprint change on every connection from the same client.
- **Fragmented hellos are reassembled.** A current Chrome or Firefox hello carrying a
  hybrid post-quantum key share exceeds one TCP segment. A sensor that parses only the
  first payload packet silently stops fingerprinting exactly the modern clients you most
  want to see. There is a test that feeds a handshake **one byte per segment**, because
  splitting a handshake into minimal segments is a long-standing way to evade inline
  inspection.

---

## How it works

```
  capture ─────▶ decode ─────▶ flow table ─────▶ detectors ─────▶ alerts
  pcap file      gopacket      bidirectional     beaconing        ATT&CK-mapped
  AF_PACKET      zero-alloc    5-tuple, LRU      dns-tunnel       + evidence
                 layer parser  expiry            port-scan             │
                     │                           exfiltration          ▼
                     └────────▶ JA4 / JA3 ──────▶ inventory       HTTP API + SSE
                               ClientHello                        embedded dashboard
                               reassembly
```

The entire data path runs on **one goroutine**. At the packet rates a single commodity
core can decode, the synchronisation cost of sharding across workers exceeds the work
being sharded, and a single-threaded pipeline is far easier to reason about and to test
deterministically. Scaling out belongs at the capture layer — one pipeline per RSS
queue — not inside the loop.

### Decisions worth reading the code for

**Flow expiry is O(expired), not O(total).** The obvious implementation scans every
entry on a timer, which degrades exactly when the table is large — that is, during the
scan or flood you most want to detect. Instead every flow is threaded onto an intrusive
recency list, so reaping pops from the head while the head is too old.
→ [`internal/flow/table.go`](internal/flow/table.go)

**Beaconing takes the better of two dispersion measures.** Coefficient of variation
catches drift; median absolute deviation forgives a missed check-in. Real beacons skip
intervals, and one doubled gap inflates a standard deviation enough to hide the pattern
entirely. → [`internal/detect/beacon.go`](internal/detect/beacon.go)

**DNS tunnelling weights uniqueness highest.** It is the one property a tunnel cannot
avoid: every packet of smuggled data has to be a new name, or caching would swallow it
and the channel would not work. → [`internal/detect/dnstunnel.go`](internal/detect/dnstunnel.go)

**Rarity requires a baseline first.** Early in a capture every host has contributed
exactly one fingerprint, so *everything* is "used by exactly one host". The detector
refuses to judge until it has seen stacks that are demonstrably shared — otherwise it
indicts the entire network. This was a real false positive, caught by replaying the
demo capture. → [`internal/detect/inventory.go`](internal/detect/inventory.go)

**The parser treats input as hostile.** A bounds-checked cursor makes every read past
the end fail rather than panic, so the parser reads as straight-line code with one
validity check at the end. There is a fuzz target because a network parser that panics
is a remote denial of service. → [`internal/fingerprint/clienthello.go`](internal/fingerprint/clienthello.go)

---

## Performance

Measured on an AMD Ryzen 9 3900X, `go test -bench . -benchmem`:

| Operation | Time | Allocations |
|---|---:|---:|
| Flow table update, existing flow | 68 ns | **0** |
| Non-TLS payload rejected | 15 ns | **0** |
| ClientHello parse + JA4 + JA3 | 1.16 µs | 16 |
| Full pipeline, end to end | **~1,050,000 packets/sec** | — |

The fingerprint path started at 4.1 µs and 51 allocations. `fmt.Sprintf("%04x")` was
allocating once per cipher suite; formatting the nibbles by hand made it 3.6× faster.

Packet decoding uses gopacket's `DecodingLayerParser` into pre-allocated layer structs
rather than `gopacket.NewPacket`, which allocates a fresh object per layer per packet
and dominates the profile at line rate.

---

## How correctness is established

Unit tests are necessary but not sufficient for a detector — a threshold low enough to
fire on anything passes its own test. So the demo capture doubles as a detection
harness: **the generator declares what it planted**, and the integration test requires
that every planted behaviour comes back out with the right host attributed, *and that
none of the six benign hosts is ever accused*.

```
--- PASS: TestReplayFindsEveryPlantedBehaviour
    found TH-0001  10.0.0.66  sev=medium  score=0.96  Periodic beaconing to 198.51.100.23:443
    found TH-0002  10.0.0.66  sev=high    score=0.95  Probable DNS tunnelling to exfil.example
    found TH-0003  10.0.0.99  sev=high    score=0.56  Port scan: 121 ports on 10.0.0.10
    found TH-0004  10.0.0.99  sev=medium  score=0.15  Network sweep: port 445 across 60 hosts
    found TH-0005  10.0.0.66  sev=medium  score=1.00  Large outbound transfer (17.9 MiB)
    found TH-0007  10.0.0.66  sev=medium  score=0.60  Rare TLS fingerprint
--- PASS: TestReplayDoesNotAccuseBenignHosts
    6 benign hosts, none reported above info severity
```

That false-positive test is the one that matters. Any detector can be made to fire by
lowering a threshold; the hard part is staying quiet about the ordinary traffic sitting
right next to the attack.

Coverage: `flow` 97%, `fingerprint` 91%, `pipeline` 85%, `detect` 83%.

CI additionally runs the race detector, a 90-second fuzz of the TLS parser on every
pull request, cross-compilation for five platforms, and an end-to-end demo that fails
the build if any rule stops firing.

---

## Usage

```
tracehound replay <file.pcap>    Analyse a capture file
tracehound sniff  -i <iface>     Capture live (Linux; needs CAP_NET_RAW)
tracehound gen-demo <file.pcap>  Write a synthetic capture containing known attacks
```

Useful flags:

| Flag | Meaning |
|---|---|
| `-listen :8080` | Serve the live dashboard and JSON API |
| `-speed 120` | Replay at 120× real time so detections appear progressively |
| `-json` | Emit alerts as JSON Lines, for piping into a SIEM |
| `-min-severity high` | Report only what matters |
| `-home-nets 10.0.0.0/8,192.168.0.0/16` | Define "inside" (defaults to RFC 1918) |

Live capture needs `CAP_NET_RAW`. Grant it narrowly rather than running as root:

```bash
sudo setcap cap_net_raw,cap_net_admin=eip ./bin/tracehound
```

### JSON API

| Endpoint | Returns |
|---|---|
| `GET /api/alerts?limit=&min_severity=` | Alerts, newest first |
| `GET /api/devices` | Passive asset inventory with JA4 fingerprints |
| `GET /api/flows?limit=` | Active flow table |
| `GET /api/stats` | Throughput and detector counters |
| `GET /api/attack` | Observed ATT&CK techniques with counts |
| `GET /api/stream` | Server-sent events, one per alert |

---

## Limitations

Stated plainly, because a security tool that oversells itself is worse than one that
does less:

- **Live capture is Linux-only.** It uses pure-Go AF_PACKET. Every platform can replay
  capture files, which is the better development workflow anyway because it is
  reproducible.
- **No TCP stream reassembly beyond the ClientHello.** Enough for fingerprinting; not
  enough for protocol analysis of the payload.
- **IPv6 extension header chains are not walked.** Plain IPv6 decodes; exotic chains
  are counted as undecodable rather than misparsed.
- **`registeredDomain` takes the last two labels** rather than consulting a public
  suffix list, so `example.co.uk` groups as `co.uk`. A PSL would be more correct at the
  cost of a megabyte of embedded data and an update obligation, for a detector whose
  scoring is dominated by entropy anyway.
- **Alerts repeat as evidence grows.** A beacon reported at 8 connections is reported
  again at 28. That is intentional — the second alert carries stronger evidence — but
  suppressing on *unchanged* evidence rather than elapsed time would be better.
- **Detector thresholds are tuned against synthetic traffic.** They are a starting
  point, not a calibration for your network.

## Roadmap

- User-extensible YAML rules (Sigma-inspired) so thresholds and ATT&CK mappings are
  editable without recompiling
- SQLite persistence so findings survive a restart
- QUIC support — JA4 already encodes the transport, the decoder does not read QUIC yet
- JA4S/JA4H (server and HTTP variants)

## License

MIT — see [LICENSE](LICENSE).

The synthetic capture uses only [RFC 5737](https://www.rfc-editor.org/rfc/rfc5737) and
RFC 1918 documentation addresses, so it can never be mistaken for, or replayed against,
real infrastructure. No real network traffic is included in this repository.
