# Security policy

## Reporting a vulnerability

Report privately through [GitHub's advisory form](https://github.com/baldoseri/tracehound/security/advisories/new), which opens a channel visible only to the maintainer.

Please do not open a public issue for a vulnerability. A crash in a parser is a remote denial of service against anyone running the sensor, and the whole point of the fuzzing in CI is that such a bug is treated as a defect rather than a curiosity.

Expect an acknowledgement within a week. There is no bounty; this is a personal project.

## What counts

tracehound reads bytes chosen by whoever is on the network being watched. Anything reachable from that input is in scope:

- A panic, hang, or unbounded allocation in a parser, reached from a crafted packet or capture file. The TLS ClientHello and ServerHello parsers, the QUIC Initial decryption path, and the DNS and flow layers all read untrusted input directly.
- Output that escapes its context: terminal control sequences, dashboard markup, or SQL reaching a query. Wire-controlled bytes are escaped at the terminal boundary and by the JSON encoder, SQLite receives them only as parameters, and the dashboard escapes what it renders. A gap in any of those is a bug.
- A detection that can be silenced by an attacker who knows the algorithm, beyond the inherent limits of passive analysis.

## What does not count

**The HTTP API and dashboard are unauthenticated by design, and this is documented rather than fixed.** See the trust boundary below. A report that the API can be read without credentials describes the current design; a report that it can be reached in a configuration the documentation says is safe is a bug.

Findings that require an attacker who already has the privileges tracehound needs to run (`CAP_NET_RAW`, or read access to the database file) are not vulnerabilities in tracehound.

## The trust boundary

`-listen` serves the dashboard, the JSON API, and a live event stream with **no authentication and no transport security**. Together they expose the internal address inventory, MAC addresses, per-host byte counts, JA4 fingerprints, observed server names, and a real-time feed of what has been detected.

That last item is the one to think about. An attacker on the monitored network who can reach the dashboard can watch their own activity being detected, in real time, and stop before the alert is acted on.

So:

- **Bind loopback.** `-listen 127.0.0.1:8080` is the safe configuration, and the sensor prints a warning when the bind is anything else.
- **To reach it remotely, put an authenticating reverse proxy in front.** TLS and access control belong there rather than in a passive sensor, and doing it properly inside this tool would mean credential storage and session handling that a reverse proxy already does better.
- **The database is not encrypted.** `-db` holds the same inventory in a file readable by anyone with filesystem access.

A bare `-listen :8080` binds every interface. That is ordinary Go semantics and is kept deliberately, because changing it would silently break the container deployment, where binding loopback inside a container makes the port unreachable through a published port. The warning exists because the behaviour is retained.

## Captures

Never commit a real capture. `.gitignore` excludes `*.pcap` and `*.pcapng` apart from the generated demo, because a capture from a real network contains exactly the data this policy is about.
