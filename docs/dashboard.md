# Dashboard

```bash
python main.py --demo              # produces scan_results.json + history/
python dashboard.py                 # serves the dashboard at http://127.0.0.1:5000
```

Shows the current host/risk table (with actual CVE IDs and severity, not
just a count), a trend chart across your scan history (needs at least 2
scans in `history/` to have something to plot), expandable per-host
mitigation guidance, and links out to the interactive topology graph, the
full report, and the ATT&CK Navigator layer download.

## Security

**This serves vulnerability data over plain HTTP with no encryption** —
fine for localhost or a trusted LAN, not something to expose to the
internet as-is. Set `DASHBOARD_PASSWORD` to require HTTP basic auth
(without it, the dashboard runs unauthenticated and prints a warning on
startup):

```bash
export DASHBOARD_PASSWORD=something-not-guessable
python dashboard.py
```

If this needs to be reachable beyond your own machine, put it behind a
reverse proxy with real TLS — basic auth over plain HTTP is not a
substitute for that.

## On-demand scanning

Scan-on-demand from the dashboard UI is off by default. To enable it:

```bash
export NETMAP_ALLOW_SCAN_TRIGGER=1
export NETMAP_RANGE=192.168.1.0/24   # fixed server-side, not client-controlled
python dashboard.py
```

The range is deliberately read from server-side config, never from the
HTTP request — this is intentional so `/api/scan` can't become a "scan
whatever IP the client sends" endpoint. Don't change that without adding
real input validation and auth first.
