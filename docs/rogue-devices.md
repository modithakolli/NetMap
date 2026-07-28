# Rogue device detection

`--allowlist known_devices.json` (default path) is a persistent baseline
of devices you expect to see — distinct from the scan-to-scan diffing in
`history/`, since a device can be "not new since last scan" and still be
something nobody ever authorized.

```bash
cp known_devices.sample.json known_devices.json   # edit to match your network
# or bootstrap it from a scan you trust:
sudo python main.py --range 192.168.1.0/24 --init-allowlist
```

If no allowlist file exists, rogue-device detection is simply skipped (no
false positives from an unconfigured baseline).

Matching is by IP primarily; if a MAC is recorded for an entry, a host
with that MAC but a different (e.g. DHCP-reassigned) IP is still matched.
This is a baseline comparison, not a security boundary — MAC addresses
are spoofable, so it tells you "something unexpected showed up," not
"this device is cryptographically verified." See `AUDIT.md` for more on
that distinction.
