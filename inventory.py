"""
"Shadow IT" / rogue device detection: flags any scanned host that isn't
in a known-good allowlist. This is a *persistent baseline*, distinct from
history.py's scan-to-scan diffing -- a device could be "new since last
scan" and still be expected (you just added a laptop), or "not new" but
still never authorized (something's been quietly sitting on the network
for a while).

Allowlist format (JSON):
{
  "192.168.1.1":  {"label": "router", "mac": "AA:BB:CC:DD:EE:FF"},
  "192.168.1.10": {"label": "file server"}
}
Matching is by IP primarily; if a MAC is recorded for an entry, a host
with that MAC but a different (e.g. DHCP-reassigned) IP is still matched.
"""

import json
import os

from oui import normalize_mac


def load_allowlist(path):
    if not path or not os.path.exists(path):
        return {}
    with open(path) as f:
        return json.load(f)


def save_allowlist(allowlist, path):
    with open(path, "w") as f:
        json.dump(allowlist, f, indent=2)


def init_allowlist_from_scan(scan_hosts, path):
    """Bootstrap an allowlist by trusting every host in the current scan."""
    allowlist = {
        ip: {"label": data.get("vendor") or "unlabeled", "mac": data.get("mac")}
        for ip, data in scan_hosts.items()
    }
    save_allowlist(allowlist, path)
    return allowlist


def _known_macs(allowlist):
    return {normalize_mac(v.get("mac")) for v in allowlist.values() if v.get("mac")}


def flag_rogue_hosts(scan_hosts, allowlist):
    """
    Mutates scan_hosts in place, adding a "rogue" bool to each host, and
    returns the list of rogue IPs. If the allowlist is empty (not
    configured), nothing is flagged -- there's no baseline to compare against.
    """
    if not allowlist:
        for data in scan_hosts.values():
            data["rogue"] = False
        return []

    known_macs = _known_macs(allowlist)
    rogue = []

    for ip, data in scan_hosts.items():
        mac = normalize_mac(data.get("mac"))
        is_known = ip in allowlist or (mac and mac in known_macs)
        data["rogue"] = not is_known
        if not is_known:
            rogue.append(ip)

    return rogue
