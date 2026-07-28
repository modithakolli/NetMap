"""
Snapshots each scan to a history directory and diffs the current scan
against the most recent previous one -- new/removed hosts, new/closed
ports, and newly-appeared CVEs.
"""

import glob
import json
import os
from datetime import datetime, timezone


def save_snapshot(scan_data, history_dir="history"):
    os.makedirs(history_dir, exist_ok=True)
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = os.path.join(history_dir, f"scan_{ts}.json")
    with open(path, "w") as f:
        json.dump(scan_data, f, indent=2)
    return path


def load_previous_scan(history_dir="history", exclude_path=None):
    if not os.path.isdir(history_dir):
        return None
    files = sorted(glob.glob(os.path.join(history_dir, "scan_*.json")))
    files = [f for f in files if f != exclude_path]
    if not files:
        return None
    with open(files[-1]) as f:
        return json.load(f)


def diff_scans(previous, current):
    """
    previous/current: the "hosts" dict of a scan (host_ip -> {"services": {...}}).
    Returns a structured diff, or None if there's no previous scan to compare.
    """
    if previous is None:
        return None

    prev_hosts = set(previous.keys())
    curr_hosts = set(current.keys())

    diff = {
        "new_hosts": sorted(curr_hosts - prev_hosts),
        "removed_hosts": sorted(prev_hosts - curr_hosts),
        "host_changes": {},
    }

    for host in curr_hosts & prev_hosts:
        prev_ports = set(previous[host].get("services", {}).keys())
        curr_ports = set(current[host].get("services", {}).keys())
        # JSON round-trips int keys to strings; normalize both sides
        prev_ports = {int(p) for p in prev_ports}
        curr_ports = {int(p) for p in curr_ports}

        new_ports = curr_ports - prev_ports
        closed_ports = prev_ports - curr_ports

        new_cve_ids = set()
        prev_cves = set()
        for info in previous[host].get("services", {}).values():
            prev_cves |= {c["id"] for c in info.get("cves", [])}
        for info in current[host].get("services", {}).values():
            new_cve_ids |= {c["id"] for c in info.get("cves", [])}
        newly_seen_cves = new_cve_ids - prev_cves

        if new_ports or closed_ports or newly_seen_cves:
            diff["host_changes"][host] = {
                "new_ports": sorted(new_ports),
                "closed_ports": sorted(closed_ports),
                "new_cves": sorted(newly_seen_cves),
            }

    return diff
