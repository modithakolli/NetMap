import json
from datetime import datetime, timezone


def save_to_json(scan_hosts, scan_range, filename="scan_results.json"):
    """
    scan_hosts: {host_ip: {"services": {...}, "risk": {...}, "techniques": [...], "osint": {...}}}
    """
    data = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "range": scan_range,
        "hosts": scan_hosts,
    }
    with open(filename, "w") as f:
        json.dump(data, f, indent=2)
    print(f"Results saved to {filename}")
    return data
