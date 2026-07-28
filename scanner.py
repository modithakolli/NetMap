"""
nmap-backed host discovery and service detection.

Note: -sV (service/version detection) and -O (OS detection) typically
need to run as root/administrator, and take noticeably longer than a
plain port scan since nmap is fingerprinting banners. That's an
intentional tradeoff here -- CVE lookups are worthless without version
info.
"""

import socket

import nmap


def detect_local_subnet():
    """
    Best-effort guess at "your" local /24, by opening a UDP socket toward
    a public IP (no packet is actually sent for UDP connect()) and reading
    back the local address the OS would use. Falls back to 192.168.1.0/24
    if that fails (e.g. no network at all).
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        octets = local_ip.split(".")
        return f"{'.'.join(octets[:3])}.0/24"
    except OSError:
        return "192.168.1.0/24"


def resolve_ranges(range_spec):
    """
    Expands a --range argument into a list of CIDR strings.
    Accepts a single CIDR, a comma-separated list of CIDRs (for scanning
    several subnets/VLANs in one run), or the literal "auto" to detect
    your current local /24.

    Note: this only reaches networks your machine has an L2/L3 route to.
    It can't discover devices on a different, unrelated network segment
    (e.g. a neighbor's Wi-Fi) -- that's a routing/physical-access
    limitation, not a software one, and scanning networks you don't have
    authorization for is out of scope for this tool regardless.
    """
    if range_spec.strip().lower() == "auto":
        detected = detect_local_subnet()
        print(f"[auto] detected local subnet: {detected}")
        return [detected]
    return [r.strip() for r in range_spec.split(",") if r.strip()]


def scan_network(range_spec="192.168.1.0/24"):
    """Ping sweep -- returns a de-duplicated list of IPs that responded."""
    return list(scan_network_details(range_spec).keys())


def scan_network_details(range_spec="192.168.1.0/24"):
    """
    Same ping sweep as scan_network(), but also captures the MAC address
    and whatever vendor name nmap itself resolved for it (nmap ships a
    fairly complete IEEE OUI database), for asset-inventory purposes.
    Returns {ip: {"mac": str|None, "nmap_vendor": str|None}}.
    """
    ranges = resolve_ranges(range_spec)
    details = {}

    for network_range in ranges:
        nm = nmap.PortScanner()
        print(f"Scanning {network_range}...")
        nm.scan(hosts=network_range, arguments="-sn")
        for host in nm.all_hosts():
            if nm[host].state() != "up" or host in details:
                continue
            addresses = nm[host].get("addresses", {})
            mac = addresses.get("mac")
            vendor_map = nm[host].get("vendor", {})
            nmap_vendor = vendor_map.get(mac) if mac else None
            details[host] = {"mac": mac, "nmap_vendor": nmap_vendor}

    return details


def scan_services(ip, full_scan=False, detect_os=False):
    """
    Scans a single host for open ports + service/version info.

    Returns {port: {"protocol": "tcp", "state": "open", "name": ...,
                     "product": ..., "version": ..., "extrainfo": ...}}
    """
    nm = nmap.PortScanner()
    print(f"Scanning services on {ip}...")

    args = "-T4 -sV"
    if not full_scan:
        args += " -F"  # fast: common ports only
    if detect_os:
        args += " -O"

    nm.scan(ip, arguments=args)

    services = {}
    if ip not in nm.all_hosts() or "tcp" not in nm[ip]:
        return services

    for port, data in nm[ip]["tcp"].items():
        if data.get("state") != "open":
            continue
        services[port] = {
            "protocol": "tcp",
            "state": data.get("state"),
            "name": data.get("name", "unknown"),
            "product": data.get("product", ""),
            "version": data.get("version", ""),
            "extrainfo": data.get("extrainfo", ""),
        }

    return services


def detect_os_guess(ip):
    """Best-effort OS guess from nmap -O. Requires elevated privileges."""
    nm = nmap.PortScanner()
    try:
        nm.scan(ip, arguments="-O")
        matches = nm[ip].get("osmatch", [])
        if matches:
            return matches[0].get("name")
    except Exception:
        pass
    return None


# --- Backwards-compatible shim for the original API -------------------

def scan_ports(ip):
    """Legacy helper: just the list of open port numbers."""
    return list(scan_services(ip).keys())
