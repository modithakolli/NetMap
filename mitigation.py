"""
Recommended-action guidance for the dashboard/report.

Two layers, both intentionally generic/non-fabricated:

1. Priority-by-tier: how urgently to act, based on the worst CVSS score
   seen on the host. This is standard vuln-management practice (SLA-style
   guidance), not specific to any one CVE.
2. Service-level hardening bullets: generic best-practice advice for a
   given exposed service (e.g. "disable Telnet, it's plaintext"). These
   are well-established security hygiene points, not claims about a
   specific product/version.

For anything CVE-specific, we surface the patch/advisory URLs NVD itself
returned for that CVE (see cve_lookup._extract_references) rather than
inventing a "here's the fix" -- we don't know the exact fix without
reading the vendor advisory, so we link to it instead of guessing.
"""

TIER_PRIORITY = {
    "critical": "Act now. Critical-severity CVEs on this host are commonly "
                 "exploited in the wild -- patch or isolate the host from "
                 "the network until it's patched.",
    "high": "Patch within days, not weeks. High-severity findings are a "
            "realistic near-term risk.",
    "medium": "Patch on your normal update cycle. Not urgent, but don't "
              "let it sit indefinitely.",
    "low": "Low priority -- track it, patch when convenient.",
    "info": "No scored CVEs matched. Doesn't mean the host is safe, just "
            "that this scan didn't find a version-matched CVE for it.",
    "none": "No open services with known CVEs detected on this host.",
}

# service name (lowercase) -> list of generic hardening bullets
SERVICE_MITIGATIONS = {
    "telnet": [
        "Disable Telnet entirely -- it transmits credentials and data in plaintext.",
        "Use SSH instead for remote administration.",
    ],
    "ftp": [
        "Disable anonymous FTP access.",
        "Prefer SFTP/FTPS over plain FTP -- FTP credentials and data are unencrypted.",
        "If this is vsftpd, confirm it isn't the backdoored 2.3.4 build from 2011 "
        "(downloaded between 2011-06-30 and 2011-07-03) -- reinstall from a trusted source if so.",
    ],
    "ssh": [
        "Disable password auth in favor of key-based auth.",
        "Keep OpenSSH patched -- several historical CVEs affect old versions.",
        "Consider restricting SSH access to specific source IPs/VPN.",
    ],
    "http": [
        "Ensure the web server and any CMS/framework behind it are patched.",
        "Put a WAF or reverse proxy in front of it if internet-facing.",
        "Redirect to HTTPS if this is meant to be a public service.",
    ],
    "https": [
        "Verify the TLS certificate and cipher config aren't using deprecated protocols (TLS 1.0/1.1, SSLv3).",
        "Keep the web server/application stack patched.",
    ],
    "microsoft-ds": [
        "Disable SMBv1 if still enabled -- it's the protocol version used by WannaCry/EternalBlue-class exploits.",
        "Don't expose port 445 to the internet; restrict to trusted internal subnets.",
        "Keep Samba/Windows patched to the latest version for your OS/branch.",
    ],
    "ms-wbt-server": [
        "Don't expose RDP (3389) directly to the internet -- put it behind a VPN.",
        "Enable Network Level Authentication (NLA).",
        "Consider disabling RDP entirely if it's not actively needed.",
    ],
    "mysql": [
        "Don't expose the database port to the network -- bind to localhost or a private subnet only.",
        "Use least-privilege DB accounts, not root, for application access.",
        "Keep MySQL patched -- several historical CVEs allow privilege escalation.",
    ],
    "ms-sql-s": [
        "Don't expose the database port to the network directly.",
        "Use least-privilege accounts and strong authentication (not SQL auth with a weak password).",
    ],
    "postgresql": [
        "Don't expose the database port to the network -- bind to localhost or a private subnet only.",
        "Review pg_hba.conf for overly permissive host-based auth rules.",
    ],
    "snmp": [
        "Disable SNMP v1/v2c if enabled -- they use plaintext community strings.",
        "Migrate to SNMPv3 with authentication and encryption.",
    ],
    "vnc": [
        "VNC often has weak default authentication -- ensure a strong password or disable it.",
        "Don't expose VNC directly to the internet; tunnel it over SSH/VPN.",
    ],
}

GENERIC_MITIGATIONS = [
    "Reduce the attack surface: close any of these ports that aren't actually needed.",
    "Segment this host from the rest of the network if it must stay exposed.",
]


def mitigations_for_host(host_services, risk_tier, top_priority_cve=None):
    """
    Returns {"priority": str, "service_actions": [str, ...], "references": [{"cve":..., "url":...}]}

    top_priority_cve, if provided (risk.score_host()'s "top_priority_cve"),
    lets the priority text cite the actual highest-priority CVE by
    CVSS+EPSS rather than just the tier -- e.g. calling out that a specific
    CVE has a high real-world exploitation probability, not just a high
    theoretical severity.
    """
    service_actions = []
    seen_services = set()
    references = []

    for port, info in host_services.items():
        name = (info.get("name") or "").lower()
        if name not in seen_services:
            seen_services.add(name)
            for bullet in SERVICE_MITIGATIONS.get(name, []):
                if bullet not in service_actions:
                    service_actions.append(bullet)
        for cve in info.get("cves", []):
            for ref in cve.get("references", []):
                references.append({"cve": cve["id"], "url": ref["url"]})

    if not service_actions:
        service_actions = list(GENERIC_MITIGATIONS)

    priority = TIER_PRIORITY.get(risk_tier, TIER_PRIORITY["none"])
    if top_priority_cve and top_priority_cve.get("epss") is not None:
        epss_pct = round(top_priority_cve["epss"] * 100, 1)
        if top_priority_cve["epss"] >= 0.10:  # only call this out when it's actually notable
            priority += (
                f" {top_priority_cve['id']} in particular has an EPSS score of {epss_pct}% -- "
                f"a real-world estimated probability of exploitation in the next 30 days, "
                f"not just a theoretical severity rating."
            )

    return {
        "priority": priority,
        "service_actions": service_actions,
        "references": references[:6],
    }
