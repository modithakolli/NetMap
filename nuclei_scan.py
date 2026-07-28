"""
Optional integration with Nuclei (https://github.com/projectdiscovery/nuclei),
a template-based vulnerability scanner, for deeper active checks against
any HTTP/HTTPS services this scan found -- CVE lookup only tells you a
version *might* be vulnerable; Nuclei actually probes for it.

Nuclei is a separate Go binary, not a pip package -- install it yourself
(https://docs.projectdiscovery.io/tools/nuclei/install) and make sure
`nuclei` is on your PATH. This module degrades gracefully (returns [] with
a note) if it isn't installed, so --nuclei is safe to leave on by default
in a script even on machines that don't have it.

This runs *active* probes against real services, unlike the passive CVE
keyword lookup -- only point it at hosts you're authorized to test.
"""

import json
import shutil
import subprocess

WEB_SERVICE_NAMES = {"http", "https", "http-proxy", "https-alt"}


def nuclei_available():
    return shutil.which("nuclei") is not None


def run_nuclei(target_url, timeout=180, severity=None):
    """
    Runs nuclei against a single URL, returns a list of finding dicts.
    Returns [] (not an exception) if nuclei isn't installed, times out,
    or finds nothing -- a missing external tool shouldn't break a scan.
    """
    if not nuclei_available():
        return []

    cmd = ["nuclei", "-u", target_url, "-jsonl", "-silent", "-no-color"]
    if severity:
        cmd += ["-severity", severity]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        print(f"  [nuclei] scan of {target_url} timed out after {timeout}s")
        return []
    except OSError as e:
        print(f"  [nuclei] failed to run nuclei: {e}")
        return []

    findings = []
    for line in result.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = data.get("info", {})
        findings.append(
            {
                "template": data.get("template-id"),
                "name": info.get("name"),
                "severity": info.get("severity"),
                "matched_at": data.get("matched-at"),
            }
        )
    return findings


def scan_host_web_services(host, host_services, timeout=180, severity=None, verbose=False):
    """
    Runs nuclei against every http/https service found on a host.
    Mutates each matching service dict in place, adding "nuclei_findings".
    """
    if not nuclei_available():
        if verbose:
            print("  [nuclei] `nuclei` binary not found on PATH -- skipping "
                  "(install: https://docs.projectdiscovery.io/tools/nuclei/install)")
        return

    for port, info in host_services.items():
        name = (info.get("name") or "").lower()
        if name not in WEB_SERVICE_NAMES:
            continue
        scheme = "https" if "https" in name else "http"
        url = f"{scheme}://{host}:{port}"
        if verbose:
            print(f"  [nuclei] scanning {url}")
        info["nuclei_findings"] = run_nuclei(url, timeout=timeout, severity=severity)
