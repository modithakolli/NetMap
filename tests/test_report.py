import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mitigation import mitigations_for_host
from risk import score_host
from report import generate_html_report


def test_zero_services_host_still_renders_mitigation_guidance():
    """A host can be up but have zero open ports in the scanned range --
    the report must still show something sensible, not an empty table
    with no mitigation guidance at all."""
    services = {}
    risk = score_host(services)
    scan_hosts = {
        "10.0.0.5": {
            "services": services, "risk": risk, "techniques": [], "osint": {},
            "mitigations": mitigations_for_host(services, risk["tier"]),
        }
    }
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "report.html")
        generate_html_report(scan_hosts, scan_range="test", output_path=path)
        html = open(path).read()
        assert "no open ports found" in html
        assert "No open services with known CVEs detected" in html


def test_malicious_banner_is_escaped_not_executed():
    services = {80: {"name": "http", "product": "<script>alert(1)</script>", "version": "1.0", "cves": []}}
    risk = score_host(services)
    scan_hosts = {
        "10.0.0.6": {
            "services": services, "risk": risk, "techniques": [], "osint": {},
            "mitigations": mitigations_for_host(services, risk["tier"]),
        }
    }
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "report.html")
        generate_html_report(scan_hosts, scan_range="test", output_path=path)
        html = open(path).read()
        assert "<script>alert(1)</script>" not in html
        assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


if __name__ == "__main__":
    test_zero_services_host_still_renders_mitigation_guidance()
    test_malicious_banner_is_escaped_not_executed()
    print("report.py: all tests passed")
