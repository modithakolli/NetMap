import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from risk import score_host


def test_no_services_means_no_risk():
    result = score_host({})
    assert result["tier"] == "none"
    assert result["cve_count"] == 0


def test_no_cves_means_no_risk():
    services = {80: {"name": "http", "cves": []}}
    result = score_host(services)
    assert result["tier"] == "none"


def test_critical_cve_drives_tier():
    services = {
        445: {"name": "microsoft-ds", "cves": [
            {"id": "CVE-2017-0144", "score": 8.1, "severity": "HIGH"},
            {"id": "CVE-9999-0001", "score": 9.8, "severity": "CRITICAL"},
        ]}
    }
    result = score_host(services)
    assert result["tier"] == "critical"
    assert result["cve_count"] == 2
    assert result["max_score"] == 9.8


def test_medium_score_tier():
    services = {80: {"name": "http", "cves": [{"id": "X", "score": 5.0, "severity": "MEDIUM"}]}}
    result = score_host(services)
    assert result["tier"] == "medium"


if __name__ == "__main__":
    test_no_services_means_no_risk()
    test_no_cves_means_no_risk()
    test_critical_cve_drives_tier()
    test_medium_score_tier()
    print("risk.py: all tests passed")
