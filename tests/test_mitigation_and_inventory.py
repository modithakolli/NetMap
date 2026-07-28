import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mitigation import mitigations_for_host
from inventory import load_allowlist, flag_rogue_hosts, save_allowlist
from oui import lookup_vendor


def test_mitigations_include_service_specific_advice():
    services = {23: {"name": "telnet", "cves": []}}
    result = mitigations_for_host(services, "none")
    assert any("Telnet" in a for a in result["service_actions"])


def test_mitigations_surface_nvd_reference_links_not_invented_ones():
    services = {
        21: {"name": "ftp", "cves": [
            {"id": "CVE-2011-2523", "references": [{"url": "https://real-nvd-link.example/adv", "tags": ["Vendor Advisory"]}]}
        ]}
    }
    result = mitigations_for_host(services, "critical")
    assert {"cve": "CVE-2011-2523", "url": "https://real-nvd-link.example/adv"} in result["references"]


def test_rogue_detection_flags_unknown_host():
    scan_hosts = {
        "10.0.0.1": {"mac": "AA:BB:CC:DD:EE:01"},
        "10.0.0.2": {"mac": "AA:BB:CC:DD:EE:02"},
    }
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "allow.json")
        save_allowlist({"10.0.0.1": {"label": "trusted", "mac": "AA:BB:CC:DD:EE:01"}}, path)
        allowlist = load_allowlist(path)

        rogue = flag_rogue_hosts(scan_hosts, allowlist)
        assert rogue == ["10.0.0.2"]
        assert scan_hosts["10.0.0.1"]["rogue"] is False
        assert scan_hosts["10.0.0.2"]["rogue"] is True


def test_no_allowlist_flags_nothing():
    scan_hosts = {"10.0.0.1": {}, "10.0.0.2": {}}
    rogue = flag_rogue_hosts(scan_hosts, {})
    assert rogue == []
    assert all(d["rogue"] is False for d in scan_hosts.values())


def test_vendor_lookup_prefers_nmap_then_local_table():
    assert lookup_vendor("00:00:00:00:00:00", nmap_vendor="Some Real Vendor") == "Some Real Vendor"
    assert lookup_vendor("B8:27:EB:12:34:56") == "Raspberry Pi Foundation"
    assert lookup_vendor("FF:FF:FF:FF:FF:FF") is None  # not in the small local table, online lookup disabled


if __name__ == "__main__":
    test_mitigations_include_service_specific_advice()
    test_mitigations_surface_nvd_reference_links_not_invented_ones()
    test_rogue_detection_flags_unknown_host()
    test_no_allowlist_flags_nothing()
    test_vendor_lookup_prefers_nmap_then_local_table()
    print("mitigation.py / inventory.py / oui.py: all tests passed")
