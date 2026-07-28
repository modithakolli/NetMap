import os
import sys
import json
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mitre_mapping import map_host_techniques, export_navigator_layer


def test_smb_maps_to_expected_techniques():
    services = {445: {"name": "microsoft-ds"}}
    techniques = map_host_techniques(services)
    ids = {t[0] for t in techniques}
    assert "T1021.002" in ids
    assert "T1046" in ids  # baseline technique always present


def test_unknown_service_still_gets_baseline():
    services = {9999: {"name": "some-made-up-service"}}
    techniques = map_host_techniques(services)
    ids = {t[0] for t in techniques}
    assert ids == {"T1046"}


def test_navigator_layer_export_is_valid_json():
    scan_hosts = {
        "10.0.0.1": {"services": {22: {"name": "ssh"}}},
        "10.0.0.2": {"services": {22: {"name": "ssh"}, 445: {"name": "microsoft-ds"}}},
    }
    with tempfile.TemporaryDirectory() as d:
        path = os.path.join(d, "layer.json")
        export_navigator_layer(scan_hosts, path)
        with open(path) as f:
            layer = json.load(f)

        assert layer["domain"] == "enterprise-attack"
        technique_ids = {t["techniqueID"] for t in layer["techniques"]}
        assert "T1021.004" in technique_ids  # SSH
        assert "T1021.002" in technique_ids  # SMB

        ssh_entry = next(t for t in layer["techniques"] if t["techniqueID"] == "T1021.004")
        assert ssh_entry["score"] == 2  # both hosts have ssh


if __name__ == "__main__":
    test_smb_maps_to_expected_techniques()
    test_unknown_service_still_gets_baseline()
    test_navigator_layer_export_is_valid_json()
    print("mitre_mapping.py: all tests passed")
