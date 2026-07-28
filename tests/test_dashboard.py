import base64
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))


def _make_client(data_dir, password=None):
    """dashboard.py reads config at import time, so each test gets a fresh
    module import pointed at its own temp data dir / auth setting."""
    import importlib
    os.environ["NETMAP_DATA_DIR"] = data_dir
    if password:
        os.environ["DASHBOARD_PASSWORD"] = password
    else:
        os.environ.pop("DASHBOARD_PASSWORD", None)
    os.environ.pop("NETMAP_ALLOW_SCAN_TRIGGER", None)

    if "dashboard" in sys.modules:
        importlib.reload(sys.modules["dashboard"])
    else:
        import dashboard  # noqa: F401
    return sys.modules["dashboard"].app.test_client()


def _sample_scan():
    return {
        "timestamp": "2026-01-01T00:00:00+00:00", "range": "10.0.0.0/24",
        "hosts": {
            "10.0.0.1": {
                "services": {"22": {"name": "ssh", "product": "OpenSSH", "version": "1.0",
                                      "cves": [{"id": "CVE-2020-0001", "score": 9.8,
                                                 "severity": "CRITICAL", "url": "https://nvd/CVE-2020-0001"}]}},
                "risk": {"tier": "critical", "cve_count": 1, "color": "#c0392b"},
                "techniques": [{"id": "T1021.004", "name": "Remote Services: SSH"}],
                "osint": {}, "vendor": "TestVendor", "rogue": False,
                "mitigations": {"priority": "Act now.", "service_actions": ["Do the thing"], "references": []},
            }
        },
    }


def test_index_shows_real_cve_ids_not_just_a_count():
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "scan_results.json"), "w") as f:
            json.dump(_sample_scan(), f)
        client = _make_client(d)
        r = client.get("/")
        assert r.status_code == 200
        html = r.get_data(as_text=True)
        assert "CVE-2020-0001" in html


def test_topology_route_falls_back_to_png(): # regression test for the visualizer fallback bug
    with tempfile.TemporaryDirectory() as d:
        with open(os.path.join(d, "topology.png"), "wb") as f:
            f.write(b"fake png bytes")
        client = _make_client(d)
        r = client.get("/topology")
        assert r.status_code == 200
        assert r.data == b"fake png bytes"


def test_topology_route_404_when_neither_file_exists():
    with tempfile.TemporaryDirectory() as d:
        client = _make_client(d)
        r = client.get("/topology")
        assert r.status_code == 404


def test_auth_gate_blocks_without_credentials():
    with tempfile.TemporaryDirectory() as d:
        client = _make_client(d, password="s3cret")
        r = client.get("/")
        assert r.status_code == 401

        creds = base64.b64encode(b"user:s3cret").decode()
        r2 = client.get("/", headers={"Authorization": f"Basic {creds}"})
        assert r2.status_code == 200


def test_scan_trigger_disabled_by_default():
    with tempfile.TemporaryDirectory() as d:
        client = _make_client(d)
        r = client.post("/api/scan")
        assert r.status_code == 403


if __name__ == "__main__":
    test_index_shows_real_cve_ids_not_just_a_count()
    test_topology_route_falls_back_to_png()
    test_topology_route_404_when_neither_file_exists()
    test_auth_gate_blocks_without_credentials()
    test_scan_trigger_disabled_by_default()
    print("dashboard.py: all tests passed")
