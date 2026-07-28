import os
import sys
import tempfile
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import epss


FAKE_EPSS_RESPONSE = {
    "status": "OK", "status-code": 200, "total": 2, "offset": 0, "limit": 100,
    "data": [
        {"cve": "CVE-2011-2523", "epss": "0.943820000", "percentile": "0.998760000", "date": "2026-07-01"},
        {"cve": "CVE-2016-1908", "epss": "0.012340000", "percentile": "0.612300000", "date": "2026-07-01"},
    ],
}


def _mock_response(json_data, status=200):
    resp = MagicMock()
    resp.json.return_value = json_data
    resp.status_code = status
    resp.raise_for_status = MagicMock()
    return resp


@patch("epss.requests.get")
def test_get_epss_scores_parses_and_caches(mock_get):
    mock_get.return_value = _mock_response(FAKE_EPSS_RESPONSE)
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "epss_test.db")
        scores = epss.get_epss_scores(
            ["CVE-2011-2523", "CVE-2016-1908"], db_path=db_path, use_cache=True
        )
        assert scores["CVE-2011-2523"]["epss"] == 0.94382
        assert scores["CVE-2016-1908"]["percentile"] == 0.6123
        assert mock_get.call_count == 1

        # cached second call shouldn't hit the network again
        scores2 = epss.get_epss_scores(
            ["CVE-2011-2523", "CVE-2016-1908"], db_path=db_path, use_cache=True
        )
        assert scores2 == scores
        assert mock_get.call_count == 1


def test_missing_cve_is_simply_absent_not_fabricated():
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "epss_test2.db")
        with patch("epss.requests.get", return_value=_mock_response({"data": []})):
            scores = epss.get_epss_scores(["CVE-9999-99999"], db_path=db_path, use_cache=False)
        assert scores == {}


def test_combined_priority_needs_both_severity_and_likelihood():
    high_cvss_low_epss = epss.combined_priority(9.8, 0.001)
    high_cvss_high_epss = epss.combined_priority(9.8, 0.95)
    low_cvss_high_epss = epss.combined_priority(3.0, 0.95)

    assert high_cvss_high_epss > high_cvss_low_epss
    assert high_cvss_high_epss > low_cvss_high_epss
    assert epss.combined_priority(None, None) == 0.0


def test_enrich_host_services_adds_epss_fields():
    services = {21: {"name": "ftp", "cves": [{"id": "CVE-2011-2523"}]}}
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "epss_test3.db")
        with patch("epss.requests.get", return_value=_mock_response(FAKE_EPSS_RESPONSE)):
            epss.enrich_host_services_with_epss(services, db_path=db_path)
        assert services[21]["cves"][0]["epss"] == 0.94382


if __name__ == "__main__":
    test_get_epss_scores_parses_and_caches()
    test_missing_cve_is_simply_absent_not_fabricated()
    test_combined_priority_needs_both_severity_and_likelihood()
    test_enrich_host_services_adds_epss_fields()
    print("epss.py: all tests passed")
