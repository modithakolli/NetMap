import os
import sys
import tempfile
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import cve_lookup


FAKE_NVD_RESPONSE = {
    "vulnerabilities": [
        {
            "cve": {
                "id": "CVE-2021-44228",
                "published": "2021-12-10T10:15:00.000",
                "descriptions": [{"lang": "en", "value": "Apache Log4j2 RCE (Log4Shell)."}],
                "metrics": {
                    "cvssMetricV31": [
                        {"cvssData": {"baseScore": 10.0, "baseSeverity": "CRITICAL"}}
                    ]
                },
            }
        }
    ]
}


def test_empty_version_returns_no_cves():
    result = cve_lookup.lookup_cves_for_service("nginx", "", use_cache=False)
    assert result == []


@patch("cve_lookup._query_nvd", return_value=FAKE_NVD_RESPONSE)
@patch("cve_lookup.time.sleep", return_value=None)  # skip the real rate-limit delay in tests
def test_lookup_parses_and_caches(mock_sleep, mock_query):
    with tempfile.TemporaryDirectory() as d:
        db_path = os.path.join(d, "test_cache.db")

        result = cve_lookup.lookup_cves_for_service(
            "log4j", "2.14.1", db_path=db_path, use_cache=True
        )
        assert len(result) == 1
        assert result[0]["id"] == "CVE-2021-44228"
        assert result[0]["score"] == 10.0
        assert result[0]["severity"] == "CRITICAL"
        assert mock_query.call_count == 1

        # second call should hit the cache, not the (mocked) network again
        result2 = cve_lookup.lookup_cves_for_service(
            "log4j", "2.14.1", db_path=db_path, use_cache=True
        )
        assert result2 == result
        assert mock_query.call_count == 1  # unchanged


if __name__ == "__main__":
    test_empty_version_returns_no_cves()
    test_lookup_parses_and_caches()
    print("cve_lookup.py: all tests passed")
