"""
CVE enrichment via the NVD (National Vulnerability Database) REST API 2.0.

Strategy
--------
Building an exact CPE 2.3 string from an nmap service banner requires
knowing the vendor, which nmap doesn't reliably give you. Instead we use
NVD's `keywordSearch` parameter against the CVE endpoint with
"<product> <version>" and filter results client-side. This is an
approximation (fine for a demo/research tool) rather than the precise
CPE-matching a commercial scanner (Nessus/OpenVAS) would do -- that
tradeoff is documented in the README.

Results are cached in a local SQLite DB so repeated scans of the same
service/version don't re-hit the API (which is rate limited).
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import requests

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "cve_cache.db")

# Without an API key NVD asks for ~1 request per 6s; with a key it's much
# faster. See https://nvd.nist.gov/developers/start-here
DELAY_NO_KEY = 6.0
DELAY_WITH_KEY = 0.7

CVSS_NONE = "NONE"


class CVELookupError(Exception):
    pass


def _init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS cve_cache (
            cache_key TEXT PRIMARY KEY,
            product TEXT,
            version TEXT,
            fetched_at TEXT,
            payload TEXT
        )
        """
    )
    conn.commit()
    return conn


def _cache_key(product, version):
    return f"{(product or '').strip().lower()}::{(version or '').strip().lower()}"


def _get_cached(conn, key, ttl_days):
    row = conn.execute(
        "SELECT fetched_at, payload FROM cve_cache WHERE cache_key = ?", (key,)
    ).fetchone()
    if not row:
        return None
    fetched_at = datetime.fromisoformat(row[0])
    if datetime.now(timezone.utc) - fetched_at > timedelta(days=ttl_days):
        return None
    return json.loads(row[1])


def _set_cache(conn, key, product, version, payload):
    conn.execute(
        "INSERT OR REPLACE INTO cve_cache (cache_key, product, version, fetched_at, payload) "
        "VALUES (?, ?, ?, ?, ?)",
        (key, product, version, datetime.now(timezone.utc).isoformat(), json.dumps(payload)),
    )
    conn.commit()


def _extract_score_severity(cve_item):
    """Pull the best available CVSS base score/severity out of an NVD CVE object."""
    metrics = cve_item.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        entries = metrics.get(key)
        if entries:
            data = entries[0].get("cvssData", {})
            score = data.get("baseScore")
            severity = data.get("baseSeverity") or entries[0].get("baseSeverity")
            return score, severity or CVSS_NONE
    return None, CVSS_NONE


def _extract_references(cve_item, max_refs=3):
    """
    Pull a few reference URLs straight from NVD's own data (patch/vendor
    advisory links where tagged as such, otherwise just the first few).
    These are real, sourced links -- never fabricate a patch URL.
    """
    refs = cve_item.get("references", [])
    tagged = [r for r in refs if any(t in ("Patch", "Vendor Advisory") for t in r.get("tags", []))]
    chosen = (tagged or refs)[:max_refs]
    return [{"url": r.get("url"), "tags": r.get("tags", [])} for r in chosen if r.get("url")]


def _extract_description(cve_item):
    for desc in cve_item.get("descriptions", []):
        if desc.get("lang") == "en":
            return desc.get("value", "")
    return ""


def _query_nvd(keyword, results_limit, api_key, timeout=15):
    headers = {"apiKey": api_key} if api_key else {}
    params = {"keywordSearch": keyword, "resultsPerPage": results_limit}

    last_err = None
    for attempt in range(3):
        try:
            resp = requests.get(NVD_API_URL, params=params, headers=headers, timeout=timeout)
            if resp.status_code == 200:
                return resp.json()
            if resp.status_code in (403, 429, 503):
                # rate limited / throttled -- back off and retry
                time.sleep((DELAY_WITH_KEY if api_key else DELAY_NO_KEY) * (attempt + 1))
                continue
            resp.raise_for_status()
        except requests.RequestException as e:
            last_err = e
            time.sleep(1.5 * (attempt + 1))
    raise CVELookupError(f"NVD API request failed after retries: {last_err}")


def lookup_cves_for_service(product, version, max_results=5, api_key=None,
                             db_path=DEFAULT_DB_PATH, use_cache=True, cache_ttl_days=7,
                             verbose=False):
    """
    Return a list of CVE dicts for a given service/product + version string.

    Each dict: {id, score, severity, description, url, published}
    Returns [] if product/version is empty, unknown, or the lookup fails
    (failures are non-fatal -- a scan should still complete without CVE data).
    """
    if not product or not version or version in ("", "unknown"):
        return []

    conn = _init_db(db_path)
    key = _cache_key(product, version)

    if use_cache:
        cached = _get_cached(conn, key, cache_ttl_days)
        if cached is not None:
            return cached

    api_key = api_key or os.environ.get("NVD_API_KEY")
    delay = DELAY_WITH_KEY if api_key else DELAY_NO_KEY

    try:
        time.sleep(delay)  # be a polite API citizen even on the first call
        raw = _query_nvd(f"{product} {version}", max_results, api_key)
    except CVELookupError as e:
        if verbose:
            print(f"  [cve] lookup failed for {product} {version}: {e}")
        return []

    results = []
    for vuln in raw.get("vulnerabilities", []):
        cve_item = vuln.get("cve", {})
        score, severity = _extract_score_severity(cve_item)
        results.append(
            {
                "id": cve_item.get("id"),
                "score": score,
                "severity": (severity or CVSS_NONE).upper(),
                "description": _extract_description(cve_item)[:400],
                "url": f"https://nvd.nist.gov/vuln/detail/{cve_item.get('id')}",
                "published": cve_item.get("published"),
                "references": _extract_references(cve_item),
            }
        )

    # Highest severity first
    results.sort(key=lambda c: (c["score"] or 0), reverse=True)

    if use_cache:
        _set_cache(conn, key, product, version, results)

    return results


def enrich_host_services(host_services, max_results=5, api_key=None, verbose=False,
                          db_path=DEFAULT_DB_PATH, use_cache=True, cache_ttl_days=7):
    """
    host_services: {port: {"name":..., "product":..., "version":..., "protocol":...}}
    Mutates each service dict in place, adding a "cves" list.
    """
    for port, info in host_services.items():
        product = info.get("product") or info.get("name")
        version = info.get("version")
        if verbose:
            print(f"  [cve] checking {product} {version} (port {port})")
        info["cves"] = lookup_cves_for_service(
            product, version, max_results=max_results, api_key=api_key, verbose=verbose,
            db_path=db_path, use_cache=use_cache, cache_ttl_days=cache_ttl_days,
        )
    return host_services
