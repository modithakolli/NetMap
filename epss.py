"""
EPSS (Exploit Prediction Scoring System) integration -- https://www.first.org/epss/

CVSS answers "how bad would this be if exploited." EPSS answers a
different, complementary question: "what's the actual probability this
specific CVE gets exploited in the wild in the next 30 days," based on a
model FIRST.org trains on real observed exploitation activity. Combining
the two is standard modern vulnerability-management practice -- a CVSS 9.8
that's never been exploited and has no public PoC is a different priority
than a CVSS 7.5 that's actively being exploited right now.

API: https://api.first.org/data/v1/epss -- public, free, no key required,
supports batch lookups via a comma-separated `cve` parameter.
"""

import json
import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import requests

EPSS_API_URL = "https://api.first.org/data/v1/epss"
DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "epss_cache.db")
BATCH_SIZE = 90  # stay comfortably under the API's default page size of 100


def _init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS epss_cache (cve TEXT PRIMARY KEY, epss REAL, "
        "percentile REAL, score_date TEXT, fetched_at TEXT)"
    )
    conn.commit()
    return conn


def _get_cached(conn, cve_id, ttl_days):
    row = conn.execute(
        "SELECT epss, percentile, score_date, fetched_at FROM epss_cache WHERE cve = ?", (cve_id,)
    ).fetchone()
    if not row:
        return None
    epss, percentile, score_date, fetched_at = row
    if datetime.now(timezone.utc) - datetime.fromisoformat(fetched_at) > timedelta(days=ttl_days):
        return None
    return {"epss": epss, "percentile": percentile, "date": score_date}


def _set_cache(conn, cve_id, epss, percentile, score_date):
    conn.execute(
        "INSERT OR REPLACE INTO epss_cache (cve, epss, percentile, score_date, fetched_at) "
        "VALUES (?, ?, ?, ?, ?)",
        (cve_id, epss, percentile, score_date, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()


def _fetch_batch(cve_ids, timeout=15):
    """One API call for up to BATCH_SIZE CVE IDs. Returns {cve_id: {epss, percentile, date}}."""
    try:
        resp = requests.get(
            EPSS_API_URL, params={"cve": ",".join(cve_ids), "limit": len(cve_ids)}, timeout=timeout
        )
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError) as e:
        print(f"  [epss] lookup failed for a batch of {len(cve_ids)} CVE(s): {e}")
        return {}

    results = {}
    for entry in data.get("data", []):
        try:
            results[entry["cve"]] = {
                "epss": float(entry["epss"]),
                "percentile": float(entry["percentile"]),
                "date": entry.get("date"),
            }
        except (KeyError, ValueError, TypeError):
            continue
    return results


def get_epss_scores(cve_ids, db_path=DEFAULT_DB_PATH, use_cache=True, cache_ttl_days=1, verbose=False):
    """
    Looks up EPSS scores for a list of CVE IDs. EPSS is recalculated daily,
    so the cache TTL defaults to 1 day (unlike the CVE/OSINT caches, which
    change far less often).

    Returns {cve_id: {"epss": float 0-1, "percentile": float 0-1, "date": str}}.
    CVE IDs with no EPSS data (e.g. too old, or not yet scored) are simply
    absent from the result -- never fabricate a score.
    """
    cve_ids = list(dict.fromkeys(cve_ids))  # de-dupe, preserve order
    if not cve_ids:
        return {}

    conn = _init_db(db_path)
    results = {}
    to_fetch = []

    if use_cache:
        for cve_id in cve_ids:
            cached = _get_cached(conn, cve_id, cache_ttl_days)
            if cached is not None:
                results[cve_id] = cached
            else:
                to_fetch.append(cve_id)
    else:
        to_fetch = cve_ids

    for i in range(0, len(to_fetch), BATCH_SIZE):
        batch = to_fetch[i : i + BATCH_SIZE]
        if verbose:
            print(f"  [epss] fetching {len(batch)} CVE(s) from FIRST.org")
        if i > 0:
            time.sleep(0.5)  # be polite; no hard published rate limit but avoid hammering
        fetched = _fetch_batch(batch)
        for cve_id in batch:
            if cve_id in fetched:
                results[cve_id] = fetched[cve_id]
                if use_cache:
                    _set_cache(conn, cve_id, fetched[cve_id]["epss"],
                               fetched[cve_id]["percentile"], fetched[cve_id]["date"])

    return results


def enrich_host_services_with_epss(host_services, db_path=DEFAULT_DB_PATH, verbose=False):
    """
    Mutates each CVE dict in host_services[port]['cves'] in place, adding
    "epss" and "epss_percentile" (floats 0-1, or None if unavailable).
    """
    all_cve_ids = [
        cve["id"]
        for info in host_services.values()
        for cve in info.get("cves", [])
        if cve.get("id")
    ]
    scores = get_epss_scores(all_cve_ids, db_path=db_path, verbose=verbose)

    for info in host_services.values():
        for cve in info.get("cves", []):
            score = scores.get(cve.get("id"))
            cve["epss"] = score["epss"] if score else None
            cve["epss_percentile"] = score["percentile"] if score else None

    return host_services


def combined_priority(cvss_score, epss_score):
    """
    A simple, transparent combination of severity (CVSS) and likelihood
    (EPSS) into one 0-100 priority number, for sorting -- not a replacement
    for reading both numbers, just a convenient default ordering.

    Rationale: severity alone (CVSS) ignores real-world exploitation
    activity; likelihood alone (EPSS) ignores impact. Multiplying
    normalized versions of both, rather than just averaging, means a CVE
    needs to score reasonably on *both* axes to rank highly -- a 9.8 CVSS
    with near-zero EPSS won't outrank a 7.5 CVSS with high EPSS, which
    matches how real vulnerability-management teams triage.
    """
    if cvss_score is None and epss_score is None:
        return 0.0
    cvss_norm = (cvss_score or 0) / 10.0
    epss_norm = epss_score or 0.0
    return round(100 * cvss_norm * (0.5 + 0.5 * epss_norm), 1)
