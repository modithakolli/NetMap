"""
Light OSINT enrichment for hosts discovered on the network.

Only makes sense for public/routable IPs -- Shodan and WHOIS don't index
private RFC1918 addresses, so those are skipped automatically. This is
meant to demonstrate the integration pattern (and be genuinely useful if
you point NetMap at a public-facing test host you control), not to be a
full recon suite.
"""

import ipaddress
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "osint_cache.db")
DEFAULT_TTL_DAYS = 7


def _init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS osint_cache "
        "(ip TEXT, source TEXT, fetched_at TEXT, payload TEXT, PRIMARY KEY (ip, source))"
    )
    conn.commit()
    return conn


def _get_cached(conn, ip, source, ttl_days):
    row = conn.execute(
        "SELECT fetched_at, payload FROM osint_cache WHERE ip = ? AND source = ?", (ip, source)
    ).fetchone()
    if not row:
        return None
    if datetime.now(timezone.utc) - datetime.fromisoformat(row[0]) > timedelta(days=ttl_days):
        return None
    return json.loads(row[1])


def _set_cache(conn, ip, source, payload):
    conn.execute(
        "INSERT OR REPLACE INTO osint_cache (ip, source, fetched_at, payload) VALUES (?, ?, ?, ?)",
        (ip, source, datetime.now(timezone.utc).isoformat(), json.dumps(payload)),
    )
    conn.commit()


def is_private_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return True  # if we can't parse it, don't try to look it up externally


def shodan_lookup(ip, api_key=None, verbose=False, db_path=DEFAULT_DB_PATH,
                   use_cache=True, cache_ttl_days=DEFAULT_TTL_DAYS):
    """
    Returns a small dict of Shodan info for a public IP, or None if the
    ip is private, the shodan package isn't installed, no API key is
    configured, or the lookup fails/finds nothing. Cached locally --
    Shodan's free tier has very limited query credits, so re-scanning
    the same host repeatedly must not re-spend them.
    """
    if is_private_ip(ip):
        return None

    conn = _init_db(db_path)
    if use_cache:
        cached = _get_cached(conn, ip, "shodan", cache_ttl_days)
        if cached is not None:
            return cached or None  # cached "no data" is stored as {}

    api_key = api_key or os.environ.get("SHODAN_API_KEY")
    if not api_key:
        if verbose:
            print(f"  [osint] no SHODAN_API_KEY set, skipping Shodan lookup for {ip}")
        return None

    try:
        import shodan
    except ImportError:
        if verbose:
            print("  [osint] `shodan` package not installed (pip install shodan), skipping")
        return None

    try:
        api = shodan.Shodan(api_key)
        result = api.host(ip)
        data = {
            "org": result.get("org"),
            "os": result.get("os"),
            "ports": result.get("ports", []),
            "hostnames": result.get("hostnames", []),
            "vulns": sorted(result.get("vulns", [])) if result.get("vulns") else [],
            "tags": result.get("tags", []),
        }
        if use_cache:
            _set_cache(conn, ip, "shodan", data)
        return data
    except Exception as e:  # shodan.APIError and friends
        if verbose:
            print(f"  [osint] Shodan lookup failed for {ip}: {e}")
        if use_cache:
            _set_cache(conn, ip, "shodan", {})  # cache the miss too, avoid hammering on failure
        return None


def whois_lookup(ip, verbose=False, db_path=DEFAULT_DB_PATH,
                  use_cache=True, cache_ttl_days=DEFAULT_TTL_DAYS):
    """
    Returns basic WHOIS info for a public IP, or None on failure/private IP.
    Uses `python-whois` if installed; entirely optional. Cached locally.
    """
    if is_private_ip(ip):
        return None

    conn = _init_db(db_path)
    if use_cache:
        cached = _get_cached(conn, ip, "whois", cache_ttl_days)
        if cached is not None:
            return cached or None

    try:
        import whois
    except ImportError:
        if verbose:
            print("  [osint] `python-whois` package not installed, skipping WHOIS")
        return None

    try:
        w = whois.whois(ip)
        data = {
            "registrar": getattr(w, "registrar", None),
            "org": getattr(w, "org", None) or getattr(w, "asn_description", None),
            "country": getattr(w, "country", None),
        }
        if use_cache:
            _set_cache(conn, ip, "whois", data)
        return data
    except Exception as e:
        if verbose:
            print(f"  [osint] WHOIS lookup failed for {ip}: {e}")
        if use_cache:
            _set_cache(conn, ip, "whois", {})
        return None


def enrich_host_osint(ip, enable_shodan=True, enable_whois=True, verbose=False):
    osint = {}
    if is_private_ip(ip):
        osint["note"] = "private/non-routable IP -- OSINT sources don't index this"
        return osint

    if enable_shodan:
        shodan_data = shodan_lookup(ip, verbose=verbose)
        if shodan_data:
            osint["shodan"] = shodan_data

    if enable_whois:
        whois_data = whois_lookup(ip, verbose=verbose)
        if whois_data:
            osint["whois"] = whois_data

    return osint
