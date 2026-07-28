"""
Best-effort vendor identification from a MAC address (asset inventory).

Priority order:
1. Whatever vendor name nmap itself already resolved (it ships a fairly
   complete IEEE OUI database) -- prefer this, it's the most complete.
2. A small local table of common OUIs, as a fallback for environments
   where nmap didn't resolve one.
3. Optionally, the free api.macvendors.com lookup (only if explicitly
   enabled -- it's an external network call and has a low rate limit).

This is illustrative, not a complete OUI database -- for production
asset inventory you'd want the full IEEE OUI list.
"""

import os
import sqlite3
import time
from datetime import datetime, timedelta, timezone

import requests

DEFAULT_DB_PATH = os.path.join(os.path.dirname(__file__), "oui_cache.db")

# A small illustrative set of common OUIs (first 6 hex chars of the MAC,
# uppercase, no separators). Real deployments should use the full IEEE list:
# https://standards-oui.ieee.org/oui/oui.txt
KNOWN_OUIS = {
    "3C5AB4": "Google",
    "B827EB": "Raspberry Pi Foundation",
    "DCA632": "Raspberry Pi Foundation",
    "D83ADD": "Raspberry Pi Foundation",
    "F4F5D8": "Google",
    "001A11": "Google",
    "8CC121": "Espressif (IoT device, e.g. ESP8266/ESP32)",
    "AC67B2": "Espressif (IoT device, e.g. ESP8266/ESP32)",
    "F0038C": "Apple",
    "F02475": "Apple",
    "A45E60": "Apple",
    "3C0754": "Apple",
    "001B63": "Apple",
    "B0BE76": "Amazon Technologies (e.g. Echo/Kindle/Fire TV)",
    "FCA183": "Amazon Technologies (e.g. Echo/Kindle/Fire TV)",
    "F0272D": "Ubiquiti Networks",
    "24A43C": "Ubiquiti Networks",
    "9C5322": "TP-Link",
    "5091E3": "TP-Link",
    "001E58": "TP-Link",
    "3C061D": "Intel",
    "001517": "Dell",
    "D067E5": "Dell",
    "001A4B": "HP",
    "9CB6D0": "HP",
    "00163E": "Xensource/Xen (virtualized NIC)",
    "080027": "VirtualBox (virtualized NIC)",
    "005056": "VMware (virtualized NIC)",
    "000C29": "VMware (virtualized NIC)",
}


def normalize_mac(mac):
    return mac.replace(":", "").replace("-", "").upper() if mac else None


def _init_db(db_path):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS oui_cache (oui TEXT PRIMARY KEY, vendor TEXT, fetched_at TEXT)"
    )
    conn.commit()
    return conn


def _lookup_online(oui_prefix, db_path, cache_ttl_days=90, timeout=5):
    conn = _init_db(db_path)
    row = conn.execute("SELECT vendor, fetched_at FROM oui_cache WHERE oui = ?", (oui_prefix,)).fetchone()
    if row:
        vendor, fetched_at = row
        if datetime.now(timezone.utc) - datetime.fromisoformat(fetched_at) < timedelta(days=cache_ttl_days):
            return vendor or None

    try:
        time.sleep(1.0)  # api.macvendors.com is aggressively rate-limited
        resp = requests.get(f"https://api.macvendors.com/{oui_prefix}", timeout=timeout)
        vendor = resp.text.strip() if resp.status_code == 200 else None
    except requests.RequestException:
        vendor = None

    conn.execute(
        "INSERT OR REPLACE INTO oui_cache (oui, vendor, fetched_at) VALUES (?, ?, ?)",
        (oui_prefix, vendor, datetime.now(timezone.utc).isoformat()),
    )
    conn.commit()
    return vendor


def lookup_vendor(mac, nmap_vendor=None, use_online=False, db_path=DEFAULT_DB_PATH):
    """
    Returns a best-effort vendor name string, or None if nothing matched.
    `nmap_vendor` is whatever nmap itself already resolved (preferred if present).
    """
    if nmap_vendor:
        return nmap_vendor

    norm = normalize_mac(mac)
    if not norm or len(norm) < 6:
        return None

    prefix = norm[:6]
    if prefix in KNOWN_OUIS:
        return KNOWN_OUIS[prefix]

    if use_online:
        return _lookup_online(prefix, db_path)

    return None
