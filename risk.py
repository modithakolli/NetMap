"""
Aggregates CVE data into a per-host risk tier for coloring/reporting.
"""

from epss import combined_priority

TIER_ORDER = ["critical", "high", "medium", "low", "info", "none"]

TIER_COLORS = {
    "critical": "#c0392b",
    "high": "#e67e22",
    "medium": "#f1c40f",
    "low": "#27ae60",
    "info": "#2980b9",
    "none": "#95a5a6",
}


def _tier_for_score(score):
    if score is None:
        return "info"
    if score >= 9.0:
        return "critical"
    if score >= 7.0:
        return "high"
    if score >= 4.0:
        return "medium"
    if score > 0.0:
        return "low"
    return "none"


def score_host(host_services):
    """
    host_services: {port: {..., "cves": [{"score": float|None, "epss": float|None, ...}, ...]}}
    Returns a summary dict with the worst-case tier, counts, and (if EPSS
    data is present) the highest combined CVSS+EPSS priority seen.
    """
    all_cves = []
    for info in host_services.values():
        all_cves.extend(info.get("cves", []))

    if not host_services:
        tier = "none"
    elif not all_cves:
        tier = "none"
    else:
        best_score = max((c["score"] for c in all_cves if c["score"] is not None), default=None)
        tier = _tier_for_score(best_score)

    counts = {t: 0 for t in TIER_ORDER}
    for c in all_cves:
        counts[_tier_for_score(c["score"])] += 1

    priorities = [
        combined_priority(c.get("score"), c.get("epss"))
        for c in all_cves
        if "epss" in c  # only computed if EPSS enrichment ran
    ]
    top_priority_cve = None
    if priorities:
        best_idx = max(range(len(priorities)), key=lambda i: priorities[i])
        top_priority_cve = {**all_cves[best_idx], "priority": priorities[best_idx]}

    return {
        "tier": tier,
        "max_score": max((c["score"] for c in all_cves if c["score"] is not None), default=None),
        "cve_count": len(all_cves),
        "counts_by_tier": counts,
        "color": TIER_COLORS[tier],
        "top_priority_cve": top_priority_cve,  # highest CVSS+EPSS combined priority, if EPSS ran
    }


def tier_rank(tier):
    """Lower = worse, for sorting hosts by severity."""
    return TIER_ORDER.index(tier) if tier in TIER_ORDER else len(TIER_ORDER)
