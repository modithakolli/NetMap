"""
Evaluates a real NetMap scan (scan_results.json) against a documented
ground-truth vulnerability list for a known target.

Two honestly-different things get measured here, not one blended number:

1. RECALL -- fully automatable. For each ground-truth vulnerability that
   *is* CVE-based, did NetMap's NVD keyword lookup actually find that CVE
   ID on the right port? This is a clean yes/no we can check by string
   comparison.

2. PRECISION -- NOT fully automatable, and this script doesn't pretend
   otherwise. Confirming a flagged CVE is a *true* positive means reading
   its description and judging whether it plausibly applies to what's
   actually running -- that requires a human (or at least a much smarter
   check than "did the strings match"). This script instead writes every
   CVE NetMap flagged that ISN'T in the curated ground-truth list to a CSV
   worksheet, for you to hand-classify. Run compute_precision.py on the
   completed sheet to get a real precision number afterward.

Usage:
    python eval/evaluate.py --scan scan_results.json \\
        --ground-truth eval/ground_truth_metasploitable2.json \\
        --target-ip 192.168.56.101
"""

import argparse
import csv
import json


def load(path):
    with open(path) as f:
        return json.load(f)


def evaluate(scan_hosts, ground_truth, target_ip):
    if target_ip not in scan_hosts:
        raise SystemExit(
            f"{target_ip} not found in the scan results -- did the scan actually reach it? "
            f"Hosts found: {list(scan_hosts.keys())}"
        )
    services = scan_hosts[target_ip].get("services", {})

    recall_rows = []
    all_flagged = []  # (port, cve_id) across every ground-truth-relevant port
    ground_truth_cve_ids = {
        e["expected_cve"] for e in ground_truth["known_vulnerabilities"] if e.get("expected_cve")
    }

    for entry in ground_truth["known_vulnerabilities"]:
        port_str = str(entry["port"])
        svc = services.get(port_str) or services.get(entry["port"])
        found_cve_ids = {c["id"] for c in (svc or {}).get("cves", [])} if svc else set()

        if svc:
            for c in svc.get("cves", []):
                all_flagged.append((port_str, c["id"]))

        if entry.get("expected_cve"):
            recall_rows.append({
                "port": port_str, "service": entry["service"],
                "expected_cve": entry["expected_cve"],
                "detected": entry["expected_cve"] in found_cve_ids,
                "note": entry.get("note", ""),
            })
        else:
            recall_rows.append({
                "port": port_str, "service": entry["service"], "expected_cve": None,
                "detected": None,
                "note": entry.get("note", "not CVE-based -- structurally undetectable by this method"),
            })

    detectable = [r for r in recall_rows if r["expected_cve"]]
    hits = [r for r in detectable if r["detected"]]
    recall = (len(hits) / len(detectable)) if detectable else 0.0

    unexplained_flags = [(p, cid) for p, cid in all_flagged if cid not in ground_truth_cve_ids]

    return {
        "recall": recall,
        "recall_rows": recall_rows,
        "detectable_count": len(detectable),
        "hits_count": len(hits),
        "not_cve_based_count": len(recall_rows) - len(detectable),
        "unexplained_flags": sorted(set(unexplained_flags)),
        "total_flagged": len(all_flagged),
    }


def print_report(result, target_name, target_ip):
    print(f"\n=== NetMap evaluation against {target_name} ({target_ip}) ===\n")
    print(f"{'Port':<6}{'Service':<14}{'Expected CVE':<18}{'Detected':<10}Note")
    for r in result["recall_rows"]:
        det = "n/a" if r["detected"] is None else ("YES" if r["detected"] else "NO")
        print(f"{r['port']:<6}{r['service']:<14}{(r['expected_cve'] or '-'):<18}{det:<10}{r['note'][:80]}")

    print(f"\nRECALL (of ground-truth vulns that are actually CVE-based): "
          f"{result['hits_count']}/{result['detectable_count']} = {result['recall']*100:.1f}%")
    print(f"Ground-truth vulns that are structurally NOT CVE-based "
          f"(backdoors/misconfig/weak creds -- excluded from recall, not scanner failures): "
          f"{result['not_cve_based_count']}")
    print(f"\nTotal CVEs flagged across the ports we checked: {result['total_flagged']}")
    print(f"CVEs flagged that aren't in the curated ground-truth list: {len(result['unexplained_flags'])}")
    print("  These are NOT automatically false positives -- some may be real, additional CVEs")
    print("  for that exact version that simply weren't in our (deliberately small) ground-truth")
    print("  list. Each needs a quick manual look before you can honestly call it a false positive.")


def write_review_worksheet(unexplained_flags, path):
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["port", "cve_id", "verdict (true_positive / false_positive / uncertain)", "notes"])
        for port, cve_id in unexplained_flags:
            w.writerow([port, cve_id, "", ""])
    print(f"\nWrote {len(unexplained_flags)} row(s) needing manual review to {path}")
    print("Look up each CVE (the report.html/dashboard already link to nvd.nist.gov for each one),")
    print("judge whether it plausibly applies to what's actually running, fill in 'verdict', then run:")
    print(f"  python eval/compute_precision.py --worksheet {path}")


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--scan", required=True, help="Path to a real scan_results.json")
    ap.add_argument("--ground-truth", required=True, help="Path to a ground-truth JSON (see eval/)")
    ap.add_argument("--target-ip", required=True, help="IP of the practice target within that scan")
    ap.add_argument("--review-csv", default="eval/manual_review_worksheet.csv")
    args = ap.parse_args()

    scan = load(args.scan)
    ground_truth = load(args.ground_truth)
    result = evaluate(scan["hosts"], ground_truth, args.target_ip)

    print_report(result, ground_truth["target"], args.target_ip)
    write_review_worksheet(result["unexplained_flags"], args.review_csv)


if __name__ == "__main__":
    main()
