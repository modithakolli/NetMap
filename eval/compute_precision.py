"""
Reads a completed manual_review_worksheet.csv (produced by evaluate.py)
and computes precision from the human-filled verdict column.

Precision here = true_positives / (true_positives + false_positives),
where "positive" means "NetMap flagged this CVE for this port." Rows
marked "uncertain" are reported separately and excluded from the
precision calculation rather than silently counted either way -- an
honest evaluation says "we couldn't determine this" instead of guessing.

Usage:
    python eval/compute_precision.py --worksheet eval/manual_review_worksheet.csv
"""

import argparse
import csv


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--worksheet", default="eval/manual_review_worksheet.csv")
    args = ap.parse_args()

    counts = {"true_positive": 0, "false_positive": 0, "uncertain": 0, "blank": 0}
    rows = []

    with open(args.worksheet) as f:
        for row in csv.DictReader(f):
            verdict = (row.get("verdict (true_positive / false_positive / uncertain)") or "").strip().lower()
            if verdict not in ("true_positive", "false_positive", "uncertain"):
                counts["blank"] += 1
            else:
                counts[verdict] += 1
            rows.append(row)

    tp, fp, unc, blank = counts["true_positive"], counts["false_positive"], counts["uncertain"], counts["blank"]
    total_judged = tp + fp

    print(f"Total rows: {len(rows)}")
    print(f"  true_positive: {tp}")
    print(f"  false_positive: {fp}")
    print(f"  uncertain: {unc}")
    if blank:
        print(f"  NOT YET FILLED IN: {blank}  <- fill these in before trusting the number below")

    if total_judged == 0:
        print("\nNo true_positive/false_positive verdicts yet -- nothing to compute.")
        return

    precision = tp / total_judged
    print(f"\nPrecision (on the CVEs that needed manual review; excludes ground-truth hits, "
          f"which were all true positives by construction): {tp}/{total_judged} = {precision*100:.1f}%")
    if unc:
        print(f"({unc} row(s) marked uncertain were excluded from this calculation, not counted either way.)")


if __name__ == "__main__":
    main()
