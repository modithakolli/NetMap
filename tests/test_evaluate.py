import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "eval"))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from evaluate import evaluate, load  # noqa: E402

EVAL_DIR = os.path.join(os.path.dirname(__file__), "..", "eval")


def test_recall_and_flagged_counts_on_synthetic_fixture():
    scan = load(os.path.join(EVAL_DIR, "example_synthetic_scan.json"))
    ground_truth = load(os.path.join(EVAL_DIR, "ground_truth_metasploitable2.json"))

    result = evaluate(scan["hosts"], ground_truth, "192.168.56.101")

    # 4 of the 8 ground-truth entries are CVE-based; the fixture hits 2 of those 4
    assert result["detectable_count"] == 4
    assert result["hits_count"] == 2
    assert result["recall"] == 0.5
    assert result["not_cve_based_count"] == 4

    # the fixture includes exactly one CVE not in the ground-truth list
    assert result["unexplained_flags"] == [("8180", "CVE-2099-00001")]


def test_missing_target_ip_raises_clear_error():
    scan = {"hosts": {}}
    ground_truth = load(os.path.join(EVAL_DIR, "ground_truth_metasploitable2.json"))
    try:
        evaluate(scan["hosts"], ground_truth, "10.0.0.99")
        assert False, "expected a SystemExit for a missing target IP"
    except SystemExit:
        pass


if __name__ == "__main__":
    test_recall_and_flagged_counts_on_synthetic_fixture()
    test_missing_target_ip_raises_clear_error()
    print("eval/evaluate.py: all tests passed")
