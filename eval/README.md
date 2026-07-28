# Evaluation: how good is NetMap's CVE detection, actually?

## What this is (and isn't)

This is a rigorous way to measure NetMap's CVE-detection accuracy against
a target with **publicly documented, known-in-advance vulnerabilities** --
Metasploitable2, Rapid7's intentionally-vulnerable practice VM. That's
what makes this a real evaluation rather than a vibe: we know the answer
key before we scan.

**Important honesty note:** the harness in this folder (`evaluate.py`,
`compute_precision.py`) is fully built and verified -- see
`example_synthetic_scan.json`, a hand-constructed fixture (clearly marked
as synthetic, not real) that was used to confirm the recall/precision math
is correct. What hasn't happened yet is running it against an actual
Metasploitable2 VM, because that needs a real hypervisor and network,
which isn't available in this environment. **You need to run the "How to
run this for real" section below yourself** to get actual numbers for
your report.

## Why recall and precision are measured separately (and why precision needs you)

- **Recall** — of the vulnerabilities that are *actually CVE-based*, how
  many did NetMap's NVD keyword lookup find? This is 100% automatable:
  Metasploitable2's known CVEs are documented, so we just check if NetMap
  found each one. `evaluate.py` computes this for you.
- **Precision** — of the CVEs NetMap flagged, how many are *real* (i.e.
  plausibly apply to what's actually running) vs. keyword-search noise?
  This is **not** automatable honestly. Confirming a true positive means
  reading the CVE's description and judging relevance -- that's a human
  judgment call, not a string comparison. `evaluate.py` does the part that
  *is* automatable (recall) and hands you a worksheet for the part that
  isn't (precision), via `compute_precision.py`.

Several of Metasploitable2's "vulnerabilities" (the UnrealIRCd backdoor,
the Java RMI insecure default, the Tomcat weak credentials, the VNC weak
password) are **not CVE-based at all** — they're supply-chain backdoors,
misconfigurations, or weak credentials. These are included in the ground
truth on purpose: they're a clean, honest way to show that CVE-based
scanning has a structural blind spot, not a NetMap-specific bug. A good
evaluation reports that limitation rather than hiding it by only testing
against vulnerabilities the tool was always going to catch.

## How to run this for real

1. Set up Metasploitable2 in a VM (VirtualBox/VMware), on a host-only or
   NAT network so it's isolated from anything else — **never expose it to
   the internet**, it's deliberately full of holes.
   [Official download/setup](https://docs.rapid7.com/metasploit/metasploitable-2/).
2. Find its IP (`ifconfig` inside the VM, or scan for it).
3. Run NetMap against it:
   ```bash
   sudo python main.py --range <metasploitable-ip>/32 --full-scan --output scan_results.json
   ```
   (`--full-scan` matters here — several of the interesting services, like
   distcc on 3632 and Java RMI on 1099, aren't in nmap's default top-100
   fast-scan port list.)
4. Run the evaluator:
   ```bash
   python eval/evaluate.py --scan scan_results.json \
       --ground-truth eval/ground_truth_metasploitable2.json \
       --target-ip <metasploitable-ip>
   ```
5. It prints your real recall number, and writes
   `eval/manual_review_worksheet.csv` listing every CVE NetMap flagged
   that wasn't in the ground truth. Look each one up (NVD links are right
   there in the report/dashboard already), judge whether it's plausible,
   fill in the verdict column.
6. Run `python eval/compute_precision.py --worksheet eval/manual_review_worksheet.csv`
   for your real precision number.

## Writing this up

For a report, present it as a small table:

| Metric | Result | Note |
|---|---|---|
| Recall (CVE-detectable vulns) | *(your number)*% (`hits`/`detectable`) | Automated, from `evaluate.py` |
| Precision (manually verified) | *(your number)*% (`tp`/`tp+fp`) | From your completed review worksheet |
| Structural blind spots found | 4 of 8 ground-truth vulns | Backdoors/misconfig/weak creds — not CVE-based by nature |

Then discuss the blind-spot finding explicitly — it's a genuinely
interesting result, not just a caveat: **it demonstrates that keyword/CVE-
based scanning fundamentally cannot catch backdoors, misconfigurations, or
weak credentials**, which is exactly why real vulnerability management
programs pair automated scanning with manual review/pentesting rather than
relying on either alone. That's a stronger conclusion for a grad project
than "the tool got X% right" — it shows you understand *why* the number
is what it is, not just what the number is.
