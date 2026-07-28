# NetMap vs. Nessus / OpenVAS — where this actually sits

A fair comparison against the two scanners anyone doing this kind of work
will have heard of. The goal here isn't "NetMap is better" — it's showing
an honest understanding of where a project like this fits next to
production-grade tools, which is exactly what's missing from most student
projects that build a scanner and stop there.

| | **NetMap** | **Nessus (Essentials, free tier)** | **OpenVAS / Greenbone Community** |
|---|---|---|---|
| **Detection method** | Passive: NVD keyword search against a version banner | Active: ~252,000 vendor-maintained plugins (NASL scripts) that actually probe for the flaw | Active: NASL/NVT checks from Greenbone's community feed, also probe-based |
| **Verification** | None by default — flags a version as *potentially* vulnerable. `--nuclei` adds optional active probing for web services only | Confirms via live checks — much lower false-positive rate | Confirms via live checks, similar model to Nessus |
| **Cost / access** | Free, open source, read every line of it | Free tier capped at 16 IPs; full product is commercial | Free, open source, no IP cap (commercial Greenbone tiers exist for faster feed updates) |
| **Setup friction** | `pip install`, run a script | Register, install, activate, wait for plugin feed sync | More manual setup/tuning; steeper learning curve |
| **Coverage breadth** | Whatever NVD has indexed, matched by keyword — inherently noisier and can miss things a precise plugin would catch | Very broad, low-noise, actively maintained by a dedicated vendor team | Broad, maintained by the Greenbone community, updates less frequently than Nessus's commercial feed |
| **Extra context beyond "is it vulnerable"** | ATT&CK technique mapping, EPSS-based exploitation likelihood, rogue-device detection, MAC/vendor asset ID, mitigation guidance, live dashboard | Reporting is strong but generally stays in "vulnerability + fix" scope | Similar — reporting-focused, less built-in threat-framework context |
| **Transparency** | Every scoring/mapping decision is a readable Python file you can audit (see `AUDIT.md`) | Proprietary plugin logic — you trust the vendor | Open-source NVTs — auditable, though large in number |
| **Best fit** | Learning, a home/lab network, a security portfolio piece, anywhere you want to see and modify exactly how detection works | An organization that wants low-noise, low-effort, well-supported scanning and can accept a commercial tool | A self-hosted team that wants free + open source and is willing to invest setup/tuning time |

## The honest one-paragraph version

Nessus and OpenVAS both **actively confirm** vulnerabilities by attempting
real checks against the service, which is why their false-positive rates
are dramatically lower than what a passive keyword match can achieve —
that's the fundamental trade this project makes for being free, simple,
and instant to set up. What NetMap adds that neither of those does out of
the box is treating a scan as *decision support* rather than just a
findings list: mapping exposures directly to ATT&CK techniques, ranking by
real-world exploitation likelihood (EPSS) instead of just theoretical
severity, flagging devices that shouldn't be on the network at all, and
putting all of it on a live dashboard with concrete next steps — all in
code short enough to read end to end in an afternoon. It's not a Nessus
replacement; it's closer to what you'd build if you wanted to *understand*
how a scanner like Nessus works, then extend it with the parts a
commercial tool doesn't prioritize (transparency, threat-framework
mapping, exploitation-likelihood-aware prioritization).

## Where this comparison came from

General claims about Nessus/OpenVAS pricing, plugin counts, and setup
friction were checked against current documentation as of July 2026
(Tenable's own Nessus documentation, Greenbone's OpenVAS documentation,
and several independent comparison write-ups) rather than pulled from
memory, since pricing/tier/plugin-count details change over time. Verify
current numbers directly at tenable.com and greenbone.net before citing
this table in a report, in case they've shifted since.
