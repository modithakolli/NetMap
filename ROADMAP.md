# Roadmap / future work

Ideas that are genuinely good next steps but out of scope for now — either
because they're a large lift relative to the project's current size, or
because they change the tool's fundamental design (e.g. distributed
scanning) rather than extending it. Listed roughly in the order I'd
tackle them.

## Detection accuracy
- **Exact CPE-based matching** instead of NVD keyword search: extract a
  proper CPE 2.3 string (vendor/product/version) where possible and query
  NVD's CPE-match endpoint instead of free-text search. This is the
  single highest-value accuracy improvement available — see `AUDIT.md`
  and `eval/` for why keyword search is the current bottleneck.
- **Richer risk model.** Right now it's CVSS + EPSS aggregated into a
  tier. A more realistic model would also weigh internet exposure,
  authentication requirements, service criticality, and known active
  campaigns (ransomware-associated CVEs, KEV-listed CVEs from CISA).

## Asset fingerprinting
- OS fingerprinting beyond nmap's `-O` guess, hostname/mDNS resolution,
  SNMP enrichment, TLS certificate metadata for HTTPS services, NetBIOS
  name resolution — would make the asset inventory genuinely useful
  rather than just port/service lists.
- Optional **authenticated scanning** (SSH/WinRM credential-based checks)
  for higher-fidelity results on hosts you have credentials for.

## Architecture / engineering
- **Plugin architecture** so new enrichment sources (another OSINT
  provider, another vuln feed) can be added without touching core
  pipeline code.
- **Async/parallel scanning** — service detection currently runs
  host-by-host; concurrent scanning would matter a lot on larger networks.
- **A REST API** in front of the pipeline, so other tools can trigger
  scans and pull results programmatically instead of only via CLI/dashboard.
- **Packaging** (`pip install netmap` or a proper container image with
  documented config) instead of "clone and run."
- **CI additions**: linting (ruff/flake8), type checking (mypy), and
  security scanning of the codebase itself (bandit) alongside the
  existing pytest workflow.

## Dashboard
- Real user accounts + sessions instead of a single shared basic-auth
  password, if this ever needs to support more than one person.
- HTTPS termination guidance/built-in option instead of "put it behind a
  reverse proxy."

## Not planned
- **Distributed scanning (multiple sensors/agents + central server).**
  Reasonable for an enterprise tool, but it's a different product shape
  than this project, not an incremental feature.
