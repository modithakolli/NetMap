# Nuclei (optional deeper scanning)

CVE lookup here is *passive* — it flags a version as potentially
vulnerable based on NVD data, it doesn't confirm it. `--nuclei` runs
[Nuclei](https://github.com/projectdiscovery/nuclei) template-based active
probes against any HTTP/HTTPS services found, for actual confirmation.

Nuclei is a separate Go binary
([install instructions](https://docs.projectdiscovery.io/tools/nuclei/install)),
not a pip package. `nuclei_scan.py` checks for it on `PATH` and degrades
gracefully with a printed note if it isn't installed — `--nuclei` is safe
to leave in a script even on a machine that doesn't have it.

This runs real requests against real services — only use it against hosts
you're authorized to test, same as everything else in this tool, but
worth restating here since this is the one part of NetMap that does more
than passively read banners.
