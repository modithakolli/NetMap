"""
Renders a self-contained HTML report (no external assets/CDN, so it
works fully offline and can be opened straight from disk, printed to
PDF via the browser, or archived as-is).
"""

from datetime import datetime, timezone

from jinja2 import Environment

from risk import TIER_COLORS

# autoescape=True is load-bearing here: service names/products/versions come
# from raw nmap banner grabs, which are attacker-controlled data (any host on
# the scanned network chooses its own banner). Without escaping, a crafted
# banner like `<script>...</script>` would execute when the report is opened
# in a browser. Do not switch this back to a plain jinja2.Template().
_env = Environment(autoescape=True)
TEMPLATE = _env.from_string("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>NetMap Scan Report</title>
<style>
  body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
         background: #0f1115; color: #e6e6e6; margin: 0; padding: 2rem; }
  h1 { margin-bottom: 0; }
  .meta { color: #999; margin-bottom: 2rem; }
  .summary { display: flex; gap: 1rem; margin-bottom: 2rem; flex-wrap: wrap; }
  .stat { background: #1a1d24; border-radius: 8px; padding: 1rem 1.5rem; min-width: 120px; }
  .stat .n { font-size: 1.8rem; font-weight: 700; }
  .stat .l { color: #999; font-size: 0.85rem; }
  table { width: 100%; border-collapse: collapse; margin-bottom: 2rem; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #2a2d35; vertical-align: top; }
  th { color: #999; font-weight: 600; font-size: 0.85rem; text-transform: uppercase; }
  .badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px;
           font-size: 0.75rem; font-weight: 700; color: #111; }
  .host-card { background: #1a1d24; border-radius: 10px; padding: 1.25rem; margin-bottom: 1.25rem;
               border-left: 4px solid #555; }
  .host-title { font-size: 1.1rem; font-weight: 700; display: flex; align-items: center; gap: 0.75rem; }
  .cve { font-size: 0.85rem; color: #ccc; }
  .cve a { color: #7fb3ff; }
  .tech { display: inline-block; background: #262a33; border-radius: 4px; padding: 0.1rem 0.5rem;
          margin: 0.1rem; font-size: 0.75rem; }
  .diff-section { background: #1a1d24; border-radius: 8px; padding: 1rem 1.25rem; margin-bottom: 2rem; }
  .diff-new { color: #2ecc71; }
  .diff-removed { color: #e74c3c; }
  .empty { color: #666; font-style: italic; }
</style>
</head>
<body>
  <h1>NetMap Scan Report</h1>
  <div class="meta">Range: {{ scan_range }} &middot; Generated {{ generated_at }}</div>

  <div class="summary">
    <div class="stat"><div class="n">{{ hosts|length }}</div><div class="l">Hosts up</div></div>
    <div class="stat"><div class="n">{{ total_ports }}</div><div class="l">Open ports</div></div>
    <div class="stat"><div class="n">{{ total_cves }}</div><div class="l">CVEs found</div></div>
    <div class="stat"><div class="n">{{ critical_hosts }}</div><div class="l">Critical-risk hosts</div></div>
  </div>

  {% if diff %}
  <div class="diff-section">
    <h3>Changes since last scan</h3>
    {% if diff.new_hosts %}<div class="diff-new">+ New hosts: {{ diff.new_hosts|join(', ') }}</div>{% endif %}
    {% if diff.removed_hosts %}<div class="diff-removed">&minus; Hosts no longer seen: {{ diff.removed_hosts|join(', ') }}</div>{% endif %}
    {% for host, ch in diff.host_changes.items() %}
      <div>
        <b>{{ host }}</b>:
        {% if ch.new_ports %}<span class="diff-new">new ports {{ ch.new_ports|join(', ') }}</span>{% endif %}
        {% if ch.closed_ports %}<span class="diff-removed">closed ports {{ ch.closed_ports|join(', ') }}</span>{% endif %}
        {% if ch.new_cves %}<span class="diff-removed">new CVEs {{ ch.new_cves|join(', ') }}</span>{% endif %}
      </div>
    {% endfor %}
    {% if not diff.new_hosts and not diff.removed_hosts and not diff.host_changes %}
      <div class="empty">No changes detected since the last scan.</div>
    {% endif %}
  </div>
  {% endif %}

  {% for host, data in hosts.items() %}
  <div class="host-card" style="border-left-color: {{ data.risk.color }}">
    <div class="host-title">
      {{ host }}
      <span class="badge" style="background: {{ data.risk.color }}">{{ data.risk.tier|upper }}</span>
      {% if data.rogue %}<span class="badge" style="background:#e74c3c;">NOT IN ALLOWLIST</span>{% endif %}
      {% if data.vendor %}<span style="color:#999; font-size:0.8rem;">{{ data.vendor }}</span>{% endif %}
      <span style="color:#999; font-size:0.8rem;">{{ data.services|length }} open port(s), {{ data.risk.cve_count }} CVE(s)</span>
    </div>

    {% if data.techniques %}
    <div style="margin-top:0.5rem;">
      {% for t in data.techniques %}<span class="tech">{{ t.id }} &middot; {{ t.name }}</span>{% endfor %}
    </div>
    {% endif %}

    {% if data.osint and data.osint.shodan %}
    <div style="margin-top:0.5rem; font-size:0.85rem; color:#ccc;">
      OSINT (Shodan): org={{ data.osint.shodan.org }}, os={{ data.osint.shodan.os }}
    </div>
    {% endif %}

    <table>
      <tr><th>Port</th><th>Service</th><th>Version</th><th>CVEs</th>{% if data.mitigations %}<th>Recommended actions</th>{% endif %}</tr>
      {% for port, svc in data.services.items() %}
      <tr>
        <td>{{ port }}/tcp</td>
        <td>{{ svc.name }}</td>
        <td>{{ svc.product }} {{ svc.version }}</td>
        <td>
          {% if svc.cves %}
            {% for c in svc.cves[:5] %}
              <div class="cve"><a href="{{ c.url }}">{{ c.id }}</a> ({{ c.severity }}{% if c.score %}, CVSS {{ c.score }}{% endif %}{% if c.epss %}, EPSS {{ (c.epss * 100)|round(1) }}%{% endif %})</div>
            {% endfor %}
          {% else %}
            <span class="empty">none found</span>
          {% endif %}
          {% if svc.nuclei_findings %}
            {% for f in svc.nuclei_findings %}
              <div class="cve" style="color:#e67e22;">nuclei: {{ f.name }} ({{ f.severity }})</div>
            {% endfor %}
          {% endif %}
        </td>
        {% if loop.first and data.mitigations %}
        <td rowspan="{{ data.services|length }}" style="font-size:0.85rem;">
          <div style="margin-bottom:0.5rem;">{{ data.mitigations.priority }}</div>
          <ul style="margin:0; padding-left:1.1rem;">
            {% for action in data.mitigations.service_actions %}<li>{{ action }}</li>{% endfor %}
          </ul>
          {% if data.mitigations.references %}
          <div style="margin-top:0.5rem;">Patch/advisory links:
            {% for r in data.mitigations.references %}<div><a href="{{ r.url }}">{{ r.cve }}</a></div>{% endfor %}
          </div>
          {% endif %}
        </td>
        {% endif %}
      </tr>
      {% else %}
      <tr>
        <td colspan="3"><span class="empty">host is up, but no open ports found in the scanned range</span></td>
        <td><span class="empty">none found</span></td>
        {% if data.mitigations %}
        <td style="font-size:0.85rem;">{{ data.mitigations.priority }}</td>
        {% endif %}
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endfor %}

  <p style="color:#666; font-size:0.8rem;">
    CVE data via NVD keyword search (approximate, not precise CPE matching). ATT&amp;CK mapping is a
    curated simplification -- see mitre_mapping.py. Generated by NetMap.
  </p>
</body>
</html>
""")


def generate_html_report(scan_hosts, scan_range="", diff=None, output_path="report.html"):
    total_ports = sum(len(d.get("services", {})) for d in scan_hosts.values())
    total_cves = sum(d.get("risk", {}).get("cve_count", 0) for d in scan_hosts.values())
    critical_hosts = sum(1 for d in scan_hosts.values() if d.get("risk", {}).get("tier") == "critical")

    html = TEMPLATE.render(
        hosts=scan_hosts,
        scan_range=scan_range,
        generated_at=datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        total_ports=total_ports,
        total_cves=total_cves,
        critical_hosts=critical_hosts,
        diff=diff,
    )

    with open(output_path, "w") as f:
        f.write(html)

    print(f"HTML report written to {output_path}")
    return output_path
