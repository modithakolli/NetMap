"""
A small Flask dashboard over NetMap's scan output: current host/risk
table, a historical trend chart, and links out to the interactive
topology graph and the ATT&CK Navigator layer.

Run alongside main.py:

    python main.py --demo                 # produces scan_results.json + history/
    python dashboard.py                    # serves the dashboard at :5000

Security note: this serves vulnerability data about your network over
plain HTTP with no encryption. Fine on localhost/a trusted LAN for a
demo; do NOT expose it directly to the internet. Set DASHBOARD_PASSWORD
to require HTTP basic auth -- without it the dashboard is unauthenticated
and prints a warning on startup.
"""

import glob
import json
import os
import subprocess
import sys
import threading
from datetime import datetime
from functools import wraps

from flask import Flask, Response, jsonify, request, send_file
from jinja2 import Environment

from risk import TIER_COLORS

app = Flask(__name__)

DATA_DIR = os.environ.get("NETMAP_DATA_DIR", ".")
HISTORY_DIR = os.path.join(DATA_DIR, "history")
LATEST_SCAN_PATH = os.path.join(DATA_DIR, "scan_results.json")
TOPOLOGY_PATH = os.path.join(DATA_DIR, "topology.html")
NAVIGATOR_LAYER_PATH = os.path.join(DATA_DIR, "attack_navigator_layer.json")

DASHBOARD_PASSWORD = os.environ.get("DASHBOARD_PASSWORD")
# Scanning is only triggerable from the dashboard if explicitly opted into,
# and the range is fixed server-side (from env), never taken from the request.
ALLOW_SCAN_TRIGGER = os.environ.get("NETMAP_ALLOW_SCAN_TRIGGER") == "1"
SCAN_RANGE = os.environ.get("NETMAP_RANGE", "192.168.1.0/24")

_scan_lock = threading.Lock()
_scan_running = False


def require_auth(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not DASHBOARD_PASSWORD:
            return f(*args, **kwargs)
        auth = request.authorization
        if not auth or auth.password != DASHBOARD_PASSWORD:
            return Response(
                "Authentication required", 401,
                {"WWW-Authenticate": 'Basic realm="NetMap Dashboard"'},
            )
        return f(*args, **kwargs)
    return wrapper


def load_latest():
    if not os.path.exists(LATEST_SCAN_PATH):
        return None
    with open(LATEST_SCAN_PATH) as f:
        return json.load(f)


def load_history():
    """Returns [(timestamp_str, hosts_dict), ...] sorted oldest -> newest."""
    if not os.path.isdir(HISTORY_DIR):
        return []
    results = []
    for path in sorted(glob.glob(os.path.join(HISTORY_DIR, "scan_*.json"))):
        ts = os.path.basename(path)[len("scan_"):-len(".json")]
        try:
            with open(path) as f:
                hosts = json.load(f)
            results.append((ts, hosts))
        except (json.JSONDecodeError, OSError):
            continue
    return results


def summarize_hosts(hosts):
    counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0, "none": 0}
    total_cves = 0
    total_ports = 0
    for data in hosts.values():
        tier = data.get("risk", {}).get("tier", "none")
        counts[tier] = counts.get(tier, 0) + 1
        total_cves += data.get("risk", {}).get("cve_count", 0)
        total_ports += len(data.get("services", {}))
    return {"host_count": len(hosts), "total_cves": total_cves, "total_ports": total_ports, **counts}


# --- API -----------------------------------------------------------------

@app.route("/api/latest")
@require_auth
def api_latest():
    data = load_latest()
    if data is None:
        return jsonify({"error": "no scan_results.json found yet -- run main.py first"}), 404
    return jsonify(data)


@app.route("/api/history")
@require_auth
def api_history():
    history = load_history()
    return jsonify([{"timestamp": ts, **summarize_hosts(hosts)} for ts, hosts in history])


@app.route("/api/host/<path:ip>")
@require_auth
def api_host(ip):
    data = load_latest()
    if not data or ip not in data.get("hosts", {}):
        return jsonify({"error": "host not found in latest scan"}), 404
    return jsonify(data["hosts"][ip])


@app.route("/api/scan", methods=["POST"])
@require_auth
def api_trigger_scan():
    global _scan_running
    if not ALLOW_SCAN_TRIGGER:
        return jsonify({"error": "scan triggering is disabled "
                                  "(set NETMAP_ALLOW_SCAN_TRIGGER=1 to enable)"}), 403
    with _scan_lock:
        if _scan_running:
            return jsonify({"status": "already running"}), 409
        _scan_running = True

    def _run():
        global _scan_running
        try:
            # Fixed args from server-side config only -- never from the request,
            # so this endpoint can't be used to make NetMap scan arbitrary targets.
            subprocess.run(
                [sys.executable, os.path.join(os.path.dirname(__file__), "main.py"),
                 "--range", SCAN_RANGE, "--output", LATEST_SCAN_PATH],
                cwd=DATA_DIR, timeout=1800,
            )
        finally:
            _scan_running = False

    threading.Thread(target=_run, daemon=True).start()
    return jsonify({"status": "scan started", "range": SCAN_RANGE})


@app.route("/report")
@require_auth
def report_page():
    report_path = os.path.join(DATA_DIR, "report.html")
    if not os.path.exists(report_path):
        return "No report.html yet -- run main.py first.", 404
    return send_file(report_path)


@app.route("/topology")
@require_auth
def topology():
    if os.path.exists(TOPOLOGY_PATH):
        return send_file(TOPOLOGY_PATH)
    # main.py falls back to a static .png here if pyvis isn't installed
    png_fallback = os.path.join(DATA_DIR, "topology.png")
    if os.path.exists(png_fallback):
        return send_file(png_fallback)
    return "No topology.html/topology.png yet -- run main.py first.", 404


@app.route("/attack-navigator-layer.json")
@require_auth
def navigator_layer():
    if not os.path.exists(NAVIGATOR_LAYER_PATH):
        return "No attack_navigator_layer.json yet -- run main.py first.", 404
    return send_file(NAVIGATOR_LAYER_PATH, as_attachment=True)


# --- Page ------------------------------------------------------------------

_env = Environment(autoescape=True)  # scan data includes attacker-controlled nmap banners
PAGE = _env.from_string("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>NetMap Dashboard</title>
<script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
<style>
  body { font-family: -apple-system, Segoe UI, Helvetica, Arial, sans-serif;
         background: #0f1115; color: #e6e6e6; margin: 0; padding: 2rem; }
  h1 { margin: 0 0 0.25rem 0; }
  .meta { color: #999; margin-bottom: 1.5rem; }
  .row { display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 1.5rem; }
  .stat { background: #1a1d24; border-radius: 8px; padding: 1rem 1.5rem; min-width: 110px; }
  .stat .n { font-size: 1.8rem; font-weight: 700; }
  .stat .l { color: #999; font-size: 0.8rem; }
  .panel { background: #1a1d24; border-radius: 10px; padding: 1.25rem; margin-bottom: 1.5rem; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 0.5rem 0.75rem; border-bottom: 1px solid #2a2d35; }
  th { color: #999; font-size: 0.8rem; text-transform: uppercase; }
  .badge { display: inline-block; padding: 0.15rem 0.6rem; border-radius: 999px;
           font-size: 0.75rem; font-weight: 700; color: #111; }
  a { color: #7fb3ff; }
  .actions { margin-bottom: 1.5rem; display: flex; gap: 0.75rem; align-items: center; }
  button { background: #2a2d35; color: #eee; border: none; border-radius: 6px;
           padding: 0.5rem 1rem; cursor: pointer; }
  button:hover { background: #383c47; }
  #scan-status { color: #999; font-size: 0.85rem; }
</style>
</head>
<body>
  <h1>NetMap Dashboard</h1>
  <div class="meta">
    {% if data %}Last scan: {{ data.timestamp }} &middot; range {{ data.range }}{% else %}No scan data yet -- run <code>python main.py</code>{% endif %}
  </div>

  <div class="actions">
    <a href="/topology"><button>Open interactive topology</button></a>
    <a href="/report"><button>Open full report</button></a>
    <a href="/attack-navigator-layer.json"><button>Download ATT&amp;CK layer</button></a>
    {% if allow_scan %}<button onclick="triggerScan()">Run new scan</button>{% endif %}
    <span id="scan-status"></span>
  </div>

  {% if summary %}
  <div class="row">
    <div class="stat"><div class="n">{{ summary.host_count }}</div><div class="l">Hosts</div></div>
    <div class="stat"><div class="n">{{ summary.total_ports }}</div><div class="l">Open ports</div></div>
    <div class="stat"><div class="n">{{ summary.total_cves }}</div><div class="l">CVEs</div></div>
    <div class="stat"><div class="n">{{ summary.critical }}</div><div class="l">Critical hosts</div></div>
    <div class="stat"><div class="n">{{ summary.high }}</div><div class="l">High hosts</div></div>
  </div>
  {% endif %}

  {% if history|length > 1 %}
  <div class="panel">
    <canvas id="trendChart" height="80"></canvas>
  </div>
  {% endif %}

  {% if hosts %}
  <div class="panel">
    <table>
      <tr><th>Host</th><th>Vendor</th><th>Risk</th><th>Open ports</th><th>CVEs</th><th>ATT&amp;CK</th><th>Recommended actions</th></tr>
      {% for ip, d in hosts.items() %}
      <tr{% if d.rogue %} style="background:#2a1418;"{% endif %}>
        <td>{{ ip }}{% if d.rogue %}<br><span class="badge" style="background:#e74c3c;">NOT IN ALLOWLIST</span>{% endif %}</td>
        <td>{{ d.vendor or '—' }}</td>
        <td><span class="badge" style="background: {{ d.risk.color }}">{{ d.risk.tier|upper }}</span></td>
        <td>{{ d.services|length }}</td>
        <td>
          {% set all_cves = [] %}
          {% for svc in d.services.values() %}{% for c in svc.cves %}{% set _ = all_cves.append(c) %}{% endfor %}{% endfor %}
          {% if all_cves %}
            {% for c in all_cves[:6] %}
              <div class="cve"><a href="{{ c.url }}">{{ c.id }}</a> <span class="badge" style="background:{{ tier_colors[c.severity.lower()] if c.severity.lower() in tier_colors else '#95a5a6' }}; font-size:0.65rem;">{{ c.severity }}</span>{% if c.epss %} <span style="color:#e67e22; font-size:0.75rem;">EPSS {{ (c.epss * 100)|round(1) }}%</span>{% endif %}</div>
            {% endfor %}
            {% if all_cves|length > 6 %}<div class="empty">+{{ all_cves|length - 6 }} more</div>{% endif %}
          {% else %}
            <span class="empty">none found</span>
          {% endif %}
        </td>
        <td>{{ d.techniques|map(attribute='id')|join(', ') }}</td>
        <td>
          {% if d.mitigations %}
          <details>
            <summary>Actions</summary>
            <div style="max-width:280px; font-size:0.85rem; margin-top:0.4rem;">
              {{ d.mitigations.priority }}
              <ul style="padding-left:1.1rem;">
                {% for a in d.mitigations.service_actions %}<li>{{ a }}</li>{% endfor %}
              </ul>
            </div>
          </details>
          {% else %}
            <span class="empty">n/a</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </table>
  </div>
  {% endif %}

<script>
const historyData = {{ history_json|safe }};
if (historyData.length > 1) {
  const ctx = document.getElementById('trendChart');
  new Chart(ctx, {
    type: 'line',
    data: {
      labels: historyData.map(h => h.timestamp),
      datasets: [
        {label: 'Critical', data: historyData.map(h => h.critical), borderColor: '#c0392b', tension: 0.2},
        {label: 'High', data: historyData.map(h => h.high), borderColor: '#e67e22', tension: 0.2},
        {label: 'Medium', data: historyData.map(h => h.medium), borderColor: '#f1c40f', tension: 0.2},
        {label: 'Hosts', data: historyData.map(h => h.host_count), borderColor: '#7fb3ff', tension: 0.2},
      ]
    },
    options: { responsive: true, plugins: { legend: { labels: { color: '#eee' } } },
               scales: { x: { ticks: { color: '#999' } }, y: { ticks: { color: '#999' }, beginAtZero: true } } }
  });
}

function triggerScan() {
  document.getElementById('scan-status').textContent = 'Scan started...';
  fetch('/api/scan', {method: 'POST'})
    .then(r => r.json())
    .then(d => { document.getElementById('scan-status').textContent = d.status || d.error; })
    .catch(() => { document.getElementById('scan-status').textContent = 'Failed to start scan.'; });
}
</script>
</body>
</html>
""")


@app.route("/")
@require_auth
def index():
    data = load_latest()
    history = load_history()
    history_summaries = [{"timestamp": ts, **summarize_hosts(hosts)} for ts, hosts in history]

    return PAGE.render(
        data=data,
        hosts=(data or {}).get("hosts", {}),
        summary=summarize_hosts(data["hosts"]) if data else None,
        history=history_summaries,
        history_json=json.dumps(history_summaries),
        allow_scan=ALLOW_SCAN_TRIGGER,
        tier_colors=TIER_COLORS,
    )


if __name__ == "__main__":
    if not DASHBOARD_PASSWORD:
        print("WARNING: DASHBOARD_PASSWORD is not set -- this dashboard is running "
              "without authentication. Fine for localhost-only use; set "
              "DASHBOARD_PASSWORD before exposing it to any shared network.")
    app.run(host="127.0.0.1", port=5000, debug=False)
