import argparse
import time

from scanner import scan_network_details, scan_services
from cve_lookup import enrich_host_services
from epss import enrich_host_services_with_epss
from risk import score_host
from mitre_mapping import map_host_techniques, export_navigator_layer
from osint import enrich_host_osint
from oui import lookup_vendor
from mitigation import mitigations_for_host
from inventory import load_allowlist, flag_rogue_hosts, init_allowlist_from_scan
from alerting import maybe_alert
from nuclei_scan import scan_host_web_services
from topology import build_topology
from visualizer import visualize_graph_interactive, visualize_graph_static
from storage import save_to_json
from history import save_snapshot, load_previous_scan, diff_scans
from report import generate_html_report
from demo_data import generate_demo_hosts, generate_demo_details


def build_arg_parser():
    parser = argparse.ArgumentParser(description="NetMap: Network Topology Visualizer")
    parser.add_argument("--range", type=str, default="192.168.1.0/24",
                         help="CIDR to scan. Also accepts a comma-separated list of CIDRs "
                              "(e.g. '192.168.1.0/24,192.168.2.0/24') to cover multiple "
                              "subnets/VLANs in one run, or the literal 'auto' to detect "
                              "your current local /24.")
    parser.add_argument("--interval", type=int, default=0, help="Run scan periodically every X seconds (0 = once)")
    parser.add_argument("--output", type=str, default="scan_results.json", help="JSON output file")
    parser.add_argument("--full-scan", action="store_true", help="Scan all ports, not just common ones (slower)")
    parser.add_argument("--no-cve", action="store_true", help="Skip CVE lookups (faster, fully offline)")
    parser.add_argument("--no-epss", action="store_true",
                         help="Skip EPSS (exploit probability) enrichment, even if CVE lookup runs")
    parser.add_argument("--nvd-api-key", type=str, default=None, help="NVD API key (or set NVD_API_KEY env var)")
    parser.add_argument("--shodan", action="store_true", help="Enable Shodan OSINT lookups for public IPs")
    parser.add_argument("--no-whois", action="store_true", help="Disable WHOIS lookups for public IPs")
    parser.add_argument("--static", action="store_true", help="Use static Matplotlib graph instead of interactive pyvis")
    parser.add_argument("--graph-output", type=str, default=None,
                         help="Topology graph output path (default topology.html or topology.png with --static)")
    parser.add_argument("--html-report", type=str, default="report.html", help="HTML report output path")
    parser.add_argument("--navigator-layer", type=str, default="attack_navigator_layer.json",
                         help="MITRE ATT&CK Navigator layer JSON output path")
    parser.add_argument("--history-dir", type=str, default="history", help="Directory to keep scan snapshots in")
    parser.add_argument("--no-history", action="store_true", help="Don't save/diff against scan history")
    parser.add_argument("--demo", action="store_true",
                         help="Use synthetic sample data instead of a real nmap scan "
                              "(no network/root/nmap required)")
    parser.add_argument("--allowlist", type=str, default="known_devices.json",
                         help="Path to a known-good device allowlist for rogue-device detection "
                              "(see known_devices.sample.json). If the file doesn't exist, "
                              "rogue-device detection is skipped.")
    parser.add_argument("--init-allowlist", action="store_true",
                         help="Write every host found in this scan into --allowlist as trusted, "
                              "then continue as normal. Use this once to bootstrap a baseline.")
    parser.add_argument("--mac-lookup-online", action="store_true",
                         help="Fall back to api.macvendors.com for OUI vendor lookups not covered "
                              "by nmap's own DB or the small local table (rate-limited, cached)")
    parser.add_argument("--nuclei", action="store_true",
                         help="Run Nuclei against detected HTTP/HTTPS services for deeper active "
                              "checks. Requires the separate `nuclei` binary; degrades gracefully "
                              "with a note if it isn't installed.")
    parser.add_argument("--alert-email", action="store_true",
                         help="Email a summary when new hosts/CVEs/rogue devices are found "
                              "(needs ALERT_EMAIL_TO, SMTP_HOST, SMTP_USER, SMTP_PASSWORD env vars)")
    parser.add_argument("--alert-slack", action="store_true",
                         help="Post a summary to Slack when new hosts/CVEs/rogue devices are found "
                              "(needs SLACK_WEBHOOK_URL env var)")
    parser.add_argument("--verbose", action="store_true", help="Print extra detail during CVE/OSINT lookups")
    return parser


def run_scan(args):
    graph_output = args.graph_output or ("topology.png" if args.static else "topology.html")

    print(f"\n=== NetMap scan: {args.range} ===")

    # 1. Discovery + service detection (+ MAC/vendor for asset inventory)
    if args.demo:
        print("[demo mode] using synthetic sample hosts instead of a live scan")
        raw_hosts = generate_demo_hosts()
        device_details = generate_demo_details()
    else:
        device_details = scan_network_details(args.range)
        raw_hosts = {
            host: scan_services(host, full_scan=args.full_scan)
            for host in device_details.keys()
        }

    # 2. CVE enrichment + risk scoring + MITRE mapping + OSINT + Nuclei + mitigations
    scan_hosts = {}
    for host, services in raw_hosts.items():
        if not args.no_cve:
            enrich_host_services(services, api_key=args.nvd_api_key, verbose=args.verbose)
            if not args.no_epss:
                enrich_host_services_with_epss(services, verbose=args.verbose)

        if args.nuclei:
            scan_host_web_services(host, services, verbose=args.verbose)

        risk = score_host(services)
        techniques = sorted(
            [{"id": tid, "name": tname} for tid, tname in map_host_techniques(services)],
            key=lambda t: t["id"],
        )
        osint = enrich_host_osint(
            host, enable_shodan=args.shodan, enable_whois=not args.no_whois, verbose=args.verbose
        )

        detail = device_details.get(host, {})
        vendor = lookup_vendor(detail.get("mac"), nmap_vendor=detail.get("nmap_vendor"),
                                use_online=args.mac_lookup_online)

        scan_hosts[host] = {
            "services": services,
            "risk": risk,
            "techniques": techniques,
            "osint": osint,
            "mac": detail.get("mac"),
            "vendor": vendor,
            "mitigations": mitigations_for_host(services, risk["tier"], risk.get("top_priority_cve")),
        }

    # 3. Rogue device detection against the allowlist
    if args.init_allowlist:
        init_allowlist_from_scan(scan_hosts, args.allowlist)
        print(f"[init-allowlist] wrote {len(scan_hosts)} host(s) to {args.allowlist} as trusted")
    allowlist = load_allowlist(args.allowlist)
    rogue_hosts = flag_rogue_hosts(scan_hosts, allowlist)
    if not allowlist:
        print(f"[rogue-detection] no allowlist found at {args.allowlist} -- "
              f"skipping (see --init-allowlist or known_devices.sample.json)")

    # 4. History diffing
    diff = None
    if not args.no_history:
        previous = load_previous_scan(args.history_dir)
        diff = diff_scans(previous, scan_hosts)
        save_snapshot(scan_hosts, args.history_dir)

    # 5. Alerting
    if args.alert_email or args.alert_slack:
        maybe_alert(args.range, diff, scan_hosts, rogue_hosts,
                    alert_email=args.alert_email, alert_slack=args.alert_slack, verbose=args.verbose)

    # 6. Persist raw results
    save_to_json(scan_hosts, args.range, args.output)

    # 7. Topology graph
    G = build_topology(scan_hosts)
    if args.static:
        actual_graph_output = visualize_graph_static(G, graph_output)
    else:
        actual_graph_output = visualize_graph_interactive(G, graph_output)

    # 8. MITRE ATT&CK Navigator layer
    export_navigator_layer(scan_hosts, args.navigator_layer, layer_name=f"NetMap scan {args.range}")

    # 9. HTML report
    generate_html_report(scan_hosts, scan_range=args.range, diff=diff, output_path=args.html_report)

    # 10. Console summary
    print("\n--- Summary ---")
    for host, data in sorted(scan_hosts.items(), key=lambda kv: kv[0]):
        r = data["risk"]
        rogue_flag = " [ROGUE]" if data.get("rogue") else ""
        vendor_str = f" ({data['vendor']})" if data.get("vendor") else ""
        print(f"  {host:15s}{vendor_str}{rogue_flag}  {len(data['services'])} port(s)  "
              f"risk={r['tier'].upper():8s}  cves={r['cve_count']}")
    if rogue_hosts:
        print(f"\n  !! {len(rogue_hosts)} unrecognized/rogue device(s): {', '.join(rogue_hosts)}")
    print(f"\nGraph:      {actual_graph_output}")
    print(f"Report:     {args.html_report}")
    print(f"ATT&CK layer: {args.navigator_layer}  (import at https://mitre-attack.github.io/attack-navigator/)")
    print(f"JSON:       {args.output}\n")


def main():
    args = build_arg_parser().parse_args()

    if args.interval > 0:
        try:
            while True:
                run_scan(args)
                print(f"Sleeping for {args.interval} seconds...\n")
                time.sleep(args.interval)
        except KeyboardInterrupt:
            print("\nScan interrupted by user.")
    else:
        run_scan(args)


if __name__ == "__main__":
    main()
