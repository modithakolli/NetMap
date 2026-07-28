"""
Builds a NetworkX graph from enriched scan data, attaching risk/technique
metadata as node attributes so the visualizer and report can both draw
from a single structure.
"""

import networkx as nx


def build_topology(scan_hosts):
    """
    scan_hosts: {
        host_ip: {
            "services": {port: {name, product, version, cves: [...]}},
            "risk": {tier, color, cve_count, ...},
            "techniques": [{"id":..., "name":...}, ...],
            "osint": {...},
        }
    }
    """
    G = nx.Graph()

    for host, data in scan_hosts.items():
        risk = data.get("risk", {})
        G.add_node(
            host,
            kind="host",
            risk_tier=risk.get("tier", "none"),
            color=risk.get("color", "#95a5a6"),
            cve_count=risk.get("cve_count", 0),
            techniques=data.get("techniques", []),
            osint=data.get("osint", {}),
            vendor=data.get("vendor"),
            rogue=data.get("rogue", False),
            mitigations=data.get("mitigations", {}),
        )

        for port, info in data.get("services", {}).items():
            port_node = f"{host}:{port}"
            cves = info.get("cves", [])
            worst_score = max((c["score"] for c in cves if c["score"] is not None), default=None)
            G.add_node(
                port_node,
                kind="port",
                host=host,
                port=port,
                service=info.get("name", "unknown"),
                product=info.get("product", ""),
                version=info.get("version", ""),
                cve_count=len(cves),
                worst_score=worst_score,
                cves=cves,
            )
            G.add_edge(host, port_node)

    return G
