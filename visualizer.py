"""
Renders the topology graph. Prefers an interactive pyvis HTML graph
(color-coded by risk tier, hover tooltips with CVE/ATT&CK detail);
falls back to the original static Matplotlib plot if pyvis isn't
installed, or if --static is passed explicitly.
"""

import html as _html

import networkx as nx

from risk import TIER_COLORS

PORT_COLOR = "#5dade2"


def _e(value):
    """Escape attacker-controllable data (nmap banners, hostnames, etc.)
    before it goes into a pyvis `title` (rendered as raw HTML by vis-network).
    A malicious host can set its own service banner, so this isn't optional."""
    return _html.escape(str(value), quote=True)


def _host_tooltip(node, attrs):
    lines = [f"<b>{_e(node)}</b>"]
    if attrs.get("vendor"):
        lines.append(f"Vendor: {_e(attrs['vendor'])}")
    if attrs.get("rogue"):
        lines.append("<b>&#9888; NOT in allowlist (rogue/unrecognized)</b>")
    lines.append(f"Risk tier: {_e(attrs.get('risk_tier', 'none').upper())}")
    if attrs.get("cve_count"):
        lines.append(f"CVE count: {attrs['cve_count']}")
    techniques = attrs.get("techniques") or []
    if techniques:
        tech_str = ", ".join(_e(t["id"]) for t in techniques[:6])
        lines.append(f"ATT&amp;CK: {tech_str}")
    osint = attrs.get("osint") or {}
    if osint.get("shodan", {}).get("org"):
        lines.append(f"Org (Shodan): {_e(osint['shodan']['org'])}")
    top_action = (attrs.get("mitigations") or {}).get("service_actions", [])
    if top_action:
        lines.append(f"Top action: {_e(top_action[0])}")
    return "<br>".join(lines)


def _port_tooltip(node, attrs):
    label = _e(attrs.get("service", "unknown"))
    if attrs.get("product"):
        label += f" ({_e(attrs['product'])} {_e(attrs.get('version', ''))})".rstrip()
    lines = [f"<b>{_e(node)}</b>", label]
    cves = attrs.get("cves") or []
    if cves:
        lines.append(f"{len(cves)} known CVE(s), worst score {attrs.get('worst_score')}")
        for c in cves[:3]:
            lines.append(f"&bull; {_e(c['id'])} ({_e(c.get('severity', '?'))})")
    else:
        lines.append("No known CVEs found")
    return "<br>".join(lines)


def visualize_graph_interactive(G, output_path="topology.html"):
    try:
        from pyvis.network import Network
    except ImportError:
        fallback_path = (
            output_path.rsplit(".", 1)[0] + ".png"
            if output_path.lower().endswith(".html") else output_path
        )
        print(f"[visualizer] pyvis not installed (pip install pyvis) -- "
              f"falling back to a static Matplotlib PNG at {fallback_path} "
              f"instead of {output_path}.")
        return visualize_graph_static(G, fallback_path)

    net = Network(height="800px", width="100%", bgcolor="#111318", font_color="#eeeeee")
    net.barnes_hut()

    for node, attrs in G.nodes(data=True):
        if attrs.get("kind") == "host":
            net.add_node(
                node,
                label=("\u26a0 " if attrs.get("rogue") else "") + node,
                title=_host_tooltip(node, attrs),
                color=attrs.get("color", TIER_COLORS["none"]),
                shape="triangle" if attrs.get("rogue") else "dot",
                size=28 if attrs.get("rogue") else 25,
                borderWidth=3 if attrs.get("rogue") else 1,
            )
        else:
            cve_count = attrs.get("cve_count", 0)
            color = "#c0392b" if cve_count else PORT_COLOR
            net.add_node(
                node,
                label=f"{attrs.get('port')}/{attrs.get('service')}",
                title=_port_tooltip(node, attrs),
                color=color,
                shape="dot",
                size=12,
            )

    for src, dst in G.edges():
        net.add_edge(src, dst, color="#555555")

    net.set_options("""
    {
      "physics": {"stabilization": {"iterations": 150}},
      "interaction": {"hover": true}
    }
    """)

    net.write_html(output_path, notebook=False, open_browser=False)
    print(f"Interactive topology written to {output_path}")
    return output_path


def visualize_graph_static(G, output_path=None):
    """Original Matplotlib rendering, now colored by risk tier where available."""
    import matplotlib
    matplotlib.use("Agg")
    import matplotlib.pyplot as plt

    pos = nx.spring_layout(G, seed=42)
    node_colors = [
        attrs.get("color", PORT_COLOR if attrs.get("kind") == "port" else TIER_COLORS["none"])
        for _, attrs in G.nodes(data=True)
    ]
    labels = {
        node: ("\u26a0 " + node if attrs.get("rogue") else node)
        for node, attrs in G.nodes(data=True)
    }

    plt.figure(figsize=(12, 8))
    nx.draw(
        G, pos, labels=labels, with_labels=True, node_color=node_colors,
        edge_color="gray", node_size=900, font_size=8,
    )
    plt.title("Network Topology (colored by risk tier; \u26a0 = not in allowlist)")

    if output_path:
        plt.savefig(output_path, dpi=150, bbox_inches="tight")
        print(f"Static topology image written to {output_path}")
        plt.close()
        return output_path

    plt.show()
    return None


# Kept for backwards compatibility with the original entry point name.
def visualize_graph(G):
    visualize_graph_static(G)
