# Scanning your whole network

`--range` covers whatever CIDR you give it — e.g. `192.168.1.0/24` covers
every address on that subnet (up to 254 hosts), which is "all devices" on
a typical home/lab LAN as long as they're on the same subnet as you and
respond to discovery. A few things worth knowing:

- On a local Ethernet/Wi-Fi segment, nmap automatically uses **ARP**
  requests instead of ICMP ping for the sweep, which is why it generally
  finds devices that have ping blocked by their firewall.
- `--range auto` detects your current local `/24` automatically — no need
  to look up your subnet manually.
- `--range "192.168.1.0/24,192.168.2.0/24"` scans multiple subnets/VLANs
  in one run (comma-separated).
- This can only reach networks your machine has an actual route to. It
  can't discover devices on an unrelated segment (a neighbor's Wi-Fi, a
  different building's VLAN you're not on) — that's a routing/physical
  access limitation, not something the tool can work around, and scanning
  networks you're not authorized on is out of scope regardless.
- IPv6-only devices won't show up in an IPv4 CIDR scan.
