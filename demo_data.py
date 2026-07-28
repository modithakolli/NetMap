"""
Synthetic scan data so the full pipeline (CVE lookup optional, risk
scoring, MITRE mapping, viz, report) can be demoed or tested without a
live network, root privileges, or nmap installed. Handy for a demo in
front of a professor/interviewer, or for CI.

Version strings are chosen to correspond to services with well-known
historical CVEs, so the CVE-lookup step (when not skipped) returns
believable, real results.
"""

def generate_demo_hosts():
    return {
        "192.168.1.1": {
            22: {"protocol": "tcp", "state": "open", "name": "ssh",
                 "product": "OpenSSH", "version": "7.2", "extrainfo": ""},
            80: {"protocol": "tcp", "state": "open", "name": "http",
                 "product": "nginx", "version": "1.14.0", "extrainfo": ""},
        },
        "192.168.1.10": {
            445: {"protocol": "tcp", "state": "open", "name": "microsoft-ds",
                  "product": "Samba", "version": "4.3.11", "extrainfo": ""},
            3389: {"protocol": "tcp", "state": "open", "name": "ms-wbt-server",
                   "product": "Microsoft Terminal Services", "version": "", "extrainfo": ""},
        },
        "192.168.1.25": {
            21: {"protocol": "tcp", "state": "open", "name": "ftp",
                 "product": "vsftpd", "version": "2.3.4", "extrainfo": ""},
            23: {"protocol": "tcp", "state": "open", "name": "telnet",
                 "product": "", "version": "", "extrainfo": ""},
        },
        "192.168.1.40": {
            443: {"protocol": "tcp", "state": "open", "name": "https",
                  "product": "Apache httpd", "version": "2.4.49", "extrainfo": ""},
            3306: {"protocol": "tcp", "state": "open", "name": "mysql",
                   "product": "MySQL", "version": "5.5.60", "extrainfo": ""},
        },
        "192.168.1.77": {  # not in the sample allowlist -- demos rogue-device detection
            23: {"protocol": "tcp", "state": "open", "name": "telnet",
                 "product": "", "version": "", "extrainfo": ""},
        },
    }


def generate_demo_details():
    """MAC/vendor info paired with generate_demo_hosts(), for the OUI-lookup demo."""
    return {
        "192.168.1.1": {"mac": "F0:27:2D:AA:BB:CC", "nmap_vendor": None},   # Ubiquiti (via local OUI table)
        "192.168.1.10": {"mac": "00:15:17:11:22:33", "nmap_vendor": None},  # Dell
        "192.168.1.25": {"mac": "AA:BB:CC:DD:EE:FF", "nmap_vendor": None},  # unknown OUI
        "192.168.1.40": {"mac": "B8:27:EB:12:34:56", "nmap_vendor": None},  # Raspberry Pi
        "192.168.1.77": {"mac": "11:22:33:44:55:66", "nmap_vendor": None},  # unknown -- rogue device
    }
