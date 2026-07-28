"""
Alerting for newly-appeared critical/high CVEs, new hosts, and rogue
devices. Email uses stdlib smtplib (no new dependency); Slack uses a
simple Incoming Webhook POST. Both are best-effort -- a failed alert
should never crash a scan, just print a warning.
"""

import os
import smtplib
from email.mime.text import MIMEText

import requests


def send_email(subject, body, to_addr=None, smtp_host=None, smtp_port=None,
                smtp_user=None, smtp_password=None, verbose=False):
    to_addr = to_addr or os.environ.get("ALERT_EMAIL_TO")
    smtp_host = smtp_host or os.environ.get("SMTP_HOST")
    smtp_port = int(smtp_port or os.environ.get("SMTP_PORT", 587))
    smtp_user = smtp_user or os.environ.get("SMTP_USER")
    smtp_password = smtp_password or os.environ.get("SMTP_PASSWORD")

    if not (to_addr and smtp_host and smtp_user and smtp_password):
        if verbose:
            print("  [alert] email not configured (need ALERT_EMAIL_TO, SMTP_HOST, "
                  "SMTP_USER, SMTP_PASSWORD) -- skipping")
        return False

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = smtp_user
    msg["To"] = to_addr

    try:
        with smtplib.SMTP(smtp_host, smtp_port, timeout=15) as server:
            server.starttls()
            server.login(smtp_user, smtp_password)
            server.sendmail(smtp_user, [to_addr], msg.as_string())
        return True
    except (smtplib.SMTPException, OSError) as e:
        print(f"  [alert] email send failed: {e}")
        return False


def send_slack(text, webhook_url=None, verbose=False):
    webhook_url = webhook_url or os.environ.get("SLACK_WEBHOOK_URL")
    if not webhook_url:
        if verbose:
            print("  [alert] SLACK_WEBHOOK_URL not set -- skipping Slack alert")
        return False

    try:
        resp = requests.post(webhook_url, json={"text": text}, timeout=10)
        return resp.status_code == 200
    except requests.RequestException as e:
        print(f"  [alert] Slack send failed: {e}")
        return False


def build_alert_message(scan_range, diff, scan_hosts, rogue_hosts):
    lines = [f"NetMap scan alert -- {scan_range}"]

    if diff:
        if diff.get("new_hosts"):
            lines.append(f"New hosts: {', '.join(diff['new_hosts'])}")
        for host, ch in diff.get("host_changes", {}).items():
            if ch.get("new_cves"):
                lines.append(f"New CVEs on {host}: {', '.join(ch['new_cves'])}")

    if rogue_hosts:
        lines.append(f"Rogue/unrecognized devices: {', '.join(rogue_hosts)}")

    critical_hosts = [ip for ip, d in scan_hosts.items() if d.get("risk", {}).get("tier") == "critical"]
    if critical_hosts:
        lines.append(f"Currently critical-risk hosts: {', '.join(critical_hosts)}")

    if len(lines) == 1:
        return None  # nothing alert-worthy

    return "\n".join(lines)


def maybe_alert(scan_range, diff, scan_hosts, rogue_hosts, alert_email=False, alert_slack=False, verbose=False):
    message = build_alert_message(scan_range, diff, scan_hosts, rogue_hosts)
    if not message:
        return

    if alert_email:
        send_email(subject=f"NetMap alert: {scan_range}", body=message, verbose=verbose)
    if alert_slack:
        send_slack(message, verbose=verbose)
