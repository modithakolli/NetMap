# Alerting

```bash
export SLACK_WEBHOOK_URL=https://hooks.slack.com/services/...
sudo python main.py --range 192.168.1.0/24 --alert-slack

# or email:
export ALERT_EMAIL_TO=you@example.com
export SMTP_HOST=smtp.gmail.com
export SMTP_USER=you@gmail.com
export SMTP_PASSWORD=an-app-password
sudo python main.py --range 192.168.1.0/24 --alert-email
```

Fires when there are new hosts, newly-appeared CVEs, rogue devices, or any
currently critical-risk host. Both alert channels fail silently (with a
printed warning) if not configured — a missing webhook/SMTP config never
crashes a scan. Email uses Python's stdlib `smtplib`, no extra dependency;
Slack is a single webhook POST via `requests`.
