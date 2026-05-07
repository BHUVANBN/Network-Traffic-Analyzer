# Improvement #21 — Email alert notifications via smtplib (standard library)
import smtplib
import threading
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

_notified = set()   # Deduplicate: don't re-email the same alert


def send_email_alert(alert: dict, config: dict):
    """
    Sends an email for a critical alert in a background thread.
    config keys: smtp_host, smtp_port, smtp_user, smtp_pass, to_email
    """
    key = f"{alert['type']}|{alert['message']}"
    if key in _notified:
        return
    _notified.add(key)

    def _send():
        try:
            msg = MIMEMultipart()
            msg["From"]    = config["smtp_user"]
            msg["To"]      = config["to_email"]
            msg["Subject"] = f"[Sentinel] {alert['type']} — {alert['severity']} Severity"
            body = (
                f"Sentinel Network Analyzer — Threat Detected\n\n"
                f"Type     : {alert['type']}\n"
                f"Severity : {alert['severity']}\n"
                f"Detail   : {alert['message']}\n"
            )
            msg.attach(MIMEText(body, "plain"))
            with smtplib.SMTP(config["smtp_host"], int(config["smtp_port"])) as srv:
                srv.starttls()
                srv.login(config["smtp_user"], config["smtp_pass"])
                srv.sendmail(config["smtp_user"], config["to_email"], msg.as_string())
            print(f"Email sent: {alert['type']}")
        except Exception as e:
            print(f"Email failed: {e}")

    threading.Thread(target=_send, daemon=True).start()


def reset_notifications():
    _notified.clear()
