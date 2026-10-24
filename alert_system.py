"""
alert_system.py — SOC Email Notification Dispatcher

Sends security notifications when a malicious payload is detected.
Fully configurable via environment variables with graceful fallback
and short network timeouts to prevent blocking web requests.
"""

import os
import smtplib
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart


def send_alert(file_path: str, virus_info: dict, filename: str = None) -> bool:
    """
    Dispatches an email alert to the security team when threats are detected.
    Fails gracefully if SMTP is not configured or server is unreachable.
    """
    smtp_server = os.getenv("SMTP_SERVER", "").strip()
    smtp_user = os.getenv("SMTP_USER", "").strip()
    smtp_password = os.getenv("SMTP_PASSWORD", "").strip()
    recipient = os.getenv("ALERT_RECIPIENT_EMAIL", "").strip()
    smtp_port = int(os.getenv("SMTP_PORT", "587"))

    # Skip sending if SMTP credentials are missing or placeholder
    if not smtp_server or "example.com" in smtp_server or not recipient:
        print("[alert_system] SMTP not configured. Notification skipped.")
        return False

    display_name = filename or os.path.basename(file_path)

    # Format malicious detections summary
    detected_engines = []
    if isinstance(virus_info, dict):
        for engine, data in virus_info.items():
            if isinstance(data, dict) and data.get("category") == "malicious":
                detected_engines.append(f"- {engine}: {data.get('result', 'Malicious')}")

    detection_summary = "\n".join(detected_engines[:15]) or "Malware detected by antivirus heuristics."

    body = f"""SECURITY ALERT: Malicious Payload Detected

File: {display_name}
Detection Summary:
{detection_summary}

Please review the VirusGuard dashboard for full AI threat analysis and containment steps.
"""

    try:
        msg = MIMEMultipart()
        msg["Subject"] = f"🚨 [VirusGuard Alert] Malware Detected: {display_name}"
        msg["From"] = smtp_user or "alerts@virusguard.security"
        msg["To"] = recipient
        msg.attach(MIMEText(body, "plain"))

        with smtplib.SMTP(smtp_server, smtp_port, timeout=5) as server:
            if os.getenv("SMTP_USE_TLS", "true").lower() in ("true", "1", "yes"):
                server.starttls()
            if smtp_user and smtp_password:
                server.login(smtp_user, smtp_password)
            server.sendmail(msg["From"], [recipient], msg.as_string())

        print(f"[alert_system] Security alert sent to {recipient} for {display_name}.")
        return True

    except Exception as err:
        print(f"[alert_system] Failed to dispatch alert: {err}")
        return False
