"""
advisory_scheduler.py — Automated Daily Ingestion Scheduler for VirusGuard

Executes automated updates every day at 12:00 AM (Midnight) for both:
1. Vulnerability Advisories & Security Alerts (Post.html)
2. Threat Intelligence Knowledge Base (Attacks.html & attack_detail.html)

Runs in a dedicated background daemon thread without requiring manual intervention.
"""

import threading
import time
from datetime import datetime, timedelta, timezone

_scheduler_started = False
_lock = threading.Lock()


def seconds_until_midnight() -> float:
    """Calculates the exact number of seconds remaining until next 12:00 AM."""
    now = datetime.now()
    tomorrow = now.date() + timedelta(days=1)
    next_midnight = datetime.combine(tomorrow, datetime.min.time())
    delta = (next_midnight - now).total_seconds()
    # Add a 2-second buffer to ensure midnight boundary has passed
    return max(delta + 2.0, 10.0)


def _scheduler_loop(app, db_session_getter, advisory_model, vector_model, intel_update_model):
    """Background daemon loop that triggers synchronization every day at 12:00 AM."""
    from advisory_service import sync_latest_advisories
    from threat_intel_service import sync_threat_intelligence

    # 1. Initial quick sync on startup (after 5 seconds buffer)
    time.sleep(5)
    with app.app_context():
        try:
            print("[scheduler] Running initial startup synchronization...")
            adv_new, adv_tot = sync_latest_advisories(db_session_getter(), advisory_model)
            intel_new, intel_tot = sync_threat_intelligence(db_session_getter(), vector_model, intel_update_model)
            print(f"[scheduler] Startup sync complete. Advisories: {adv_tot}, Threat Intel Updates: {intel_tot}")
        except Exception as err:
            print(f"[scheduler] Startup sync error: {err}")

    # 2. Main Midnight Loop (Runs every day at 12:00 AM)
    while True:
        wait_seconds = seconds_until_midnight()
        next_run_time = datetime.now() + timedelta(seconds=wait_seconds)
        print(f"[scheduler] Next scheduled 12:00 AM run at: {next_run_time.strftime('%Y-%m-%d %H:%M:%S')} (in {int(wait_seconds)}s)")

        time.sleep(wait_seconds)

        with app.app_context():
            try:
                print("[scheduler] 12:00 AM Triggered — Syncing Threat Knowledge Base & Advisories...")
                adv_new, adv_tot = sync_latest_advisories(db_session_getter(), advisory_model)
                intel_new, intel_tot = sync_threat_intelligence(db_session_getter(), vector_model, intel_update_model)
                print(f"[scheduler] Ingestion complete: +{adv_new} advisories, +{intel_new} threat intel updates. Catalog: {adv_tot} adv / {intel_tot} intel.")
            except Exception as err:
                print(f"[scheduler] Scheduled ingestion error: {err}")


def start_advisory_scheduler(app, db_session_getter, advisory_model, vector_model, intel_update_model):
    """Initializes and launches the automated daily midnight scheduler thread."""
    global _scheduler_started
    with _lock:
        if _scheduler_started:
            return
        _scheduler_started = True

        thread = threading.Thread(
            target=_scheduler_loop,
            args=(app, db_session_getter, advisory_model, vector_model, intel_update_model),
            name="VirusGuard-Midnight-Ingestion-Scheduler",
            daemon=True
        )
        thread.start()
        print("[scheduler] Automated 12:00 AM background scheduler initialized for Advisories & Threat Knowledge Base.")
