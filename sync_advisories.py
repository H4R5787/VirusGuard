"""
sync_advisories.py — Standalone CLI Command for Scheduled Cron Ingestion

Can be executed manually or as an external cron job / Render Cron Job:
    python sync_advisories.py
"""

import sys
from app import app, db, SecurityAdvisory, ThreatVector, ThreatIntelUpdate
from advisory_service import sync_latest_advisories
from threat_intel_service import sync_threat_intelligence

def main():
    print("[sync_all] Triggering live threat advisory and knowledge base synchronization...")
    with app.app_context():
        try:
            adv_new, adv_total = sync_latest_advisories(db.session, SecurityAdvisory)
            print(f"[sync_all] Advisories complete: Added {adv_new} new. Total: {adv_total}")
            
            intel_new, intel_total = sync_threat_intelligence(db.session, ThreatVector, ThreatIntelUpdate)
            print(f"[sync_all] Threat Intel complete: Added {intel_new} updates. Total: {intel_total}")
            return 0
        except Exception as err:
            print(f"[sync_all] Error during synchronization: {err}", file=sys.stderr)
            return 1

if __name__ == '__main__':
    sys.exit(main())
