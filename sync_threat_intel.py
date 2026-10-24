"""
sync_threat_intel.py — Standalone CLI Command for Threat Intelligence Sync

Can be executed manually or as an external cron job / Render Cron Job:
    python sync_threat_intel.py
"""

import sys
from app import app, db, ThreatVector, ThreatIntelUpdate
from threat_intel_service import sync_threat_intelligence

def main():
    print("[sync_threat_intel] Starting automated Threat Intelligence Knowledge Base synchronization...")
    with app.app_context():
        try:
            new_cnt, total = sync_threat_intelligence(db.session, ThreatVector, ThreatIntelUpdate)
            print(f"[sync_threat_intel] Success! Ingested {new_cnt} updates. Total updates catalog: {total}")
            return 0
        except Exception as err:
            print(f"[sync_threat_intel] Error during synchronization: {err}", file=sys.stderr)
            return 1

if __name__ == '__main__':
    sys.exit(main())
