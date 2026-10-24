"""
virus_scanner.py — Multi-Engine Threat Intelligence Client

Interfaces with the VirusTotal API v3:
1. Fast-path: checks existing SHA-256 hash first for instant verdicts.
2. Fallback: uploads new binaries and polls the analysis endpoint within
   WSGI-safe timeouts (optimized for Render Free Tier).
"""

import os
import time
import requests
from typing import Optional, Dict, Any

VT_BASE_URL = "https://www.virustotal.com/api/v3"
VT_DIRECT_UPLOAD_LIMIT_BYTES = 32 * 1024 * 1024

# Polling configuration: check every 2 seconds for up to 24 seconds
DEFAULT_POLL_INTERVAL_SECONDS = 2
DEFAULT_MAX_POLL_ATTEMPTS = 12


def get_api_key() -> Optional[str]:
    """Retrieves VirusTotal API key from environment."""
    key = os.getenv("VIRUSTOTAL_API_KEY", "").strip()
    if not key or "placeholder" in key.lower():
        return None
    return key


def _headers(api_key: str) -> dict:
    return {
        "x-apikey": api_key,
        "Accept": "application/json"
    }


def check_hash_report(file_hash: str) -> Optional[Dict[str, Any]]:
    """
    Fast-path: Queries VirusTotal for an existing analysis of this file hash.
    Avoids redundant uploads and yields instantaneous verdicts (< 1 sec).
    """
    api_key = get_api_key()
    if not api_key:
        return None

    try:
        url = f"{VT_BASE_URL}/files/{file_hash}"
        response = requests.get(url, headers=_headers(api_key), timeout=10)
        
        if response.status_code == 200:
            payload = response.json()
            attributes = payload.get("data", {}).get("attributes", {})
            return {
                "source": "hash_lookup",
                "status": "completed",
                "stats": attributes.get("last_analysis_stats", {}),
                "results": attributes.get("last_analysis_results", {}),
                "sha256": attributes.get("sha256", file_hash),
                "meaningful_name": attributes.get("meaningful_name", ""),
            }
        elif response.status_code == 404:
            # File not seen by VirusTotal yet — requires upload
            return None
    except requests.exceptions.RequestException as err:
        print(f"[virus_scanner] Hash lookup error for {file_hash}: {err}")
    return None


def _get_upload_url(api_key: str) -> str:
    """For files > 32MB, fetches a dedicated upload URL from VirusTotal."""
    response = requests.get(f"{VT_BASE_URL}/files/upload_url", headers=_headers(api_key), timeout=15)
    response.raise_for_status()
    return response.json()["data"]


def scan_file(file_path: str) -> Optional[str]:
    """
    Uploads a file to VirusTotal for analysis.
    Returns analysis_id string on success, or None on failure.
    """
    api_key = get_api_key()
    if not api_key:
        print("[virus_scanner] VIRUSTOTAL_API_KEY not configured.")
        return None

    try:
        file_size = os.path.getsize(file_path)
        upload_url = f"{VT_BASE_URL}/files"
        if file_size > VT_DIRECT_UPLOAD_LIMIT_BYTES:
            upload_url = _get_upload_url(api_key)

        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(upload_url, headers=_headers(api_key), files=files, timeout=60)

        response.raise_for_status()
        data = response.json()
        return data.get("data", {}).get("id")

    except requests.exceptions.HTTPError as err:
        status = err.response.status_code if err.response is not None else "unknown"
        print(f"[virus_scanner] Upload HTTP error ({status}) for {file_path}: {err}")
        return None
    except requests.exceptions.RequestException as err:
        print(f"[virus_scanner] Upload failed for {file_path}: {err}")
        return None
    except (KeyError, ValueError) as err:
        print(f"[virus_scanner] Malformed response while uploading {file_path}: {err}")
        return None


def get_scan_results(
    analysis_id: str,
    poll_interval_seconds: int = DEFAULT_POLL_INTERVAL_SECONDS,
    max_poll_attempts: int = DEFAULT_MAX_POLL_ATTEMPTS,
) -> Optional[Dict[str, Any]]:
    """
    Polls VirusTotal's analysis endpoint until the scan completes or times out.
    """
    api_key = get_api_key()
    if not api_key or not analysis_id:
        return None

    analysis_url = f"{VT_BASE_URL}/analyses/{analysis_id}"

    for attempt in range(max_poll_attempts):
        try:
            response = requests.get(analysis_url, headers=_headers(api_key), timeout=15)
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.RequestException as err:
            print(f"[virus_scanner] Polling error on attempt {attempt+1}: {err}")
            return None

        status = payload.get("data", {}).get("attributes", {}).get("status")

        if status == "completed":
            attributes = payload.get("data", {}).get("attributes", {})
            return {
                "source": "live_scan",
                "status": "completed",
                "data": {
                    "attributes": {
                        "stats": attributes.get("stats", {}),
                        "results": attributes.get("results", {}),
                    }
                }
            }

        if attempt < max_poll_attempts - 1:
            time.sleep(poll_interval_seconds)

    # If polling ended before full completion, use partial results if AV engines have reported
    try:
        if 'payload' in locals() and payload:
            attrs = payload.get("data", {}).get("attributes", {})
            stats = attrs.get("stats", {})
            results = attrs.get("results", {})
            total_reported = sum(stats.values()) if stats else 0
            if total_reported > 0:
                print(f"[virus_scanner] Analysis {analysis_id} status is '{status}', but {total_reported} engines reported results.")
                return {
                    "source": "live_scan",
                    "status": "in_progress",
                    "data": {
                        "attributes": {
                            "stats": stats,
                            "results": results,
                        }
                    }
                }
    except Exception as err:
        print(f"[virus_scanner] Partial stats parsing error: {err}")

    print(f"[virus_scanner] Analysis {analysis_id} did not finish within {max_poll_attempts * poll_interval_seconds}s.")
    return None
