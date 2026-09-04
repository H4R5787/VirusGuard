"""
virus_scanner.py

Wraps the VirusTotal API v3 file-scanning workflow used by app.py's /upload route.
This module was referenced by app.py (`from virus_scanner import scan_file,
get_scan_results`) but did not exist in the repository, which made the core
scan feature crash with an ImportError at startup. This restores it.

Flow:
  1. scan_file(file_path)      -> uploads the file, returns an analysis_id
  2. get_scan_results(analysis_id) -> polls the analysis endpoint until VT
                                       finishes, then returns the report dict
                                       shaped like app.py expects:
                                       result['data']['attributes']['stats']['malicious']
                                       result['data']['attributes']['results']
"""

import os
import time
import requests

VT_BASE_URL = "https://www.virustotal.com/api/v3"

# Files larger than 32MB require VirusTotal's special upload-URL flow.
VT_DIRECT_UPLOAD_LIMIT_BYTES = 32 * 1024 * 1024

# How long we're willing to wait for VirusTotal to finish analyzing a file.
DEFAULT_POLL_INTERVAL_SECONDS = 5
DEFAULT_MAX_POLL_ATTEMPTS = 24  # ~2 minutes total at the default interval


def _get_api_key():
    api_key = os.getenv("VIRUSTOTAL_API_KEY")
    if not api_key:
        raise RuntimeError(
            "VIRUSTOTAL_API_KEY is not set. Add it to your .env file "
            "(see .env.example) before scanning files."
        )
    return api_key


def _headers():
    return {"x-apikey": _get_api_key()}


def _get_upload_url():
    """For files > 32MB, VirusTotal requires fetching a dedicated upload URL first."""
    response = requests.get(f"{VT_BASE_URL}/files/upload_url", headers=_headers(), timeout=30)
    response.raise_for_status()
    return response.json()["data"]


def scan_file(file_path):
    """
    Uploads a file to VirusTotal for scanning.

    Returns the VirusTotal analysis_id (string) on success, or None on failure.
    The analysis_id is what get_scan_results() needs to poll for the report.
    """
    try:
        file_size = os.path.getsize(file_path)
        upload_url = f"{VT_BASE_URL}/files"
        if file_size > VT_DIRECT_UPLOAD_LIMIT_BYTES:
            upload_url = _get_upload_url()

        with open(file_path, "rb") as f:
            files = {"file": (os.path.basename(file_path), f)}
            response = requests.post(upload_url, headers=_headers(), files=files, timeout=120)

        response.raise_for_status()
        data = response.json()
        # VirusTotal returns an "analysis" object; its id is what we poll.
        return data["data"]["id"]

    except requests.exceptions.RequestException as exc:
        print(f"[virus_scanner] Upload failed for {file_path}: {exc}")
        return None
    except (KeyError, ValueError) as exc:
        print(f"[virus_scanner] Unexpected response shape while uploading {file_path}: {exc}")
        return None


def get_scan_results(
    analysis_id,
    poll_interval_seconds=DEFAULT_POLL_INTERVAL_SECONDS,
    max_poll_attempts=DEFAULT_MAX_POLL_ATTEMPTS,
):
    """
    Polls VirusTotal's analysis endpoint until the scan completes (status
    'completed') or we give up after max_poll_attempts.

    Returns a dict shaped so app.py's existing access pattern keeps working:
        result['data']['attributes']['stats']['malicious']
        result['data']['attributes']['results']

    Returns None if the analysis never completes or the request fails.
    """
    analysis_url = f"{VT_BASE_URL}/analyses/{analysis_id}"

    for attempt in range(max_poll_attempts):
        try:
            response = requests.get(analysis_url, headers=_headers(), timeout=30)
            response.raise_for_status()
            payload = response.json()
        except requests.exceptions.RequestException as exc:
            print(f"[virus_scanner] Polling failed for analysis {analysis_id}: {exc}")
            return None

        status = payload.get("data", {}).get("attributes", {}).get("status")

        if status == "completed":
            attributes = payload["data"]["attributes"]
            return {
                "data": {
                    "attributes": {
                        "stats": attributes.get("stats", {}),
                        "results": attributes.get("results", {}),
                    }
                }
            }

        # Not done yet — wait and try again, unless this was the last attempt.
        if attempt < max_poll_attempts - 1:
            time.sleep(poll_interval_seconds)

    print(
        f"[virus_scanner] Analysis {analysis_id} did not complete within "
        f"{poll_interval_seconds * max_poll_attempts} seconds."
    )
    return None
