"""
advisory_service.py — Live Vulnerability Advisories & Security News Ingestion

Automates fetching, parsing, and persisting real-time security alerts
from authoritative global feeds:
1. CISA Cybersecurity Advisories (Official US Gov CISA Alerts & ICS Bulletins)
2. The Hacker News (Real-time zero-day, malware, and patch coverage)

Includes automated CVE extraction, severity classification, deduplication,
and graceful offline fallback seeding.
"""

import re
import html
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
import requests

CVE_REGEX = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)

# Keywords indicating vulnerability severity
CRITICAL_KEYWORDS = {'critical', 'rce', 'remote code execution', 'zero-day', '0-day', 'actively exploited', 'unauthenticated', 'auth bypass', 'privilege escalation'}
HIGH_KEYWORDS = {'high', 'arbitrary file', 'injection', 'denial of service', 'dos', 'xss', 'ssrf', 'csrf', 'backdoor', 'ransomware', 'trojan'}
MEDIUM_KEYWORDS = {'medium', 'moderate', 'spoofing', 'information disclosure', 'sensitive data', 'bypass'}

USER_AGENT = "Mozilla/5.0 (compatible; VirusGuard-ThreatIntel/2.0; +https://virusguard.security)"


def determine_severity(text: str) -> str:
    """Classifies advisory severity based on text heuristics and CVSS indicators."""
    lower_text = text.lower()
    for kw in CRITICAL_KEYWORDS:
        if kw in lower_text:
            return "CRITICAL"
    for kw in HIGH_KEYWORDS:
        if kw in lower_text:
            return "HIGH"
    for kw in MEDIUM_KEYWORDS:
        if kw in lower_text:
            return "MEDIUM"
    return "HIGH"  # Default for security bulletins


def clean_html(raw_html: str) -> str:
    """Strips HTML tags and unescapes HTML entities for clean reading."""
    if not raw_html:
        return ""
    clean = re.sub(r'<[^>]+>', ' ', raw_html)
    clean = html.unescape(clean)
    return " ".join(clean.split())


def fetch_cisa_advisories() -> List[Dict[str, Any]]:
    """Fetches official CISA Cybersecurity Advisories RSS feed."""
    url = "https://www.cisa.gov/cybersecurity-advisories/all.xml"
    headers = {"User-Agent": USER_AGENT}
    advisories = []

    try:
        response = requests.get(url, headers=headers, timeout=12)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            channel = root.find("channel")
            items = channel.findall("item") if channel is not None else []

            for item in items[:15]:
                title = clean_html(item.findtext("title", ""))
                link = item.findtext("link", "").strip()
                description = clean_html(item.findtext("description", ""))
                pub_date_str = item.findtext("pubDate", "")

                cve_match = CVE_REGEX.search(f"{title} {description}")
                cve_id = cve_match.group(0).upper() if cve_match else None

                severity = determine_severity(f"{title} {description}")

                if title and link:
                    advisories.append({
                        "title": title,
                        "cve_id": cve_id,
                        "severity": severity,
                        "source": "CISA Advisory",
                        "author": "CISA Security Operations",
                        "summary": description[:450] + ("..." if len(description) > 450 else ""),
                        "external_url": link,
                        "published_date": datetime.now(timezone.utc)
                    })
    except Exception as err:
        print(f"[advisory_service] CISA feed error: {err}")

    return advisories


def fetch_thn_news() -> List[Dict[str, Any]]:
    """Fetches latest cybersecurity news and threat advisories from The Hacker News."""
    url = "https://feeds.feedburner.com/TheHackersNews"
    headers = {"User-Agent": USER_AGENT}
    articles = []

    try:
        response = requests.get(url, headers=headers, timeout=12)
        if response.status_code == 200:
            root = ET.fromstring(response.content)
            channel = root.find("channel")
            items = channel.findall("item") if channel is not None else []

            for item in items[:20]:
                title = clean_html(item.findtext("title", ""))
                link = item.findtext("link", "").strip()
                description = clean_html(item.findtext("description", ""))

                cve_match = CVE_REGEX.search(f"{title} {description}")
                cve_id = cve_match.group(0).upper() if cve_match else None

                severity = determine_severity(f"{title} {description}")

                if title and link:
                    articles.append({
                        "title": title,
                        "cve_id": cve_id,
                        "severity": severity,
                        "source": "The Hacker News",
                        "author": "Cyber Threat Desk",
                        "summary": description[:450] + ("..." if len(description) > 450 else ""),
                        "external_url": link,
                        "published_date": datetime.now(timezone.utc)
                    })
    except Exception as err:
        print(f"[advisory_service] The Hacker News feed error: {err}")

    return articles


def get_fallback_advisories() -> List[Dict[str, Any]]:
    """High-quality baseline advisories if network feeds are temporarily unreachable."""
    return [
        {
            "title": "Critical RCE in Apache HugeGraph Server: CVE-2024-27348",
            "cve_id": "CVE-2024-27348",
            "severity": "CRITICAL",
            "source": "Apache Security",
            "author": "Threat Research Desk",
            "summary": "Apache HugeGraph-Server versions prior to 1.3.0 allow unauthenticated users to execute arbitrary OS commands remotely via Groovy script injection. Upgrade to version 1.3.0 or later immediately.",
            "external_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-27348",
            "published_date": datetime.now(timezone.utc)
        },
        {
            "title": "Check Point Security Gateways Information Disclosure: CVE-2024-24919",
            "cve_id": "CVE-2024-24919",
            "severity": "HIGH",
            "source": "Check Point Advisory",
            "author": "Security Response",
            "summary": "Check Point Security Gateways with IPSec VPN or Mobile Access blades are vulnerable to unauthorized information disclosure, actively exploited in the wild. Hotfix installation required.",
            "external_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-24919",
            "published_date": datetime.now(timezone.utc)
        },
        {
            "title": "Critical Stored XSS in GitLab Web Editor: CVE-2024-4835",
            "cve_id": "CVE-2024-4835",
            "severity": "HIGH",
            "source": "GitLab Security",
            "author": "Security Engineering",
            "summary": "GitLab Community and Enterprise Edition vulnerability allows malicious actors to execute arbitrary client script to hijack sessions. Patched in versions 17.0.1, 16.11.3, and 16.10.6.",
            "external_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-4835",
            "published_date": datetime.now(timezone.utc)
        },
        {
            "title": "Authentication Bypass in GitHub Enterprise Server: CVE-2024-4985",
            "cve_id": "CVE-2024-4985",
            "severity": "CRITICAL",
            "source": "GitHub Security",
            "author": "GitHub Response Team",
            "summary": "SAML SSO assertions with encrypted responses enable unauthorized authentication bypass without prior credentials on versions prior to 3.13.0.",
            "external_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-4985",
            "published_date": datetime.now(timezone.utc)
        },
        {
            "title": "QNAP QTS Remote Code Execution Vulnerability: CVE-2024-27130",
            "cve_id": "CVE-2024-27130",
            "severity": "CRITICAL",
            "source": "QNAP Advisory",
            "author": "Network Storage Security",
            "summary": "Buffer overflow flaw in QNAP NAS systems running QTS allows unauthenticated remote actors to execute arbitrary code. Upgrade to QTS 5.1.7.2770 or higher.",
            "external_url": "https://nvd.nist.gov/vuln/detail/CVE-2024-27130",
            "published_date": datetime.now(timezone.utc)
        }
    ]


def sync_latest_advisories(db_session, model_class) -> tuple[int, int]:
    """
    Ingests live advisories from feeds, deduplicates by external_url,
    and commits new records to the database.

    Returns:
        tuple (new_items_added, total_items_in_database)
    """
    fetched = []
    
    # 1. Fetch live feeds
    fetched.extend(fetch_cisa_advisories())
    fetched.extend(fetch_thn_news())

    # 2. If all external feeds failed, use curated fallbacks
    if not fetched and model_class.query.count() == 0:
        fetched.extend(get_fallback_advisories())

    new_count = 0
    for item in fetched:
        url = item.get("external_url")
        if not url:
            continue

        existing = model_class.query.filter_by(external_url=url).first()
        if not existing:
            advisory = model_class(
                title=item["title"][:250],
                cve_id=item.get("cve_id"),
                severity=item.get("severity", "HIGH"),
                source=item.get("source", "Threat Intelligence Desk"),
                author=item.get("author", "Security Analyst"),
                summary=item.get("summary", ""),
                external_url=url,
                published_date=item.get("published_date") or datetime.now(timezone.utc)
            )
            db_session.add(advisory)
            new_count += 1

    if new_count > 0:
        db_session.commit()
        print(f"[advisory_service] Successfully ingested {new_count} new vulnerability advisories.")

    total_count = model_class.query.count()
    return new_count, total_count
