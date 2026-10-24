"""
test_app.py — Automated Test Suite for VirusGuard

Tests all critical workflows:
- Route responses & health checks
- Security headers
- Authentication & RBAC enforcement
- Form validation & input constraints
- File upload handling, extension validation, and sanitization
- Mocked VirusTotal v3 analysis & fast-path hash queries
- Mocked Groq Cloud (Llama 3 70B) threat briefings
- Graceful API failure fallbacks
- Admin user governance & contact inquiries
"""

import os
import io
import pytest
from unittest.mock import patch, MagicMock

# Configure testing environment before importing app
os.environ['DATABASE_URL'] = 'sqlite:///:memory:'
os.environ['SECRET_KEY'] = 'test-secret-key-32-bytes-long-for-testing'
os.environ['ADMIN_EMAIL'] = 'admin@example.com'
os.environ['ADMIN_PASSWORD'] = 'adminpass123'
os.environ['VIRUSTOTAL_API_KEY'] = 'mock_vt_key'
os.environ['GROQ_API_KEY'] = 'mock_groq_key'

from app import (
    app, db, User, ContactMessage, SecurityAdvisory,
    ThreatVector, ThreatIntelUpdate, explain_virus_info
)
from file_handler import (
    is_allowed_file, calculate_sha256, save_file, delete_file
)
from alert_system import send_alert
from advisory_service import sync_latest_advisories
from threat_intel_service import sync_threat_intelligence, seed_baseline_vectors
from advisory_scheduler import seconds_until_midnight


@pytest.fixture
def client():
    app.config['TESTING'] = True
    app.config['WTF_CSRF_ENABLED'] = False

    with app.app_context():
        db.create_all()
        seed_baseline_vectors(db.session, ThreatVector)
        admin_user = User.query.filter_by(email="admin@example.com").first()
        if not admin_user:
            admin_user = User(
                name="Test Admin",
                email="admin@example.com",
                password="adminpass123",
                is_admin=True
            )
            db.session.add(admin_user)
            db.session.commit()

        yield app.test_client()

        # Clean non-admin records between tests
        ContactMessage.query.delete()
        SecurityAdvisory.query.delete()
        ThreatIntelUpdate.query.delete()
        User.query.filter(User.email != "admin@example.com").delete()
        db.session.commit()


# -----------------------------------------------------------------------------
# 1. System & Health Check Tests
# -----------------------------------------------------------------------------
def test_health_check(client):
    """Verifies that the /health monitoring endpoint responds with 200 OK."""
    res = client.get('/health')
    assert res.status_code == 200
    data = res.get_json()
    assert data['status'] == 'healthy'
    assert data['service'] == 'VirusGuard'


def test_security_headers(client):
    """Verifies that essential security headers are applied to HTTP responses."""
    res = client.get('/')
    assert res.status_code == 200
    assert res.headers.get('X-Content-Type-Options') == 'nosniff'
    assert res.headers.get('X-Frame-Options') == 'SAMEORIGIN'
    assert res.headers.get('X-XSS-Protection') == '1; mode=block'


# -----------------------------------------------------------------------------
# 2. Public Route Tests
# -----------------------------------------------------------------------------
def test_public_pages(client):
    """Verifies all public marketing and encyclopedia pages render correctly."""
    routes = ['/', '/about', '/Missions', '/Help', '/Post', '/Attacks', '/ContactUs']
    for route in routes:
        res = client.get(route)
        assert res.status_code == 200, f"Failed on {route}"


def test_attack_dossier_pages(client):
    """Verifies dynamic attack dossier pages and legacy 302 redirects."""
    # Dynamic route
    res = client.get('/attacks/sql-injection')
    assert res.status_code == 200
    assert b'SQL Injection' in res.data

    # Legacy redirect
    legacy_res = client.get('/SQL_Injection')
    assert legacy_res.status_code == 302
    assert '/attacks/SQL_Injection' in legacy_res.headers['Location']


# -----------------------------------------------------------------------------
# 3. Authentication & Authorization Tests
# -----------------------------------------------------------------------------
def test_user_registration_flow(client):
    """Tests successful user registration and duplicate checks."""
    # Registration with valid data
    res = client.post('/Register', data={
        'name': 'Alice Security',
        'email': 'alice@example.com',
        'password': 'StrongPassword123!'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'Scan Console' in res.data or b'Malware Analysis Console' in res.data

    # Log out Alice before attempting duplicate registration
    client.get('/logout')

    # Attempt duplicate registration with same email
    dup_res = client.post('/Register', data={
        'name': 'Alice Duplicate',
        'email': 'alice@example.com',
        'password': 'AnotherPassword123!'
    }, follow_redirects=True)
    assert b'already exists' in dup_res.data


def test_password_length_validation(client):
    """Verifies password length constraint (minimum 8 characters)."""
    res = client.post('/Register', data={
        'name': 'Shorty',
        'email': 'short@example.com',
        'password': 'short'
    }, follow_redirects=True)
    assert b'Password must be at least 8 characters' in res.data


def test_login_and_logout(client):
    """Tests login with valid credentials and subsequent logout."""
    # Create test user
    with app.app_context():
        user = User(name="Bob Analyst", email="bob@example.com", password="Password1234")
        db.session.add(user)
        db.session.commit()

    # Valid Login
    login_res = client.post('/login', data={
        'email': 'bob@example.com',
        'password': 'Password1234'
    }, follow_redirects=True)
    assert login_res.status_code == 200
    assert b'Bob Analyst' in login_res.data

    # Logout
    logout_res = client.get('/logout', follow_redirects=True)
    assert b'logged out securely' in logout_res.data


def test_protected_routes_unauthenticated(client):
    """Verifies that unauthenticated requests to /scan and /upload are blocked."""
    scan_res = client.get('/scan')
    assert scan_res.status_code == 302
    assert '/login' in scan_res.headers['Location']

    upload_res = client.post('/upload', data={'file': (io.BytesIO(b'data'), 'test.bin')})
    assert upload_res.status_code == 302
    assert '/login' in upload_res.headers['Location']


def test_admin_access_control(client):
    """Verifies that non-admin users cannot access administrative views."""
    # Standard user login
    with client.session_transaction() as sess:
        sess['name'] = 'Standard User'
        sess['email'] = 'user@example.com'
        sess['admin'] = False

    admin_res = client.get('/admin')
    assert admin_res.status_code == 302
    assert '/login' in admin_res.headers['Location']

    # Admin user login
    with client.session_transaction() as sess:
        sess['name'] = 'Test Admin'
        sess['email'] = 'admin@example.com'
        sess['admin'] = True

    admin_res = client.get('/admin')
    assert admin_res.status_code == 200
    assert b'System Administration' in admin_res.data


# -----------------------------------------------------------------------------
# 4. File Handler & Quarantine Tests
# -----------------------------------------------------------------------------
def test_file_extension_validation():
    """Verifies allowed extension check for executables, archives, and docs."""
    assert is_allowed_file('sample.exe') is True
    assert is_allowed_file('document.pdf') is True
    assert is_allowed_file('archive.tar.gz') is True
    assert is_allowed_file('script.py') is True
    assert is_allowed_file('dangerous') is False  # No extension
    assert is_allowed_file('test.unsupported_ext_xyz') is False


def test_file_saving_sanitization_and_cleanup(tmp_path):
    """Tests file saving with random UUID and immediate cleanup."""
    fake_file = io.BytesIO(b'VIRUSGUARD_TEST_BINARY_CONTENT')
    fake_file.filename = '../../traversal_test.exe'

    file_path, original_name, file_hash = save_file(fake_file, str(tmp_path))

    assert original_name == 'traversal_test.exe'
    assert os.path.exists(file_path)
    assert '..' not in file_path
    assert file_hash == calculate_sha256(file_path)

    # Clean up
    deleted = delete_file(file_path)
    assert deleted is True
    assert not os.path.exists(file_path)


# -----------------------------------------------------------------------------
# 5. Scanning Workflow & Mocked Intelligence Tests
# -----------------------------------------------------------------------------
@patch('app.check_hash_report')
def test_upload_clean_file(mock_hash_check, client):
    """Tests scanning a clean file (fast-path hash check)."""
    # Authenticate session
    with client.session_transaction() as sess:
        sess['name'] = 'Analyst'
        sess['email'] = 'analyst@example.com'

    mock_hash_check.return_value = {
        'status': 'completed',
        'stats': {'malicious': 0, 'suspicious': 0, 'harmless': 70, 'undetected': 2},
        'results': {}
    }

    data = {'file': (io.BytesIO(b'clean content'), 'clean_doc.pdf')}
    res = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b'Clean Verdict' in res.data
    assert b'clean_doc.pdf' in res.data


@patch('app.check_hash_report')
@patch('app.explain_virus_info')
@patch('app.send_alert')
def test_upload_malicious_file_with_ai(mock_send_alert, mock_ai, mock_hash_check, client):
    """Tests scanning a malicious file and displaying AI briefings."""
    with client.session_transaction() as sess:
        sess['name'] = 'Analyst'
        sess['email'] = 'analyst@example.com'

    mock_hash_check.return_value = {
        'status': 'completed',
        'stats': {'malicious': 45, 'suspicious': 2, 'harmless': 10, 'undetected': 5},
        'results': {'Kaspersky': {'category': 'malicious', 'result': 'Trojan.Win32.Generic'}}
    }

    mock_ai.return_value = [
        ("Explain Virus", "This is a generic trojan binary."),
        ("Explain the History of the Virus", "First observed in 2021."),
        ("Explain how the Virus works", "Modifies autorun registry keys."),
        ("Explain how to prevent the Virus", "Isolate host and block port 443 outbound.")
    ]

    data = {'file': (io.BytesIO(b'malicious payload'), 'trojan_sample.exe')}
    res = client.post('/upload', data=data, content_type='multipart/form-data', follow_redirects=True)
    assert res.status_code == 200
    assert b'Malicious Verdict' in res.data
    assert b'trojan_sample.exe' in res.data
    assert b'AI Threat Intelligence Briefing' in res.data
    assert mock_send_alert.called


def test_ai_explanation_graceful_fallback():
    """Tests explain_virus_info fallback when Groq client is unconfigured/fails."""
    with patch('app.get_groq_client', return_value=None):
        briefing = explain_virus_info({'Engine1': {'category': 'malicious', 'result': 'Worm.Stuxnet'}})
        assert len(briefing) == 4
        assert 'Worm.Stuxnet' in briefing[0][1]


def test_alert_system_graceful_handling():
    """Verifies that alert_system does not raise an exception when unconfigured."""
    result = send_alert('/tmp/nonexistent.exe', {})
    assert result is False  # Graceful skip


# -----------------------------------------------------------------------------
# 6. Contact Inquiries & Admin Management Tests
# -----------------------------------------------------------------------------
def test_contact_form_submission(client):
    """Verifies contact inquiry submission and persistence in database."""
    res = client.post('/ContactUs', data={
        'name': 'Diana Prince',
        'email': 'diana@themyscira.gov',
        'subject': 'Malware Analysis Inquiry',
        'message': 'We observed a suspicious binary sample.'
    }, follow_redirects=True)
    assert res.status_code == 200
    assert b'received by our security team' in res.data

    with app.app_context():
        msg = ContactMessage.query.filter_by(email='diana@themyscira.gov').first()
        assert msg is not None
        assert msg.subject == 'Malware Analysis Inquiry'


def test_admin_delete_user_and_message(client):
    """Tests deleting users and contact messages from the admin panel."""
    with app.app_context():
        target_user = User(name="UserToDelete", email="delete@example.com", password="Password123")
        target_msg = ContactMessage(name="MsgSender", email="msg@example.com", subject="Test", message="Hello")
        db.session.add(target_user)
        db.session.add(target_msg)
        db.session.commit()
        user_id = target_user.id
        msg_id = target_msg.id

    with client.session_transaction() as sess:
        sess['name'] = 'Test Admin'
        sess['email'] = 'admin@example.com'
        sess['admin'] = True

    # Delete message
    del_msg_res = client.post(f'/delete_message/{msg_id}', follow_redirects=True)
    assert del_msg_res.status_code == 200

    # Delete user
    del_user_res = client.post(f'/delete_user/{user_id}', follow_redirects=True)
    assert del_user_res.status_code == 200
    assert b'successfully removed' in del_user_res.data


# -----------------------------------------------------------------------------
# 7. Automated Daily Advisories & News Feed Tests
# -----------------------------------------------------------------------------
def test_advisory_sync_and_post_route(client):
    """Verifies that security advisories render dynamically on /Post with filters."""
    with app.app_context():
        adv1 = SecurityAdvisory(
            title="Apache HugeGraph Critical RCE",
            cve_id="CVE-2024-27348",
            severity="CRITICAL",
            source="Apache Security",
            summary="Remote code execution via Groovy injection.",
            external_url="https://example.com/cve-2024-27348"
        )
        adv2 = SecurityAdvisory(
            title="Check Point Info Disclosure",
            cve_id="CVE-2024-24919",
            severity="HIGH",
            source="CISA Advisory",
            summary="Information disclosure in VPN blades.",
            external_url="https://example.com/cve-2024-24919"
        )
        db.session.add(adv1)
        db.session.add(adv2)
        db.session.commit()

    # Test /Post renders both
    res = client.get('/Post')
    assert res.status_code == 200
    assert b'Apache HugeGraph' in res.data
    assert b'Check Point Info Disclosure' in res.data
    assert b'CVE-2024-27348' in res.data

    # Test severity filter
    res_crit = client.get('/Post?severity=CRITICAL')
    assert res_crit.status_code == 200
    assert b'Apache HugeGraph' in res_crit.data
    assert b'Check Point Info Disclosure' not in res_crit.data

    # Test search filter
    res_search = client.get('/Post?q=HugeGraph')
    assert res_search.status_code == 200
    assert b'Apache HugeGraph' in res_search.data
    assert b'Check Point Info Disclosure' not in res_search.data


def test_advisory_ingestion_and_deduplication():
    """Verifies sync_latest_advisories parses items and deduplicates URLs."""
    with app.app_context():
        new_cnt, total = sync_latest_advisories(db.session, SecurityAdvisory)
        assert total >= 5  # At least fallback baseline or live feed items
        assert new_cnt == total

        # Running a second time should add 0 duplicates
        new_cnt2, total2 = sync_latest_advisories(db.session, SecurityAdvisory)
        assert new_cnt2 == 0
        assert total2 == total


def test_admin_sync_and_api_webhook(client):
    """Verifies admin sync button and API webhook endpoints."""
    # 1. Test API Webhook endpoint
    webhook_res = client.post('/api/sync-advisories')
    assert webhook_res.status_code == 200
    data = webhook_res.get_json()
    assert data['status'] == 'success'
    assert 'total_advisories' in data

    # 2. Test Admin manual sync button
    with client.session_transaction() as sess:
        sess['name'] = 'Test Admin'
        sess['email'] = 'admin@example.com'
        sess['admin'] = True

    admin_sync_res = client.post('/admin/sync_advisories', follow_redirects=True)
    assert admin_sync_res.status_code == 200
    assert b'Live Ingestion Complete' in admin_sync_res.data


def test_seconds_until_midnight_calculation():
    """Verifies seconds_until_midnight returns a valid positive interval <= 86402s."""
    secs = seconds_until_midnight()
    assert isinstance(secs, float)
    assert 10.0 <= secs <= 86402.0


# -----------------------------------------------------------------------------
# 8. Automated Threat Intelligence Knowledge Base Tests
# -----------------------------------------------------------------------------
def test_threat_vector_dynamic_routes_and_iocs(client):
    """Verifies that /Attacks and /attacks/<slug> render database records & IOCs."""
    with app.app_context():
        # Add a linked live threat intel update with an IOC
        update = ThreatIntelUpdate(
            vector_slug="Ransomware",
            title="LockBit 3.0 Variant Active in Europe",
            update_type="Malware Analysis",
            summary="New affiliate deploying compromised certificates.",
            cve_id="CVE-2023-34362",
            iocs="SHA-256: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
            source_name="CISA Advisory",
            source_url="https://example.com/lockbit-advisory-live"
        )
        db.session.add(update)
        db.session.commit()

    # Verify /Attacks renders the vectors
    res = client.get('/Attacks')
    assert res.status_code == 200
    assert b'Ransomware' in res.data
    assert b'Threat Vectors' in res.data

    # Verify category filter
    res_cat = client.get('/Attacks?category=Web+Application+Security')
    assert res_cat.status_code == 200
    assert b'SQL Injection' in res_cat.data

    # Verify /attacks/Ransomware renders the live linked IOC & analysis
    dossier_res = client.get('/attacks/Ransomware')
    assert dossier_res.status_code == 200
    assert b'LockBit 3.0 Variant' in dossier_res.data
    assert b'CVE-2023-34362' in dossier_res.data
    assert b'0123456789abcdef' in dossier_res.data


def test_threat_intel_ingestion_and_deduplication():
    """Verifies sync_threat_intelligence parses items, correlates vectors, and deduplicates."""
    with app.app_context():
        ThreatIntelUpdate.query.delete()
        db.session.commit()
        new_cnt, total = sync_threat_intelligence(db.session, ThreatVector, ThreatIntelUpdate)
        assert total >= 4
        assert new_cnt == total

        # Second run must not produce duplicates
        new_cnt2, total2 = sync_threat_intelligence(db.session, ThreatVector, ThreatIntelUpdate)
        assert new_cnt2 == 0
        assert total2 == total


def test_admin_and_api_threat_intel_sync_endpoints(client):
    """Verifies admin manual sync button and API webhook for threat intelligence."""
    # 1. API Webhook
    api_res = client.post('/api/sync-threat-intel')
    assert api_res.status_code == 200
    data = api_res.get_json()
    assert data['status'] == 'success'
    assert 'total_updates' in data

    # 2. Admin dashboard manual button
    with client.session_transaction() as sess:
        sess['name'] = 'Test Admin'
        sess['email'] = 'admin@example.com'
        sess['admin'] = True

    admin_res = client.post('/admin/sync_threat_intel', follow_redirects=True)
    assert admin_res.status_code == 200
    assert b'Threat Intelligence Ingestion Complete' in admin_res.data


