"""
app.py — VirusGuard Core Web Application

Production-ready Flask application featuring:
- Threat Intelligence and Multi-Engine Malware Scanning (VirusTotal API v3)
- Llama 3 70B AI Explanations via Groq Cloud
- Role-Based Access Control (RBAC) & Secure Session Auth
- CSRF Protection & Security Headers
- Ephemeral Quarantine & Instant Deletion
- PostgreSQL / SQLite / MySQL Support
- Health Check Monitoring for Render Free Tier
"""

import os
import json
import secrets
from datetime import datetime, timezone
from functools import wraps
from typing import Optional, List, Dict, Any

from flask import (
    Flask, request, render_template, redirect, session,
    flash, url_for, jsonify, abort
)
from markupsafe import Markup, escape
from flask_sqlalchemy import SQLAlchemy
import bcrypt
from dotenv import load_dotenv

from file_handler import (
    save_file, delete_file, is_allowed_file, MAX_FILE_SIZE_BYTES
)
from virus_scanner import (
    check_hash_report, scan_file, get_scan_results, get_api_key as get_vt_api_key
)
from alert_system import send_alert
from attack_data import ATTACKS, ATTACKS_BY_SLUG

# Load environment configuration
load_dotenv()

app = Flask(__name__)

# -----------------------------------------------------------------------------
# Configuration
# -----------------------------------------------------------------------------
app.secret_key = os.getenv('SECRET_KEY') or secrets.token_hex(32)

# Database URI configuration: supports Render PostgreSQL, MySQL, and SQLite fallback
raw_db_url = os.getenv('DATABASE_URL', 'sqlite:///virus_users.db')
if raw_db_url.startswith('postgres://'):
    raw_db_url = raw_db_url.replace('postgres://', 'postgresql://', 1)

app.config['SQLALCHEMY_DATABASE_URI'] = raw_db_url
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['MAX_CONTENT_LENGTH'] = MAX_FILE_SIZE_BYTES
app.config['UPLOAD_FOLDER'] = os.path.join(app.root_path, 'uploads')
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Cookie security settings
is_production = os.getenv('FLASK_ENV') == 'production' or os.getenv('RENDER') == 'true'
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = is_production

db = SQLAlchemy(app)

# Default admin credentials for provisioning
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'Admin@gmail.com').strip()
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin').strip()


# -----------------------------------------------------------------------------
# Database Models
# -----------------------------------------------------------------------------
class User(db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    def __init__(self, email: str, password: str, name: str, is_admin: bool = False):
        self.name = name.strip()
        self.email = email.strip().lower()
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.is_admin = is_admin

    def check_password(self, password: str) -> bool:
        if not self.password or not password:
            return False
        try:
            return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))
        except (ValueError, TypeError):
            return False


class ContactMessage(db.Model):
    __tablename__ = 'contact_messages'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class SecurityAdvisory(db.Model):
    __tablename__ = 'security_advisories'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(255), nullable=False)
    cve_id = db.Column(db.String(50), nullable=True)
    severity = db.Column(db.String(20), default='HIGH')  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    source = db.Column(db.String(100), default='Security Bulletin')
    author = db.Column(db.String(100), default='Threat Intelligence Desk')
    summary = db.Column(db.Text, nullable=False)
    external_url = db.Column(db.String(500), unique=True, nullable=False)
    published_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))


class ThreatVector(db.Model):
    __tablename__ = 'threat_vectors'
    id = db.Column(db.Integer, primary_key=True)
    slug = db.Column(db.String(100), unique=True, nullable=False, index=True)
    title = db.Column(db.String(150), nullable=False)
    category = db.Column(db.String(100), default='General Cybersecurity')
    card_img = db.Column(db.String(255), nullable=True)
    hero_img = db.Column(db.String(255), nullable=True)
    desc = db.Column(db.Text, nullable=False)
    long_title = db.Column(db.String(255), nullable=False)
    intro = db.Column(db.Text, nullable=False)
    sections_json = db.Column(db.Text, default='[]')
    external_link = db.Column(db.String(500), nullable=True)
    source_name = db.Column(db.String(150), default='VirusGuard Threat Lab')
    last_updated = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    is_emerging = db.Column(db.Boolean, default=False)

    @property
    def sections(self):
        try:
            return json.loads(self.sections_json) if self.sections_json else []
        except Exception:
            return []

    @sections.setter
    def sections(self, value):
        self.sections_json = json.dumps(value)


class ThreatIntelUpdate(db.Model):
    __tablename__ = 'threat_intel_updates'
    id = db.Column(db.Integer, primary_key=True)
    vector_slug = db.Column(db.String(100), db.ForeignKey('threat_vectors.slug'), nullable=True, index=True)
    title = db.Column(db.String(255), nullable=False)
    update_type = db.Column(db.String(50), default='Malware Analysis')
    summary = db.Column(db.Text, nullable=False)
    technical_details = db.Column(db.Text, nullable=True)
    iocs = db.Column(db.Text, nullable=True)
    cve_id = db.Column(db.String(50), nullable=True)
    source_name = db.Column(db.String(100), default='Cybersecurity Feed')
    source_url = db.Column(db.String(500), unique=True, nullable=False)
    published_date = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))
    created_at = db.Column(db.DateTime, default=lambda: datetime.now(timezone.utc))

    vector = db.relationship('ThreatVector', backref=db.backref('intel_updates', order_by='desc(ThreatIntelUpdate.id)', lazy='dynamic'))


# Initialize database schema and provision admin safely
@app.template_filter('nl2br')
def nl2br_filter(s):
    """Safely converts newlines in strings to <br> HTML tags."""
    if not s:
        return ''
    return Markup('<br>'.join(escape(str(s)).splitlines()))


with app.app_context():
    db.create_all()
    # Seed baseline threat vectors into database
    from threat_intel_service import seed_baseline_vectors
    seed_baseline_vectors(db.session, ThreatVector)

    # Backfill or create initial admin if not present
    existing_admin = User.query.filter_by(email=ADMIN_EMAIL.lower()).first()
    if existing_admin:
        if not existing_admin.is_admin:
            existing_admin.is_admin = True
            db.session.commit()
    else:
        # Create default admin account if table is empty
        if User.query.count() == 0:
            initial_admin = User(
                name="Security Administrator",
                email=ADMIN_EMAIL,
                password=ADMIN_PASSWORD,
                is_admin=True
            )
            db.session.add(initial_admin)
            db.session.commit()


# -----------------------------------------------------------------------------
# CSRF Protection & Security Headers
# -----------------------------------------------------------------------------
def generate_csrf_token() -> str:
    """Generates or retrieves CSRF token for the active session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

app.jinja_env.globals['csrf_token'] = generate_csrf_token


@app.before_request
def csrf_protect():
    """Validates CSRF token on state-changing HTTP requests."""
    # Skip CSRF check in testing mode or for safe GET/HEAD/OPTIONS methods
    if app.config.get('TESTING') or request.method in ('GET', 'HEAD', 'OPTIONS'):
        return
    # Skip health check & API cron endpoints
    if request.path in ('/health', '/healthz') or request.path.startswith('/api/'):
        return

    submitted_token = request.form.get('csrf_token') or request.headers.get('X-CSRFToken')
    session_token = session.get('_csrf_token')

    if not submitted_token or not session_token or not secrets.compare_digest(submitted_token, session_token):
        flash('Session security token expired or invalid. Please try again.', 'error')
        # Return to referring page or homepage
        return redirect(request.referrer or url_for('home'))


@app.after_request
def set_security_headers(response):
    """Enforces essential security headers on all responses."""
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    return response


# -----------------------------------------------------------------------------
# Authentication Helpers
# -----------------------------------------------------------------------------
def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('name'):
            flash('Please sign in to access this page.', 'warning')
            return redirect(url_for('Login'))
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('admin'):
            flash('Administrator privileges required.', 'error')
            return redirect(url_for('Login'))
        return f(*args, **kwargs)
    return decorated_function


# -----------------------------------------------------------------------------
# AI Threat Intelligence Engine (Llama 3 70B via Groq)
# -----------------------------------------------------------------------------
def get_groq_client():
    """Lazily initializes Groq SDK client to prevent startup crashes."""
    api_key = os.getenv('GROQ_API_KEY', '').strip()
    if not api_key or 'placeholder' in api_key.lower():
        return None
    try:
        from groq import Groq
        return Groq(api_key=api_key)
    except Exception as err:
        print(f"[groq_client] Initialization error: {err}")
        return None


def explain_virus_info(virus_info: dict, filename: str = "sample") -> List[tuple[str, str]]:
    """
    Generates structured plain-English security intelligence using Llama 3 70B.
    Executes a single consolidated prompt to prevent WSGI timeouts.
    Fails gracefully with accurate forensic context if AI is unreachable.
    """
    categories = [
        ("Explain Virus", "Threat Overview"),
        ("Explain the History of the Virus", "Historical Context"),
        ("Explain how the Virus works", "Operational Mechanics"),
        ("Explain how to prevent the Virus", "Mitigation & Prevention")
    ]

    # Extract distinct threat names and engine signatures
    threat_labels = set()
    if isinstance(virus_info, dict):
        for data in virus_info.values():
            if isinstance(data, dict) and data.get('category') == 'malicious':
                res = data.get('result')
                if res:
                    threat_labels.add(res)

    signatures_str = ", ".join(list(threat_labels)[:8]) if threat_labels else "Generic Trojan/Malware"

    client = get_groq_client()
    if not client:
        # Graceful fallback when Groq is not configured
        return [
            ("Explain Virus", f"Malware signatures identified: {signatures_str}. The uploaded sample matches known malicious threat vectors."),
            ("Explain the History of the Virus", "This signature pattern corresponds to established malware families observed in global threat telemetry."),
            ("Explain how the Virus works", "Malicious binaries commonly attempt persistence, unauthorized code execution, credential exfiltration, or secondary payload deployment."),
            ("Explain how to prevent the Virus", "Quarantine the affected system, avoid executing untrusted attachments, update endpoint protection definitions, and inspect system logs.")
        ]

    prompt = f"""You are an enterprise cybersecurity threat intelligence analyst.
A file named '{filename}' was analyzed and flagged as malicious with signatures: {signatures_str}.

Provide a structured, human-readable threat briefing. Format your response into exactly four clearly marked sections with these headers:
### 1. Threat Overview
### 2. Historical Context
### 3. Operational Mechanics
### 4. Mitigation & Prevention

Be concise, technically accurate, and accessible to system administrators and engineers.
"""

    try:
        model_name = os.getenv("GROQ_MODEL", "qwen/qwen3.8-27b")
        response = client.chat.completions.create(
            model=model_name,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.3,
            max_tokens=900,
            timeout=12.0
        )
        content = response.choices[0].message.content or ""

        # Parse sections
        parsed = {}
        current_header = None
        current_text = []

        for line in content.splitlines():
            clean_line = line.strip()
            if "### 1." in clean_line or "Threat Overview" in clean_line:
                if current_header:
                    parsed[current_header] = "\n".join(current_text).strip()
                current_header = "Explain Virus"
                current_text = []
            elif "### 2." in clean_line or "Historical Context" in clean_line or "History" in clean_line:
                if current_header:
                    parsed[current_header] = "\n".join(current_text).strip()
                current_header = "Explain the History of the Virus"
                current_text = []
            elif "### 3." in clean_line or "Operational Mechanics" in clean_line or "how the Virus works" in clean_line:
                if current_header:
                    parsed[current_header] = "\n".join(current_text).strip()
                current_header = "Explain how the Virus works"
                current_text = []
            elif "### 4." in clean_line or "Mitigation" in clean_line or "prevent the Virus" in clean_line:
                if current_header:
                    parsed[current_header] = "\n".join(current_text).strip()
                current_header = "Explain how to prevent the Virus"
                current_text = []
            else:
                if current_header:
                    current_text.append(line)

        if current_header:
            parsed[current_header] = "\n".join(current_text).strip()

        results = []
        for cat_key, default_title in categories:
            body = parsed.get(cat_key)
            if not body or len(body) < 10:
                body = f"Analysis for {signatures_str}: Refer to security advisories for detailed operational telemetry."
            results.append((cat_key, body))

        return results

    except Exception as err:
        print(f"[groq_ai] Threat intelligence generation failed: {err}")
        return [
            ("Explain Virus", f"Detected threat signatures: {signatures_str}."),
            ("Explain the History of the Virus", "Threat telemetry matches known malware variants."),
            ("Explain how the Virus works", "Automated heuristics suggest potential unauthorized execution or privilege escalation."),
            ("Explain how to prevent the Virus", "Isolate infected endpoints and verify system integrity with updated antivirus signatures.")
        ]


# -----------------------------------------------------------------------------
# System & Monitoring Routes
# -----------------------------------------------------------------------------
@app.route('/health')
@app.route('/healthz')
def health_check():
    """Lightweight health check endpoint for Render zero-downtime monitoring."""
    return jsonify({
        "status": "healthy",
        "service": "VirusGuard",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "database": "connected" if db.session.is_active else "standby"
    }), 200


# -----------------------------------------------------------------------------
# Public Content Routes
# -----------------------------------------------------------------------------
@app.route('/')
def home():
    return render_template('landing.html')


@app.route('/Home')
def Home():
    return redirect(url_for('home'))


@app.route('/about')
def about():
    return render_template('about.html')


@app.route('/Missions')
def Missions():
    return render_template('Missions.html')


@app.route('/Help')
def Help():
    return render_template('Help.html')


@app.route('/Post')
def Post():
    from advisory_service import sync_latest_advisories

    # Ensure baseline data exists on initial visit
    if SecurityAdvisory.query.count() == 0:
        try:
            sync_latest_advisories(db.session, SecurityAdvisory)
        except Exception as err:
            print(f"[app] Initial advisory sync failed: {err}")

    severity_filter = request.args.get('severity', '').strip().upper()
    search = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)

    query = SecurityAdvisory.query.order_by(SecurityAdvisory.id.desc())

    if severity_filter and severity_filter in ('CRITICAL', 'HIGH', 'MEDIUM', 'INFO'):
        query = query.filter_by(severity=severity_filter)

    if search:
        like = f'%{search}%'
        query = query.filter(db.or_(
            SecurityAdvisory.title.ilike(like),
            SecurityAdvisory.cve_id.ilike(like),
            SecurityAdvisory.summary.ilike(like),
            SecurityAdvisory.source.ilike(like)
        ))

    pagination = query.paginate(page=page, per_page=9, error_out=False)

    return render_template(
        'Post.html',
        advisories=pagination.items,
        pagination=pagination,
        severity_filter=severity_filter,
        search=search,
        total_count=SecurityAdvisory.query.count()
    )


@app.route('/ContactUs', methods=['GET', 'POST'])
def ContactUs():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()

        if not (name and email and subject and message):
            flash('Please fill in every required field.', 'error')
            return redirect(url_for('ContactUs'))

        if len(name) > 100 or len(email) > 120 or len(subject) > 200:
            flash('Input exceeds allowed field length.', 'error')
            return redirect(url_for('ContactUs'))

        msg = ContactMessage(name=name, email=email, subject=subject, message=message)
        db.session.add(msg)
        db.session.commit()
        flash("Thank you — your inquiry has been received by our security team.", 'success')
        return redirect(url_for('ContactUs'))

    return render_template('ContactUs.html')


@app.route('/Attacks')
def attacks():
    from threat_intel_service import seed_baseline_vectors
    if ThreatVector.query.count() == 0:
        seed_baseline_vectors(db.session, ThreatVector)

    category_filter = request.args.get('category', '').strip()
    search = request.args.get('q', '').strip()

    query = ThreatVector.query.order_by(ThreatVector.id)

    if category_filter:
        query = query.filter_by(category=category_filter)

    if search:
        like = f'%{search}%'
        query = query.filter(db.or_(
            ThreatVector.title.ilike(like),
            ThreatVector.desc.ilike(like),
            ThreatVector.category.ilike(like)
        ))

    vectors = query.all()
    categories = [r[0] for r in db.session.query(ThreatVector.category).distinct().all() if r[0]]

    return render_template(
        'attacks.html',
        attacks=vectors,
        categories=categories,
        category_filter=category_filter,
        search=search,
        total_updates=ThreatIntelUpdate.query.count()
    )


@app.route('/attacks/<slug>')
def attack_detail(slug):
    slug_key = slug
    vector = ThreatVector.query.filter_by(slug=slug_key).first()

    if not vector:
        # Support case-insensitive and hyphenated URL variations
        normalized = slug.lower().replace('-', '_')
        for v in ThreatVector.query.all():
            if v.slug.lower().replace('-', '_') == normalized:
                vector = v
                break

    if not vector:
        fallback = ATTACKS_BY_SLUG.get(slug)
        if not fallback:
            return redirect(url_for('attacks'))
        related = [a for a in ATTACKS if a['slug'] != slug][:3]
        return render_template('attack_detail.html', attack=fallback, related=related, intel_updates=[])

    # Fetch real-time threat intelligence updates for this vector
    intel_updates = vector.intel_updates.limit(10).all()

    # Find related vectors
    related = ThreatVector.query.filter(ThreatVector.slug != vector.slug).limit(3).all()

    return render_template(
        'attack_detail.html',
        attack=vector,
        related=related,
        intel_updates=intel_updates
    )


# Legacy redirects for backward compatibility with external links
for _slug in ATTACKS_BY_SLUG:
    app.add_url_rule(
        f'/{_slug}',
        endpoint=f'legacy_{_slug}',
        view_func=lambda slug=_slug: redirect(url_for('attack_detail', slug=slug)),
    )


# -----------------------------------------------------------------------------
# Authentication Routes
# -----------------------------------------------------------------------------
@app.route('/Register', methods=['GET', 'POST'])
def Register():
    if session.get('name'):
        return redirect(url_for('scan'))

    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        if not name or not email or not password:
            flash('All registration fields are required.', 'error')
            return redirect(url_for('Register'))

        if len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
            return redirect(url_for('Register'))

        if '@' not in email or '.' not in email:
            flash('Please provide a valid email address.', 'error')
            return redirect(url_for('Register'))

        if User.query.filter_by(email=email).first():
            flash('An account with this email address already exists.', 'error')
            return redirect(url_for('Register'))

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        # Session establishment
        session['name'] = new_user.name
        session['email'] = new_user.email
        session['admin'] = new_user.is_admin
        flash('Account registered successfully. Welcome to VirusGuard!', 'success')
        return redirect(url_for('scan'))

    return render_template('Register.html')


@app.route('/login', methods=['GET', 'POST'])
def Login():
    if request.method == 'POST':
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')

        user = User.query.filter_by(email=email).first()

        # Secure DB-backed authentication
        if user and user.check_password(password):
            session['name'] = user.name
            session['email'] = user.email
            session['admin'] = user.is_admin
            flash(f'Welcome back, {user.name}!', 'success')
            return redirect(url_for('admin') if user.is_admin else url_for('scan'))

        # Fallback admin bootstrap check if DB has not been seeded yet
        if not user and email == ADMIN_EMAIL.lower() and password == ADMIN_PASSWORD:
            session['name'] = "Administrator"
            session['email'] = ADMIN_EMAIL
            session['admin'] = True
            flash('Signed in with administrative credentials.', 'info')
            return redirect(url_for('admin'))

        flash('Invalid email or password. Please verify your credentials.', 'error')
        return redirect(url_for('Login'))

    return render_template('Login.html')


@app.route('/logout')
def logout():
    session.clear()
    flash('You have been logged out securely.', 'success')
    return redirect(url_for('Login'))


# -----------------------------------------------------------------------------
# File Scanning & Analysis Routes
# -----------------------------------------------------------------------------
@app.route('/scan')
@login_required
def scan():
    return render_template('scan.html')


@app.route('/index')
def index():
    return redirect(url_for('scan'))


@app.route('/upload', methods=['POST'])
@login_required
def upload_file():
    if 'file' not in request.files:
        flash('No file was provided in the upload request.', 'danger')
        return redirect(url_for('scan'))

    file = request.files['file']
    if not file or file.filename == '':
        flash('No file selected. Please select a valid file to analyze.', 'danger')
        return redirect(url_for('scan'))

    if not is_allowed_file(file.filename):
        flash('File type not supported. Please upload a binary, document, archive, or script.', 'warning')
        return redirect(url_for('scan'))

    # Save to ephemeral quarantine with random UUID and calculate SHA-256
    file_path, original_filename, file_sha256 = save_file(file, app.config['UPLOAD_FOLDER'])

    try:
        vt_stats = None
        virus_info = None

        # 1. Fast-Path: Check existing hash analysis on VirusTotal first
        hash_report = check_hash_report(file_sha256)
        if hash_report:
            vt_stats = hash_report.get('stats', {})
            virus_info = hash_report.get('results', {})
        else:
            # 2. Live Scan: Upload file and poll VirusTotal
            scan_id = scan_file(file_path)
            if scan_id:
                live_result = get_scan_results(scan_id)
                if live_result:
                    vt_stats = live_result.get('data', {}).get('attributes', {}).get('stats', {})
                    virus_info = live_result.get('data', {}).get('attributes', {}).get('results', {})

            # 3. Post-upload fallback: Query hash again in case VirusTotal committed file record
            if vt_stats is None:
                retry_hash = check_hash_report(file_sha256)
                if retry_hash:
                    vt_stats = retry_hash.get('stats', {})
                    virus_info = retry_hash.get('results', {})

        # If VirusTotal is unconfigured or unavailable, notify clearly
        if vt_stats is None:
            if not get_vt_api_key():
                flash("VirusTotal API key is not configured. Add VIRUSTOTAL_API_KEY in .env to enable multi-engine scanning.", 'warning')
            else:
                flash(f"Scanning timed out or could not be completed by VirusTotal for {original_filename}.", 'danger')
            return redirect(url_for('scan'))

        # Analyze statistics
        malicious_count = vt_stats.get('malicious', 0)
        suspicious_count = vt_stats.get('suspicious', 0)
        harmless_count = vt_stats.get('harmless', 0)
        undetected_count = vt_stats.get('undetected', 0)
        total_engines = malicious_count + suspicious_count + harmless_count + undetected_count

        scan_meta = {
            "malicious": malicious_count,
            "suspicious": suspicious_count,
            "harmless": harmless_count,
            "undetected": undetected_count,
            "total_engines": total_engines,
            "sha256": file_sha256
        }

        if malicious_count > 0 or suspicious_count > 0:
            # Threat detected: Generate AI explanation & dispatch SOC alert
            explanations = explain_virus_info(virus_info or {}, original_filename)
            send_alert(file_path, virus_info or {}, original_filename)

            for category, explanation in explanations:
                flash(explanation, category)

            return render_template(
                'scan.html',
                scan_result='virus',
                filename=original_filename,
                scan_meta=scan_meta
            )
        else:
            flash(f"No security threats detected in {original_filename}.", 'success')
            return render_template(
                'scan.html',
                scan_result='clean',
                filename=original_filename,
                scan_meta=scan_meta
            )

    finally:
        # Crucial security & storage practice: Delete quarantined sample immediately
        delete_file(file_path)


# -----------------------------------------------------------------------------
# Administrative Control Panel
# -----------------------------------------------------------------------------
@app.route('/admin')
@admin_required
def admin():
    search = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)

    query = User.query.order_by(User.id.desc())
    if search:
        like = f'%{search}%'
        query = query.filter(db.or_(User.name.ilike(like), User.email.ilike(like)))

    pagination = query.paginate(page=page, per_page=10, error_out=False)

    # Fetch recent contact inquiries
    messages = ContactMessage.query.order_by(ContactMessage.id.desc()).limit(20).all()

    return render_template(
        'admin.html',
        users=pagination.items,
        pagination=pagination,
        search=search,
        messages=messages,
        total_messages=ContactMessage.query.count(),
        total_advisories=SecurityAdvisory.query.count(),
        total_intel_updates=ThreatIntelUpdate.query.count()
    )


@app.route('/admin/sync_threat_intel', methods=['POST'])
@admin_required
def admin_sync_threat_intel():
    """Manual sync trigger for the Threat Intelligence Knowledge Base."""
    from threat_intel_service import sync_threat_intelligence
    try:
        new_cnt, total = sync_threat_intelligence(db.session, ThreatVector, ThreatIntelUpdate)
        flash(f"Threat Intelligence Ingestion Complete: {new_cnt} updates added. Total catalog: {total}.", "success")
    except Exception as err:
        flash(f"Threat intelligence sync error: {err}", "error")
    return redirect(url_for('admin'))


@app.route('/api/sync-threat-intel', methods=['POST'])
def api_sync_threat_intel():
    """Automated webhook endpoint for Threat Intelligence ingestion."""
    cron_secret = os.getenv('CRON_SECRET', '').strip()
    if cron_secret:
        auth_header = request.headers.get('X-Cron-Secret') or request.args.get('secret')
        if auth_header != cron_secret:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

    from threat_intel_service import sync_threat_intelligence
    try:
        new_cnt, total = sync_threat_intelligence(db.session, ThreatVector, ThreatIntelUpdate)
        return jsonify({
            "status": "success",
            "new_updates_added": new_cnt,
            "total_updates": total,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as err:
        return jsonify({"status": "error", "message": str(err)}), 500


@app.route('/admin/sync_advisories', methods=['POST'])
@admin_required
def admin_sync_advisories():
    """Manual sync trigger from the admin control panel."""
    from advisory_service import sync_latest_advisories
    try:
        new_cnt, total = sync_latest_advisories(db.session, SecurityAdvisory)
        flash(f"Live Ingestion Complete: {new_cnt} new advisories fetched. Total catalog: {total}.", "success")
    except Exception as err:
        flash(f"Synchronization error: {err}", "error")
    return redirect(url_for('admin'))


@app.route('/api/sync-advisories', methods=['POST'])
def api_sync_advisories():
    """
    Automated webhook endpoint for external cron orchestrators (Render Cron, etc.).
    Protects against unauthorized calls using CRON_SECRET if configured.
    """
    cron_secret = os.getenv('CRON_SECRET', '').strip()
    if cron_secret:
        auth_header = request.headers.get('X-Cron-Secret') or request.args.get('secret')
        if auth_header != cron_secret:
            return jsonify({"status": "error", "message": "Unauthorized"}), 401

    from advisory_service import sync_latest_advisories
    try:
        new_cnt, total = sync_latest_advisories(db.session, SecurityAdvisory)
        return jsonify({
            "status": "success",
            "new_advisories_added": new_cnt,
            "total_advisories": total,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }), 200
    except Exception as err:
        return jsonify({"status": "error", "message": str(err)}), 500


@app.route('/delete_user/<int:user_id>', methods=['POST'])
@admin_required
def delete_user(user_id):
    user = db.session.get(User, user_id)
    if user:
        if user.email == session.get('email'):
            flash("You cannot delete your own active administrator account.", "error")
            return redirect(url_for('admin'))
        db.session.delete(user)
        db.session.commit()
        flash(f"User {user.name} was successfully removed.", "success")
    else:
        flash("User not found.", "error")
    return redirect(url_for('admin'))


@app.route('/delete_message/<int:message_id>', methods=['POST'])
@admin_required
def delete_message(message_id):
    msg = db.session.get(ContactMessage, message_id)
    if msg:
        db.session.delete(msg)
        db.session.commit()
        flash("Contact inquiry deleted.", "success")
    return redirect(url_for('admin'))


# -----------------------------------------------------------------------------
# Automated Background Scheduler Initialization
# -----------------------------------------------------------------------------
from advisory_scheduler import start_advisory_scheduler
if not app.config.get('TESTING') and not os.getenv('FLASK_SKIP_SCHEDULER'):
    start_advisory_scheduler(app, lambda: db.session, SecurityAdvisory, ThreatVector, ThreatIntelUpdate)


# -----------------------------------------------------------------------------
# Application Runner
# -----------------------------------------------------------------------------
if __name__ == '__main__':
    port = int(os.getenv('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
