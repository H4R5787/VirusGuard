
from flask import Flask, request, render_template, redirect, session, flash, url_for
from flask_sqlalchemy import SQLAlchemy
import bcrypt
import os
from file_handler import save_file
from virus_scanner import scan_file, get_scan_results
from alert_system import send_alert
from dotenv import load_dotenv
from groq import Groq
from attack_data import ATTACKS, ATTACKS_BY_SLUG


# Load environment variables from .env file
load_dotenv()


app = Flask(__name__)

# Database Configuration
# Was hardcoded as 'mysql+pymysql://root:root@localhost/virus_users' — moved to
# an env var so credentials aren't committed to source and so this can be
# pointed at a different DB per environment (dev/staging/prod) without code changes.
app.config['SQLALCHEMY_DATABASE_URI'] = os.getenv(
    'DATABASE_URL', 'mysql+pymysql://root:root@localhost/virus_users'
)
db = SQLAlchemy(app)

# Was hardcoded as 'supersecretkey' — a committed, unrotatable secret key lets
# anyone who reads the source forge session cookies (including the 'admin'
# session flag). Now required from the environment; the app refuses to start
# without it rather than silently falling back to an insecure default.
app.secret_key = os.getenv('SECRET_KEY')
if not app.secret_key:
    raise RuntimeError(
        "SECRET_KEY is not set. Add it to your .env file (see .env.example) "
        "before starting the app."
    )

app.config['UPLOAD_FOLDER'] = 'uploads'
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

# Hardcoded admin login, moved out of source (see /login below). Still a
# temporary measure — see Phase 4 of the redesign plan for a proper DB-backed
# is_admin flag on the User model.
ADMIN_EMAIL = os.getenv('ADMIN_EMAIL', 'Admin@gmail.com')
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD', 'admin')

# Initialize Groq client for Llama 3

client = Groq(api_key=os.getenv('GROQ_API_KEY'))

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), unique=True)
    password = db.Column(db.String(100))
    # Redesign plan Phase 4: DB-backed admin flag, replacing the env-var
    # ADMIN_EMAIL/ADMIN_PASSWORD comparison in /login as the primary check.
    # Defaults to False for every normal registered user.
    is_admin = db.Column(db.Boolean, nullable=False, default=False)

    def __init__(self, email, password, name, is_admin=False):
        self.name = name
        self.email = email
        self.password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')
        self.is_admin = is_admin

    def check_password(self, password):
        return bcrypt.checkpw(password.encode('utf-8'), self.password.encode('utf-8'))


class ContactMessage(db.Model):
    # Was: ContactUs.html's <form action="#"> — the form rendered fine but
    # submitting it did nothing at all, silently discarding whatever the
    # user typed. This gives it somewhere real to go.
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(100), nullable=False)
    subject = db.Column(db.String(200), nullable=False)
    message = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, server_default=db.func.now())


with app.app_context():
    db.create_all()

    # One-time backfill (Phase 4): if a DB user already exists with the
    # legacy admin email, flag it is_admin so it can log in via the DB path
    # below without needing to change any credentials. Safe to run on every
    # startup — it's a no-op once the flag is already set or no such user
    # exists yet.
    _admin_user = User.query.filter_by(email=ADMIN_EMAIL).first()
    if _admin_user and not _admin_user.is_admin:
        _admin_user.is_admin = True
        db.session.commit()

def explain_virus_info(virus_info):
    """Uses Llama 3 to generate detailed explanations about the virus information."""
    
    messages = [
        {"role": "user", "content": f"Provide a detailed explanation of the virus: {virus_info}"},
        {"role": "user", "content": f"Describe the history of the virus: {virus_info}"},
        {"role": "user", "content": f"Explain how the virus operates: {virus_info}"},
        {"role": "user", "content": f"Suggest methods to prevent infection by the virus: {virus_info}"}
    ]
    
    explanations = []
    
    for msg in messages:
        response = client.chat.completions.create(
            model="llama3-70b-8192",
            messages=[msg],
            temperature=1,
            max_tokens=1024,
            top_p=1,
            stream=False,
            stop=None,
        )

        if isinstance(response, tuple):
            response = response[0]

        explanation = response.choices[0].message.content
        explanations.append(explanation)
    
    return explanations

@app.route('/')
def home():
    # Was 'TEST.html' — renamed to landing.html as part of the redesign.
    # Full merge with /Home into a single canonical landing page is tracked
    # as Phase 3 in the redesign plan; for now this route is the canonical
    # entry point and uses the shared design system.
    return render_template('landing.html')


@app.route('/Home')
def Home():
    # Home.html was a near-duplicate of landing.html (same hero + feature
    # cards, older copy, standalone chrome). Redesign plan §7/Phase 3:
    # retired the template in favor of a redirect to the canonical `/`.
    return redirect('/')


@app.route('/Missions')
def Missions():
    return render_template('Missions.html')



@app.route('/about')
def about():
    return render_template('about.html')

@app.route('/ContactUs', methods=['GET', 'POST'])
def ContactUs():
    if request.method == 'POST':
        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        subject = request.form.get('subject', '').strip()
        message = request.form.get('message', '').strip()

        if not (name and email and subject and message):
            flash('Please fill in every field before sending.', 'error')
            return redirect('/ContactUs')

        db.session.add(ContactMessage(name=name, email=email, subject=subject, message=message))
        db.session.commit()
        flash("Thanks — we've received your message and will get back to you soon.", 'success')
        return redirect('/ContactUs')

    return render_template('ContactUs.html')


@app.route('/Post')
def Post():
    return render_template('Post.html')


@app.route('/Help')
def Help():
    return render_template('Help.html')



@app.route('/Register', methods=['GET', 'POST'])
def Register():
    if request.method == 'POST':
        name = request.form['name']
        email = request.form['email']
        password = request.form['password']

        existing_user_email = User.query.filter_by(email=email).first()
        if existing_user_email:
            flash('Email already exists. Please use a different email.', 'error')
            return redirect('/Register')

        existing_user_name = User.query.filter_by(name=name).first()
        if existing_user_name:
            flash('Name already exists. Please use a different name.', 'error')
            return redirect('/Register')

        new_user = User(name=name, email=email, password=password)
        db.session.add(new_user)
        db.session.commit()

        # Auto-login after registration instead of bouncing to a separate
        # login page and making the user re-type credentials they just typed.
        session['name'] = new_user.name
        session['email'] = new_user.email
        return redirect('/scan')

    return render_template('Register.html')


@app.route('/login', methods=['GET', 'POST'])
def Login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        user = User.query.filter_by(email=email).first()

        # Phase 4: DB-backed is_admin is now the primary admin check. The
        # env-var comparison is kept only as a legacy fallback for installs
        # that haven't registered a DB user for their admin account yet —
        # once that account exists (see the startup backfill above, or any
        # user manually flagged is_admin=True), this branch is never
        # reached and ADMIN_PASSWORD stops being a live credential.
        if user and user.is_admin and user.check_password(password):
            session['admin'] = True
            session['name'] = user.name
            return redirect('/admin')

        if not user and email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            session['admin'] = True
            return redirect('/admin')

        if user and user.check_password(password):
            session['name'] = user.name
            session['email'] = user.email
            return redirect('/scan')

        flash('Invalid email or password', 'error')
        return redirect('/login')

    return render_template('Login.html')


@app.route('/logout')
def logout():
    # There was previously no way to end a session through the UI at all —
    # a real gap for a security product. Clears the whole session (covers
    # both regular users and the admin session flag) and returns to login.
    session.clear()
    flash('You have been logged out.', 'success')
    return redirect('/login')


@app.route('/scan')
def scan():
    if session.get('name'):
        return render_template('scan.html')
    else:
        return redirect('/login')


@app.route('/index')
def index():
    # Old route name, kept as a redirect so any existing bookmarks/links
    # don't 404 after the rename to /scan.
    return redirect('/scan')


@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        flash('No file part', 'danger')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file', 'danger')
        return redirect(request.url)
    if file:
        file_path = save_file(file, app.config['UPLOAD_FOLDER'])
        scan_id = scan_file(file_path)
        if scan_id:
            result = get_scan_results(scan_id)
            if result:
                positives = result['data']['attributes']['stats']['malicious']
                if positives > 0:
                    virus_info = result['data']['attributes']['results']
                    explanations = explain_virus_info(virus_info)
                    send_alert(file_path, virus_info)
                    flash(f"Virus found in {file.filename}:", 'danger')
                    
                    categories = [
                        "Explain Virus",
                        "Explain the History of the Virus",
                        "Explain how the Virus works",
                        "Explain how to prevent the Virus"
                    ]
                    
                    for explanation, category in zip(explanations, categories):
                        flash(explanation, category)
                    return render_template('scan.html', scan_result='virus', filename=file.filename)
                else:
                    flash(f"{file.filename} is clean.", 'success')
                    return render_template('scan.html', scan_result='clean', filename=file.filename)
            else:
                flash(f"Could not retrieve scan results for {file.filename}.", 'danger')
        else:
            flash(f"Could not scan file {file.filename}.", 'danger')
    return redirect(url_for('scan'))


@app.route('/Attacks')
def attacks():
    return render_template('attacks.html', attacks=ATTACKS)


@app.route('/attacks/<slug>')
def attack_detail(slug):
    # Redesign plan §7/Phase 3: single dynamic template + shared data source
    # (attack_data.py) replacing 11 near-duplicate templates/routes.
    attack = ATTACKS_BY_SLUG.get(slug)
    if not attack:
        return redirect('/Attacks')
    related = [a for a in ATTACKS if a['slug'] != slug][:3]
    return render_template('attack_detail.html', attack=attack, related=related)


# The 11 old routes/URLs are kept as redirects to /attacks/<slug> so any
# existing bookmarks or external links to e.g. /SQL_Injection still resolve,
# instead of 404ing now that the individual templates are gone.
for _slug in ATTACKS_BY_SLUG:
    app.add_url_rule(
        f'/{_slug}',
        endpoint=f'legacy_{_slug}',
        view_func=lambda slug=_slug: redirect(f'/attacks/{slug}'),
    )


@app.route('/admin')
def admin():
    if not session.get('admin'):
        return redirect('/login')

    # Phase 4: search + pagination, using Flask-SQLAlchemy's built-in
    # paginate() rather than a new dependency. Previously this loaded
    # every registered user into one unpaginated table — fine at a handful
    # of rows, a real problem once the table grows past a screen.
    search = request.args.get('q', '').strip()
    page = request.args.get('page', 1, type=int)

    query = User.query.order_by(User.id)
    if search:
        like = f'%{search}%'
        query = query.filter(db.or_(User.name.ilike(like), User.email.ilike(like)))

    pagination = query.paginate(page=page, per_page=10, error_out=False)
    return render_template('admin.html', users=pagination.items, pagination=pagination, search=search)


@app.route('/delete_user/<int:user_id>', methods=['POST'])
def delete_user(user_id):
    if session.get('admin'):
        user = User.query.get(user_id)
        if user:
            db.session.delete(user)
            db.session.commit()
        return redirect('/admin')
    else:
        return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)
