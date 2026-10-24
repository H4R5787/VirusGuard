# VirusGuard 🛡️

[![Python Version](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)](https://www.python.org/)
[![Framework](https://img.shields.io/badge/Flask-3.0%2B-000000?style=for-the-badge&logo=flask&logoColor=white)](https://flask.palletsprojects.com/)
[![Database](https://img.shields.io/badge/SQLAlchemy-2.0%2B-D71F00?style=for-the-badge&logo=sqlalchemy&logoColor=white)](https://www.sqlalchemy.org/)
[![AI Engine](https://img.shields.io/badge/Groq_Cloud-Llama_3_70B-F55036?style=for-the-badge&logo=meta&logoColor=white)](https://groq.com/)
[![Threat Intel](https://img.shields.io/badge/VirusTotal-API_v3-3949AB?style=for-the-badge&logo=virustotal&logoColor=white)](https://www.virustotal.com/)
[![License](https://img.shields.io/badge/License-MIT-green.svg?style=for-the-badge)](LICENSE)

> **VirusGuard** is an enterprise-grade cybersecurity analysis and threat intelligence platform built with Flask, SQLAlchemy, VirusTotal API v3, and Groq-accelerated Llama 3 (70B). It combines multi-engine antivirus telemetry with generative AI explanations to deliver actionable, human-readable insights for detected malware, alongside an administrative control panel and an interactive threat encyclopedia.

---

## 📑 Table of Contents

- [Overview](#-overview)
- [Key Features](#-key-features)
- [System Architecture](#-system-architecture)
- [Tech Stack](#-tech-stack)
- [Project Structure](#-project-structure)
- [Component Breakdown](#-component-breakdown)
- [Installation \& Setup](#-installation--setup)
- [Environment Configuration](#-environment-configuration)
- [Database Schema \& Models](#-database-schema--models)
- [Authentication \& Authorization Flow](#-authentication--authorization-flow)
- [Malware Scanning \& AI Pipeline](#-malware-scanning--ai-pipeline)
- [API \& Route Reference](#-api--route-reference)
- [Admin Dashboard](#-admin-dashboard)
- [Threat Intelligence Encyclopedia](#-threat-intelligence-encyclopedia)
- [Security Implementations](#-security-implementations)
- [Production Deployment Guide](#-production-deployment-guide)
- [Troubleshooting](#-troubleshooting)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)
- [Author \& Acknowledgements](#-author--acknowledgements)

---

## 🌟 Overview

Modern cybersecurity analysis tools often present users with cryptic telemetry (hex dumps, raw engine verdicts, heuristic flags) that non-specialist engineers and everyday users struggle to interpret. **VirusGuard** bridges this gap:

1. **Upload & Multi-Engine Verification:** Uploaded binaries, documents, and archives are analyzed through the **VirusTotal v3 API**, aggregating threat verdicts across 70+ industry antivirus engines.
2. **Generative AI Explanation:** If malicious payloads are detected, VirusGuard feeds the engine signatures and behavioral flags into **Llama 3-70B** via the high-throughput **Groq Cloud API**. The model outputs structured, plain-language insights detailing virus history, operational mechanics, and remediation/prevention steps.
3. **Automated SOC Alerts:** Detected threats trigger automated alert dispatching via the built-in email notification system.
4. **Threat Encyclopedia:** A centralized malware database offering in-depth articles on 11 distinct attack vectors (SQLi, XSS, RCE, Trojans, Spyware, Worms, Adware, Keyloggers, Phishing, Rootkits, Ransomware, Cryptojacking).
5. **Secure Administrative Governance:** Admin portal providing user management, search, and pagination.

---

## 🚀 Key Features

- 🔍 **Multi-Engine Malware Detection:** Direct integration with VirusTotal v3, supporting large file uploads up to 32MB+ with polling mechanisms.
- 🧠 **AI-Powered Threat Analysis (Llama 3-70B):** Generates 4-part structured intelligence reports covering identity, history, mechanics, and prevention.
- 🔐 **Robust Authentication:** Secure registration and login using salted `bcrypt` password hashing and signed HTTP sessions.
- 🛡️ **Role-Based Access Control (RBAC):** Database-backed administrative role (`is_admin`) with fallback migration safeguards.
- 📊 **Administrative Control Panel:** Full user lifecycle management featuring real-time search queries and paginated database records.
- 📚 **Threat Knowledgebase:** Dynamic, data-driven attack library detailing attack mechanics, types, real-world CVEs, and mitigation strategies.
- ⚡ **Automated 12:00 AM Daily Ingestion:** Background scheduler automatically queries CISA advisories and zero-day feeds every midnight without manual intervention.
- 📬 **Interactive Support & Contact System:** Persistent contact and inquiries pipeline stored in the database.
- 🎨 **Modern Futuristic UI/UX:** Responsive cybersecurity-themed aesthetic with cyber-glow styling, modal feedback, and flash alert notifications.

---

## 🏗️ System Architecture

VirusGuard leverages a clean, decoupled MVC-inspired architecture built on top of Flask:

```mermaid
flowchart TD
    subgraph Client["Client Tier (Browser)"]
        User["User / Analyst"]
        AdminUser["Security Administrator"]
    end

    subgraph AppServer["Application Tier (Flask / WSGI)"]
        Router["Flask Routing Engine (app.py)"]
        AuthModule["Auth & Session Handler (bcrypt)"]
        ScannerModule["Scanner Gateway (virus_scanner.py)"]
        AIEngine["AI Intelligence Agent (Groq / Llama 3)"]
        AlertModule["Alert Dispatcher (alert_system.py)"]
        FileModule["File Storage Handler (file_handler.py)"]
    end

    subgraph DataTier["Data Tier"]
        DB[(Relational DB / MySQL / SQLite)]
        DiskStorage[("Local Upload Quarantine (/uploads)")]
        AttackData["Threat Dataset (attack_data.py)"]
    end

    subgraph ExternalAPIs["External Intelligence Cloud"]
        VT["VirusTotal API v3"]
        GroqCloud["Groq Cloud (Llama 3 70B)"]
        SMTP["SMTP Mail Server"]
    end

    User -->|HTTP Requests / Uploads| Router
    AdminUser -->|Admin Auth & Queries| Router
    Router --> AuthModule
    Router --> ScannerModule
    Router --> AttackData
    AuthModule <--> DB
    Router <--> DB

    ScannerModule --> FileModule
    FileModule --> DiskStorage
    ScannerModule <-->|Upload & Poll Results| VT
    ScannerModule -->|Trigger on Malicious Result| AIEngine
    ScannerModule -->|Trigger on Malicious Result| AlertModule
    AIEngine <-->|Structured Prompts| GroqCloud
    AlertModule -->|Dispatches Alerts| SMTP
```

---

## 💻 Tech Stack

### Backend Core
- **Language:** Python 3.10+
- **Web Framework:** [Flask 3.0+](https://flask.palletsprojects.com/)
- **ORM:** [Flask-SQLAlchemy 3.1+](https://flask-sqlalchemy.palletsprojects.com/)
- **Database Driver:** [PyMySQL 1.1+](https://pymysql.readthedocs.io/)
- **Cryptography & Hashing:** [bcrypt 4.1+](https://pypi.org/project/bcrypt/)
- **Configuration Management:** [python-dotenv 1.0+](https://pypi.org/project/python-dotenv/)

### AI & Threat Intelligence APIs
- **Generative AI:** [Groq Python SDK (groq 0.9+)](https://console.groq.com/) running `llama3-70b-8192`
- **Antivirus Analysis:** [VirusTotal API v3](https://developers.virustotal.com/reference/overview) via [requests 2.31+](https://requests.readthedocs.io/)
- **Alert Dispatching:** Standard Library `smtplib` + `email.mime`

### Frontend & Design System
- **Templating:** Jinja2 (HTML5)
- **Styling:** Custom CSS3 Design System (`tokens.css`, `app.css`, `space.css`)
- **Fonts & Icons:** Google Fonts, FontAwesome

---

## 📁 Project Structure

```text
VirusGuard/
├── .env.example                # Template for environment variables and secrets
├── .gitignore                  # Git ignore rules for virtual environments, uploads, and caches
├── Procfile                    # Render & Heroku WSGI entry configuration
├── render.yaml                 # Render infrastructure-as-code blueprint specification
├── pytest.ini                  # Pytest configuration and path discovery
├── README.md                   # Complete enterprise documentation and architecture guide
├── REDESIGN_PROGRESS.md        # Architecture transition and feature tracking document
├── requirements.txt            # Production Python package dependencies (Flask, Gunicorn, etc.)
│
├── app.py                      # Core Flask application, routing, models, CSRF, and AI pipeline
├── attack_data.py              # Centralized encyclopedia dataset for attack vectors & CVEs
├── virus_scanner.py            # VirusTotal API v3 multi-engine scanner & fast-path hash client
├── alert_system.py             # Configurable SMTP security alert notification dispatcher
├── file_handler.py             # Secure file quarantine, SHA-256 calculation & auto-deletion
│
├── tests/                      # Automated test suite (pytest)
│   └── test_app.py             # Unit & integration tests for routes, auth, files & APIs
│
├── static/                     # Static media and modern design system assets
│   ├── css/
│   │   ├── app.css             # Main application layout, components, and responsive grid
│   │   └── tokens.css          # Design tokens (colors, typography, spacing, glow variables)
│   ├── space.css               # Futuristic visual effects and cosmic theme overrides
│   ├── Attacks/                # Threat encyclopedia card and blog hero images
│   ├── Post/                   # Security advisories and CVE vulnerability artwork
│   ├── aboutUS/                # Company and team profile images
│   ├── ContactUs/              # Background graphics for contact view
│   ├── Help/                   # Visual assets for help and documentation pages
│   └── Missions/               # Company mission visual assets
│
├── templates/                  # Jinja2 template components and views
│   ├── base.html               # Master layout wrapper with global head, meta, and script tags
│   ├── _nav.html               # Reusable navigation header with session-aware links
│   ├── _footer.html            # Global footer component
│   ├── landing.html            # Primary landing page and hero section
│   ├── scan.html               # File upload, scan progression, and AI report dashboard
│   ├── attacks.html            # Threat intelligence catalog / card grid
│   ├── attack_detail.html      # Dynamic single-view template for individual attack vectors
│   ├── admin.html              # Administrator user management panel (search & pagination)
│   ├── Login.html              # Secure user and administrator authentication interface
│   ├── Register.html           # User account creation interface
│   ├── ContactUs.html          # Contact form and message dispatch interface
│   ├── Help.html               # Frequently asked questions and usage guide
│   ├── Missions.html           # Platform mission and security principles
│   ├── Post.html               # Security advisories and trending vulnerability bulletin
│   └── about.html              # About the platform, team, and technology architecture
│
└── uploads/                    # Local quarantine directory for uploaded files (git-ignored)
```

---

## 🧩 Component Breakdown

| Module / Directory | Purpose & Responsibility | Key Interactions |
| :--- | :--- | :--- |
| **`app.py`** | Central orchestrator. Initializes Flask, manages DB models (`User`, `ContactMessage`), registers all endpoints, performs session verification, and coordinates scanning. | Interacts with `virus_scanner.py`, `attack_data.py`, `file_handler.py`, `alert_system.py`, and `Groq`. |
| **`virus_scanner.py`** | Wrapper around VirusTotal API v3. Handles direct file uploads (<32MB), dedicated large-file upload URLs (>32MB), and polling execution. | Invoked by `/upload` in `app.py`. Communicates externally with `https://www.virustotal.com/api/v3`. |
| **`attack_data.py`** | Single source of truth for the cybersecurity encyclopedia. Contains descriptions, classifications, and mitigation guides for 11 major attack types. | Ingested by `/Attacks` (grid view) and `/attacks/<slug>` (detail view) in `app.py`. |
| **`alert_system.py`** | Automated alerting module. Formats MIME email messages and dispatches notifications via SMTP when malicious files are confirmed. | Triggered by `app.py` when `positives > 0` in scan results. |
| **`file_handler.py`** | Manages local filesystem write operations and quarantines uploaded files inside the `/uploads` directory. | Called by `app.py` during multipart form file submissions. |
| **`templates/`** | Server-side rendered Jinja2 templates using modular partials (`_nav.html`, `_footer.html`) and template inheritance (`base.html`). | Consumed by Flask view functions to deliver responsive web pages. |
| **`static/css/`** | Custom CSS design system using CSS custom properties (variables), responsive flex/grid layouts, and cyberpunk dark-mode aesthetics. | Loaded by `base.html` for uniform interface styling. |

---

## ⚙️ Installation & Setup

### Prerequisites
- **Python:** 3.10, 3.11, or 3.12
- **MySQL Database Server:** (Optional: SQLite can be used for local testing)
- **VirusTotal API Key:** [Obtain free from VirusTotal](https://www.virustotal.com/)
- **Groq Cloud API Key:** [Obtain free from Groq Console](https://console.groq.com/)

### Step-by-Step Installation

#### 1. Clone the Repository
```bash
git clone https://github.com/H4R5787/VirusGuard.git
cd VirusGuard
```

#### 2. Create and Activate a Virtual Environment
- **On Linux / macOS:**
  ```bash
  python3 -m venv venv
  source venv/bin/activate
  ```
- **On Windows (PowerShell):**
  ```powershell
  python -m venv venv
  .\venv\Scripts\Activate.ps1
  ```
- **On Windows (Command Prompt):**
  ```cmd
  .\venv\Scripts\activate.bat
  ```

#### 3. Install Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

#### 4. Configure Environment Variables
Copy the `.env.example` file to create your `.env` file:
```bash
# On Linux / macOS:
cp .env.example .env

# On Windows:
copy .env.example .env
```
Edit `.env` with your actual API keys and database credentials (see [Environment Configuration](#-environment-configuration)).

#### 5. Initialize the Database & Run the Server
```bash
python app.py
```
*The application will automatically connect to the configured database, create the required tables (`User`, `ContactMessage`), and start the development server at `http://127.0.0.1:5000/`.*

---

## 🔐 Environment Configuration

All environment variables must be defined in the `.env` file located in the root directory:

| Variable | Required | Default Value | Description |
| :--- | :---: | :--- | :--- |
| `SECRET_KEY` | **Yes** | *None* | Cryptographic key used by Flask to sign session cookies. Generate with `python -c "import secrets; print(secrets.token_hex(32))"` |
| `GROQ_API_KEY` | **Yes** | *None* | API key for Groq Cloud to execute Llama 3 70B inferences. |
| `VIRUSTOTAL_API_KEY` | **Yes** | *None* | API key for VirusTotal v3 multi-engine file analysis. |
| `DATABASE_URL` | No | `mysql+pymysql://root:root@localhost/virus_users` | SQLAlchemy connection string. Can use SQLite via `sqlite:///virusguard.db`. |
| `ADMIN_EMAIL` | No | `Admin@gmail.com` | Fallback administrative email address for bootstrapping admin accounts. |
| `ADMIN_PASSWORD` | No | `admin` | Fallback bootstrap password for initial administrator provisioning. |

---

## 🗄️ Database Schema & Models

VirusGuard uses **Flask-SQLAlchemy** with an automatic table creation workflow on application startup (`db.create_all()`).

```mermaid
erDiagram
    USER {
        int id PK
        string name "NOT NULL"
        string email "UNIQUE, NOT NULL"
        string password "NOT NULL (bcrypt hash)"
        boolean is_admin "DEFAULT FALSE"
    }

    CONTACT_MESSAGE {
        int id PK
        string name "NOT NULL"
        string email "NOT NULL"
        string subject "NOT NULL"
        text message "NOT NULL"
        datetime created_at "DEFAULT CURRENT_TIMESTAMP"
    }
```

### Model Definitions (`app.py`)

#### `User` Model
Represents registered platform members and administrators.
- `id` (`Integer`, Primary Key): Unique identifier.
- `name` (`String(100)`, Not Null): Full name or display username.
- `email` (`String(100)`, Unique, Not Null): User login email.
- `password` (`String(100)`, Not Null): Salted `bcrypt` password hash string.
- `is_admin` (`Boolean`, Default `False`): Role-based access control flag.

#### `ContactMessage` Model
Stores inquiries and feedback submitted via the Contact Us portal.
- `id` (`Integer`, Primary Key): Message identifier.
- `name` (`String(100)`, Not Null): Sender's name.
- `email` (`String(100)`, Not Null): Sender's email.
- `subject` (`String(200)`, Not Null): Inquiry topic.
- `message` (`Text`, Not Null): Full message body.
- `created_at` (`DateTime`): Timestamp generated automatically by the database server.

---

## 🔑 Authentication & Authorization Flow

```mermaid
sequenceDiagram
    autonumber
    actor User as User / Admin
    participant App as Flask Router (/login)
    participant DB as Database (SQLAlchemy)
    participant Session as Flask Secure Session

    User->>App: POST /login (email, password)
    App->>DB: Query User where email == input_email
    alt User Found in DB
        App->>App: Verify password using bcrypt.checkpw()
        alt Password Matches & is_admin == True
            App->>Session: Set session['admin'] = True, session['name'] = user.name
            App-->>User: 302 Redirect to /admin
        else Password Matches & is_admin == False
            App->>Session: Set session['name'] = user.name, session['email'] = user.email
            App-->>User: 302 Redirect to /scan
        else Password Invalid
            App-->>User: Flash error ("Invalid email or password") -> Render /login
        end
    else Legacy Admin Fallback
        alt email == ADMIN_EMAIL and password == ADMIN_PASSWORD
            App->>Session: Set session['admin'] = True
            App-->>User: 302 Redirect to /admin
        else User Not Found
            App-->>User: Flash error ("Invalid email or password") -> Render /login
        end
    end
```

---

## 🔬 Malware Scanning & AI Pipeline

```mermaid
sequenceDiagram
    autonumber
    actor User as Authenticated User
    participant Router as Flask (/upload)
    participant Disk as Quarantine (/uploads)
    participant VT as VirusTotal API v3
    participant AI as Groq Llama 3-70B
    participant Alert as SMTP Alert System

    User->>Router: POST /upload (multipart/form-data)
    Router->>Disk: Save file to /uploads via file_handler.py
    Router->>VT: POST /files (Upload file payload)
    VT-->>Router: Return analysis_id
    loop Poll Scan Status
        Router->>VT: GET /analyses/{analysis_id}
        VT-->>Router: Status ('queued', 'in_progress', or 'completed')
    end
    alt Malicious Verdict (positives > 0)
        Router->>AI: Trigger explain_virus_info(virus_info)
        Note over Router,AI: 4 Parallel Queries: Identity, History, Mechanics, Prevention
        AI-->>Router: 4-part AI Explanation Output
        Router->>Alert: send_alert(file_path, virus_info)
        Alert->>Alert: Send notification email via SMTP
        Router-->>User: Render scan.html with Threat Badges & AI Accordion
    else Clean Verdict (positives == 0)
        Router-->>User: Render scan.html with Clean File Status
    end
```

---

## 📡 API & Route Reference

### Web Routes & Application Endpoints

| Endpoint | HTTP Method | Auth Required | Description |
| :--- | :---: | :---: | :--- |
| `/` | `GET` | No | Renders the primary landing view (`landing.html`). |
| `/Home` | `GET` | No | Permanent redirect to `/`. |
| `/Register` | `GET`, `POST` | No | User registration. Hashes password via `bcrypt` and auto-authenticates user. |
| `/login` | `GET`, `POST` | No | User/Admin authentication with role-based routing. |
| `/logout` | `GET` | Yes | Terminates session and redirects to `/login`. |
| `/scan` | `GET` | **User** | Protected dashboard for uploading and scanning files (`scan.html`). |
| `/upload` | `POST` | **User** | Receives file upload, triggers VirusTotal analysis, AI explanation, and email alerts. |
| `/Attacks` | `GET` | No | Renders the attack vector catalog (`attacks.html`). |
| `/attacks/<slug>` | `GET` | No | Renders deep-dive guide for a specific attack type (`attack_detail.html`). |
| `/<legacy_slug>` | `GET` | No | Backwards-compatibility redirects for legacy attack paths (e.g. `/SQL_Injection`). |
| `/admin` | `GET` | **Admin** | Protected management console with search (`?q=`) and pagination (`?page=`). |
| `/delete_user/<id>` | `POST` | **Admin** | Deletes a user account by primary key ID. |
| `/ContactUs` | `GET`, `POST` | No | Renders contact form and stores messages in `ContactMessage` table. |
| `/Post` | `GET` | No | Security advisories, trending threat alerts, and CVE bulletins. |
| `/Missions` | `GET` | No | Platform mission statement, security standards, and operational guidelines. |
| `/about` | `GET` | No | About the engineering team, architecture, and threat research methodology. |
| `/Help` | `GET` | No | Documentation, FAQs, and user assistance portal. |

---

## 🛡️ Admin Dashboard

Accessible at `/admin` for users with `is_admin == True` or authenticated via administrator credentials:

- **User Search:** Real-time case-insensitive search by user name or email address (`db.or_(User.name.ilike(...), User.email.ilike(...))`).
- **Pagination Engine:** Uses SQLAlchemy's native `paginate(page=page, per_page=10)` to efficiently manage high volumes of records.
- **Account Removal:** Instant, secure POST-based deletion (`/delete_user/<user_id>`) with automatic session validation.

---

## 📖 Threat Intelligence Encyclopedia

VirusGuard includes built-in guides covering 11 critical cyber threat categories:

1. **SQL Injection (SQLi):** Classic, Blind, Time-Based, and Out-of-Band query manipulation techniques.
2. **Cross-Site Scripting (XSS):** Stored, Reflected, and DOM-based client execution vulnerabilities.
3. **Command Execution (RCE/LCE):** Arbitrary system command execution vectors and sanitization strategies.
4. **Trojan Horses:** RATs, Banking Trojans, Downloaders, DDoS Bots, and Ransomware Trojans.
5. **Spyware:** Adware trackers, Keyloggers, Browser Hijackers, and System Activity Monitors.
6. **Worms:** Autonomous self-replicating network, email, file-sharing, and IM worms.
7. **Adware:** Malvertising, popup injection frameworks, and browser search hijackers.
8. **Keyloggers:** Kernel-mode vs User-mode software loggers and physical USB/wireless hardware loggers.
9. **Phishing:** Spear Phishing, Executive Whaling, Smishing (SMS), Vishing (Voice), Clone Phishing, and Pharming.
10. **Rootkits:** User Mode, Kernel Mode, Bootkits, Firmware Rootkits, and Virtual Machine Rootkits.
11. **Ransomware & Cryptojacking:** Asymmetric file encryption operations, Bitcoin/Monero resource hijacking, and mitigation protocols.

---

## 🔒 Security Implementations

- 🔑 **Cryptographic Session Integrity:** Session cookies signed using a high-entropy `SECRET_KEY`.
- 🛡️ **Salted Password Hashing:** Cryptographic password storage using `bcrypt.hashpw()` with random salt generation (`bcrypt.gensalt()`).
- 🛑 **Strict Environment Isolation:** Zero hardcoded API keys or database passwords in source code; enforced runtime checks halt startup if secrets are missing.
- 📁 **File Quarantine & Storage Control:** Uploaded binaries staged inside dedicated quarantine storage with unique name preservation.
- 🚫 **SQL Injection Protection:** Complete reliance on SQLAlchemy parameterized queries, mitigating SQL injection across all authentication and contact inputs.
- 🚦 **RBAC Protected Route Guards:** Route-level session inspections protecting `/scan`, `/upload`, `/admin`, and `/delete_user` endpoints.

---

## 🧪 Automated Testing Suite

VirusGuard includes a comprehensive automated test suite powered by `pytest` and Flask's test client covering authentication, RBAC, input validation, file quarantine, mocked VirusTotal scans, Groq AI fallbacks, and security headers:

```bash
# Run the complete test suite
pytest -v

# Run with coverage summary
pytest --tb=short
```

Mocked testing ensures that external APIs are not queried during CI/CD runs and no API quotas are consumed.

---

## 🚢 Production Deployment Guide

### Option A: Render Free Tier (Recommended Cloud Deployment)

VirusGuard is fully optimized for **Render Free Tier** web services:
- Lightweight resource footprint (< 512MB RAM)
- Fast-path SHA-256 hash lookups preventing long worker hangs
- Gunicorn WSGI server with multi-threaded workers (`--workers=2 --threads=4 --timeout=60`)
- Native `/health` zero-downtime monitoring endpoint
- Ephemeral quarantine storage with automatic file deletion

#### 1. Push Code to GitHub
Ensure all changes, including `Procfile` and `render.yaml`, are committed to your GitHub repository:
```bash
git push origin main
```

#### 2. Create a Web Service on Render
1. Navigate to the **[Render Dashboard](https://dashboard.render.com/)** and click **New +** → **Web Service**.
2. Connect your GitHub repository (`H4R5787/VirusGuard`).
3. Select **Python** as the runtime environment.
4. Set the build and start commands:
   - **Build Command:** `pip install -r requirements.txt`
   - **Start Command:** `gunicorn --workers=2 --threads=4 --timeout=60 --bind=0.0.0.0:$PORT app:app`
5. Select the **Free** instance type.

#### 3. Configure Environment Variables in Render
In the **Environment** tab of your Render service, configure:

| Variable | Recommended Value / Description |
| :--- | :--- |
| `PYTHON_VERSION` | `3.11.9` |
| `FLASK_ENV` | `production` |
| `RENDER` | `true` |
| `SECRET_KEY` | Click **Generate** (or enter a 32-byte hex string) |
| `DATABASE_URL` | Render PostgreSQL URL (`postgresql://...`) or default SQLite |
| `VIRUSTOTAL_API_KEY` | Your VirusTotal v3 API Key |
| `GROQ_API_KEY` | Your Groq Cloud API Key (`gsk_...`) |
| `ADMIN_EMAIL` | `Admin@gmail.com` (or your preferred admin email) |
| `ADMIN_PASSWORD` | Strong password for initial admin bootstrapping |

#### 4. Ephemeral Filesystem & Database Note for Render Free Tier
> [!IMPORTANT]
> - **Database Persistence:** On Render Free Tier, the local disk is ephemeral and resets during spin-downs. For persistent user accounts, threat intelligence updates, and advisories in production, create a free **Render PostgreSQL database** (or Neon / Supabase PostgreSQL) and paste its connection string into `DATABASE_URL`.
> - **Ephemeral Quarantine:** Quarantined samples in `uploads/` are deleted immediately after scanning via `file_handler.delete_file()`, ensuring zero disk bloat on Render.

---

### 🕒 Automated 12:00 AM Threat Intelligence & Advisories Engine

VirusGuard features a fully automated threat intelligence and vulnerability advisory engine that updates every day at **12:00 AM (Midnight)** without requiring manual intervention:

#### 1. Ingestion Feeds & Correlation
- **CISA Cybersecurity Advisories (Official US-CERT alerts & bulletins)**
- **BleepingComputer Cybersecurity Research Feed**
- **The Hacker News Threat Intelligence & Zero-Day Feed**
- **Automated Entity Extraction:** Automatically extracts CVE IDs (`CVE-YYYY-NNNNN`) and Indicators of Compromise (IOCs: SHA-256/MD5 hashes, malicious IP addresses).
- **Categorization & Mapping:** Classifies intelligence into canonical threat vectors (`Ransomware`, `SQL_Injection`, `Trojan_horse`, `Command_Execution`, `Phishing`, etc.) and automatically updates vector `last_updated` timestamps.
- **Strict Deduplication:** Guaranteed uniqueness enforced at the database level via canonical `source_url` index.

#### 2. Render Free Tier Architecture (Three-Tier Reliability)
Because Render Free Tier web services spin down after 15 minutes of inactivity, VirusGuard employs a robust three-tier execution strategy:
1. **Background Daemon Scheduler (`advisory_scheduler.py`):** Runs when the service is active, computes seconds until 12:00 AM UTC/Local, sleeps until midnight, and executes both `sync_latest_advisories()` and `sync_threat_intelligence()`.
2. **Boot Catch-up Sync:** Whenever the app spins up or restarts (e.g. on visitor wake-up), a background thread checks catalog freshness and ingests any missed updates 5 seconds post-boot without blocking the HTTP server.
3. **External Cron / Webhook Integration:** You can ping authenticated endpoints from an external cron service (such as [cron-job.org](https://cron-job.org/) or Render Cron):
   - `POST https://your-app.onrender.com/api/sync-threat-intel`
   - `POST https://your-app.onrender.com/api/sync-advisories`
   *(Optional: protect with `CRON_SECRET` header `Authorization: Bearer <CRON_SECRET>`)*

#### 3. CLI & Manual Triggers
- **CLI Ingestion Scripts:**
  ```bash
  python sync_threat_intel.py   # Ingest latest threat vectors and IOCs
  python sync_advisories.py     # Ingest latest CVE security advisories
  ```
- **Admin Dashboard Trigger:** Authenticated administrators can click the **Sync Threat Intel Now** or **Sync Advisories Now** buttons in the `/admin` portal for instant on-demand synchronization.

---

### Option B: Linux Server (Gunicorn & Nginx Reverse Proxy)

#### 1. Install Production Dependencies
```bash
pip install -r requirements.txt
```

#### 2. Run Gunicorn Worker Pool
```bash
gunicorn --workers 2 --threads 4 --timeout 60 --bind 127.0.0.1:8000 app:app
```

#### 3. Configure Nginx Reverse Proxy
Add the following upstream configuration to `/etc/nginx/sites-available/virusguard`:

```nginx
server {
    listen 80;
    server_name yourdomain.com;

    client_max_body_size 32M;

    location / {
        proxy_pass http://127.0.0.1:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 60s;
    }

    location /static/ {
        alias /path/to/VirusGuard/static/;
        expires 30d;
    }
}
```

---

## 🔧 Troubleshooting

### Common Issues & Resolutions

#### 1. `RuntimeError: SECRET_KEY is not set`
- **Cause:** Missing `.env` file or `SECRET_KEY` variable.
- **Solution:** Create a `.env` file based on `.env.example` and supply a secure string:
  ```bash
  python -c "import secrets; print(secrets.token_hex(32))"
  ```

#### 2. `RuntimeError: VIRUSTOTAL_API_KEY is not set`
- **Cause:** Attempting to scan a file without setting a VirusTotal key.
- **Solution:** Register at [VirusTotal](https://www.virustotal.com/), obtain an API key, and set `VIRUSTOTAL_API_KEY=your_key` in `.env`.

#### 3. Database Connection Failure (`OperationalError: (2003, "Can't connect to MySQL server")`)
- **Cause:** MySQL service is not running or credentials in `DATABASE_URL` are incorrect.
- **Solution:** Verify MySQL service status, or switch to SQLite for local development:
  ```env
  DATABASE_URL=sqlite:///virusguard.db
  ```

#### 4. Groq API Quota / Timeout
- **Cause:** Rate limits on Groq free tier or invalid key.
- **Solution:** Verify API key validity on the [Groq Console](https://console.groq.com/) and check available quota.

---

## 🗺️ Roadmap

- [ ] **Async Scan Tasks:** Integrate Celery and Redis to handle VirusTotal polling asynchronously without holding HTTP worker connections.
- [ ] **Heuristic Static Analysis Engine:** Local YARA rule matching and PE header inspection for instant offline triage.
- [ ] **Advanced SOC Dashboard:** Real-time threat visualizer, malware family clustering charts, and CSV report export.
- [ ] **REST API with JWT:** External developer API with Bearer token authentication and webhook event callbacks.
- [ ] **Multi-Factor Authentication (MFA):** TOTP-based 2FA support for administrative accounts.

---

## 🤝 Contributing

Contributions are welcome! Please follow these steps:

1. **Fork the Repository** on GitHub.
2. **Create a Feature Branch:**
   ```bash
   git checkout -b feature/AmazingFeature
   ```
3. **Commit Your Changes:**
   ```bash
   git commit -m "Add AmazingFeature"
   ```
4. **Push to Branch:**
   ```bash
   git push origin feature/AmazingFeature
   ```
5. **Open a Pull Request.**

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.

---

## 👨‍💻 Author & Acknowledgements

- **Harsh Vishwakarma** — *Lead Developer & Security Architect*
  - **Current Role:** DevOps Engineer — Cyber Security at **Tata Consultancy Services (TCS)**
  - **Specialization:** Dynamic Application Security Testing (DAST), Veracode Onboarding, API Security Testing, MFA/SSO Authentication Validation, DevSecOps & Security Tooling
  - **Portfolio:** [h4r5787.github.io/portfolio-Harsh-Vishwakarma](https://h4r5787.github.io/portfolio-Harsh-Vishwakarma/)
  - **GitHub:** [@H4R5787](https://github.com/H4R5787)
  - **LinkedIn:** [harsh-vishwakarma-b88ab4410](https://www.linkedin.com/in/harsh-vishwakarma-b88ab4410/)
  - **Email:** [vishwakarma.harsh.office@gmail.com](mailto:vishwakarma.harsh.office@gmail.com)
  - **Certifications:** Google Cybersecurity Professional Certificate, Cisco Ethical Hacker Certification, Top 100 TCS HackQuest Season 9
- **VirusTotal** for the multi-engine analysis API v3.
- **Groq & Meta AI** for ultra-fast Llama & open-weights threat intelligence inference.
- **CISA, BleepingComputer & The Hacker News** for authoritative threat intelligence feeds.
- **Flask & SQLAlchemy Communities** for open-source frameworks.
