# Redesign Progress — Phase 0 & 1 (+ start of Phase 2/3)

Implemented against `Virus-Detection-System_UIUX-Redesign-Plan.md`.

## Phase 0 — Unblock ✅
- **`virus_scanner.py` created.** Was imported by `app.py` but didn't exist,
  so `/upload` crashed with `ImportError` at startup. Implements
  `scan_file()` / `get_scan_results()` against VirusTotal API v3 (upload,
  poll `/analyses/{id}` until `status == "completed"`, return a dict shaped
  the way `app.py` already expects).
- **Secrets pulled out of source.** `.env` (which only had placeholder
  values, but shouldn't have been committed as a pattern) is removed;
  `.env.example` added as the template; `.gitignore` added so `.env`,
  `venv/`, `instance/`, and `uploads/` never get committed again.
  `SECRET_KEY`, `DATABASE_URL`, and the admin login now come from
  environment variables instead of being hardcoded in `app.py`.
- **Logout added** (`/logout`, clears the session) plus a visible control in
  the nav — there was previously no way to end a session through the UI at
  all.
- **Removed the bundled `venv/` and `.idea/` directories** from the
  repo/deliverable — a committed virtualenv bloats the repo and can leak
  machine-specific paths; add a `requirements.txt` (also added) instead.

## Phase 1 — Foundation ✅
- **`static/css/tokens.css`** — the single color/spacing/shadow palette from
  the plan's §5.2, replacing ~5 competing hardcoded color sets.
- **`static/css/app.css`** — shared nav, footer, button, card, form, table,
  toast, and accordion styles, replacing the ~380 lines of duplicated inline
  `<style>` per page (Login.html alone had that much).
- **`templates/base.html`, `_nav.html`, `_footer.html`** — real template
  inheritance (`{% extends %}` was never used before) and one shared,
  auth-state-aware nav instead of 3 hand-copied implementations.
- **Removed dead code**: `dashboard.html` and `new_blog.html` (no Flask
  route ever served them).
- **Bootstrap version conflict resolved** — standardized on Bootstrap 5.3
  everywhere via CDN; the old Bootstrap 4 CSS + Bootstrap 5 JS combo on
  `index.html` is gone.

## Phase 2/3 — started (highest-priority pages only)
These pages were rebuilt on the new `base.html` foundation because they're
the core auth + scan flow (flagged High priority in the plan):
- **`Login.html`** — shared auth layout, show/hide password toggle.
- **`Register.html`** — shared auth layout, password strength meter,
  **auto-login after registration** (previously redirected to a separate
  login page).
- **`scan.html`** (was `index.html`, route renamed `/index` → `/scan` with a
  redirect kept for old links) — drag-and-drop with idle/dragover/uploading
  states, a real progress indicator, the "Cancel" button fixed
  (`type="button"` — it was previously a bare `<button>` that re-submitted
  the form), and the scan result rendered as a status header + **collapsible
  accordion** instead of a flat image + wall of un-collapsible flash boxes.
- **`attacks.html`** — one data-driven card grid with a real client-side
  search filter reading the same list the cards render from (the old
  hardcoded JS search array, duplicated separately in `index.html`'s navbar,
  is gone).
- **`admin.html`** — delete now requires a confirmation modal (previously
  one click, no confirmation); removed the "Create a New Post" and
  "Settings" forms since neither had a backend handler and the page also
  referenced an undefined `posts` variable that would have raised a Jinja
  error on render.
- **`landing.html`** (new; replaces `TEST.html`, served at `/`) — single
  hero, one primary CTA, no full-screen video/animation.

All new/edited templates were render-tested with Jinja2 directly (not just
visually) to catch inheritance/scoping issues — including the
`get_flashed_messages()`-can-only-be-read-once gotcha, which required
capturing flashes exactly once in `base.html` and passing them to child
templates as `all_flashes`.

## Phase 3 — Content pages + attack library ✅
- **`Home.html` retired.** It duplicated `landing.html`'s hero/features
  content under an older, unmigrated layout; `/Home` now redirects to `/`
  instead of serving a second copy of the same page.
- **`Missions.html`, `about.html`, `Help.html`, `Post.html` rebuilt on
  `base.html`.** Real content preserved, embedded `<style>` blocks and
  mismatched CDN pins removed. `Help.html`'s FAQ is now a real accordion
  (reusing the same component `scan.html` uses for its results, per the
  plan's §7 recommendation) instead of a flat list. `Post.html`'s 5 posts
  are now data (a Jinja list) rendered through one `.post-card` component
  instead of 512 lines with the content and chrome copy-pasted 5 times.
- **`ContactUs.html` rebuilt, and its form now actually works.** It was
  previously `<form action="#">` — submitting it did nothing. It now POSTs
  to `/ContactUs`, which validates the fields and saves the message to a
  new `ContactMessage` table.
- **11 attack-detail pages collapsed into one dynamic route.**
  `attack_data.py` is now the single source of truth (title, hero image,
  intro, section headings/bodies, external link) for all 12 attack types —
  extracted from the original 11 templates so no content was lost or
  rewritten. Both `/Attacks` (the grid) and the new
  `templates/attack_detail.html` (served at `/attacks/<slug>`) read from
  it. The old URLs (`/SQL_Injection`, etc.) 302-redirect to the new ones so
  existing links don't break. `attack_detail.html` adds a breadcrumb, an
  accordion for the sections, a "Scan a file" CTA, and a related-attacks
  block. `static/styles.css` (only used by the old `Post.html`) is removed.
- All new/changed templates were re-verified with the same render-test
  approach as Phase 2 (Jinja2 render with realistic context, not just
  parsed), plus a static check that every `url_for()` reference in every
  template resolves to a real Flask endpoint, and that every image path
  referenced by `attack_data.py` and the content pages exists on disk.

## Phase 4 — Admin ✅
- **DB-backed `is_admin` flag.** `User` now has an `is_admin` boolean
  column (default `False`). On startup, if a `User` row already exists
  with the legacy `ADMIN_EMAIL`, it's backfilled to `is_admin=True`
  automatically. `/login` now checks `user.is_admin` first; the
  `ADMIN_EMAIL`/`ADMIN_PASSWORD` env-var comparison is kept only as a
  fallback for installs that haven't created a DB-backed admin user yet —
  once one exists, the env-var path is never reached.
- **Search + pagination on `/admin`.** Uses Flask-SQLAlchemy's built-in
  `paginate()` plus an `ilike` filter on name/email — no new dependency.
  The table now shows a Role column (Admin/User badge).

## Not yet migrated
Per the plan's own phasing, this is Phase 5 work:
- Accessibility pass (contrast audit, full `aria-label` coverage) across
  the whole app, including pages migrated in earlier phases.
- Responsive/cross-browser QA — not yet done anywhere.
- Route/template smoke tests (pytest + Flask test client) — the checks
  done so far in Phase 3/4 were static (Jinja parse/render + endpoint
  cross-reference), not a running Flask app, since this environment has no
  network access to install `Flask-SQLAlchemy`/`groq`/`PyMySQL`. Recommend
  running the app for real (`python app.py` with deps installed) before
  deploying, to exercise the DB-backed admin login and pagination paths
  end-to-end.

## Before running
1. Copy `.env.example` to `.env` and fill in `SECRET_KEY`,
   `GROQ_API_KEY`, `VIRUSTOTAL_API_KEY` (and optionally `DATABASE_URL`,
   `ADMIN_EMAIL`, `ADMIN_PASSWORD`).
2. `pip install -r requirements.txt`
3. Have a MySQL server reachable at the configured `DATABASE_URL` (or point
   it at your own instance).
4. `python app.py`
