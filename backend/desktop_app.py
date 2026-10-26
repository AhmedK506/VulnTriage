"""
VulnTriage desktop app (Linux / Kali) — native window via pywebview.

Boots the Flask backend (SQLite, serving the compiled React SPA) on a local
port using waitress, waits until it answers, then opens it in a native
GTK/WebKit window. No browser, no Postgres, no terminal — double-click the
applications-menu entry and the GUI opens, ZAP-style.

The pywebview import is deliberately lazy (inside main) so the server logic
can be imported and tested on machines without a GUI/webview backend.
"""

import os
import sys
import time
import socket
import logging
import threading
import urllib.request

# ── Paths & environment (set BEFORE importing the Flask app/config) ───────────
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))   # …/FYP
BACKEND = os.path.join(ROOT, "backend")
if BACKEND not in sys.path:
    sys.path.insert(0, BACKEND)

# Per-user data dir so the database persists across launches and never needs
# write access to the install location.
DATA_DIR = os.path.join(os.path.expanduser("~"), ".local", "share", "vulntriage")
os.makedirs(DATA_DIR, exist_ok=True)

DIST = os.path.join(ROOT, "frontend", "dist")

os.environ.setdefault("FLASK_ENV", "production")
os.environ.setdefault(
    "DATABASE_URL",
    "sqlite:///" + os.path.join(DATA_DIR, "vulntriage.db").replace("\\", "/"),
)
if os.path.isdir(DIST):
    os.environ.setdefault("FRONTEND_DIST", DIST)

APP_TITLE = "VulnTriage — AI Vulnerability Triage"


def _free_port(preferred: int = 5000) -> int:
    """Return the preferred port if free, otherwise an OS-assigned one."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        s.bind(("127.0.0.1", preferred))
        return preferred
    except OSError:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]
    finally:
        s.close()


def init_db():
    """Create the schema and seed the default analyst user. Returns the app."""
    from app import create_app, db
    import app.models  # noqa: F401  (registers every table)
    from app.models.user import User

    app = create_app(os.environ["FLASK_ENV"])
    with app.app_context():
        db.create_all()
        username = os.environ.get("ADMIN_USERNAME", "admin")
        if not User.query.filter_by(username=username).first():
            user = User(
                username=username,
                email=os.environ.get("ADMIN_EMAIL", "admin@vulntriage.local"),
                role="analyst",
            )
            user.set_password(os.environ.get("ADMIN_PASSWORD", "admin"))
            db.session.add(user)
            db.session.commit()
    return app


def serve(app, port: int):
    """Serve the app with waitress (production-grade, pure-Python)."""
    logging.getLogger("waitress").setLevel(logging.ERROR)
    from waitress import serve as waitress_serve
    waitress_serve(app, host="127.0.0.1", port=port, threads=6)


def wait_until_up(port: int, timeout: float = 25.0) -> bool:
    """Poll /api/health until the server responds or the timeout elapses."""
    url = f"http://127.0.0.1:{port}/api/health"
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=1) as resp:
                if resp.status == 200:
                    return True
        except Exception:
            time.sleep(0.3)
    return False


def open_in_webview(url: str):
    """Native GTK/WebKit window (default). Best on real hardware."""
    import webview  # lazy — only this path needs a webview backend installed
    webview.create_window(
        APP_TITLE, url, width=1400, height=900, min_size=(1024, 700)
    )
    webview.start()


def open_in_browser(url: str) -> int:
    """Chromium app-window fallback.

    WebKitGTK renders a blank white page on VMs with no 3D acceleration
    ("VMware: No 3D enabled"), regardless of the software-GL/DMABUF env tweaks.
    A Chromium '--app' window gives the same chrome-less, single-window UX and
    renders correctly there. Selected with VULNTRIAGE_UI=browser. Blocks until
    the window is closed so the embedded server stays up for its lifetime.
    """
    import shutil
    import subprocess

    profile = os.path.join(DATA_DIR, "browser-profile")
    for binary in ("chromium", "chromium-browser", "google-chrome", "brave-browser"):
        path = shutil.which(binary)
        if path:
            return subprocess.call([
                path,
                f"--app={url}",
                f"--user-data-dir={profile}",
                "--class=VulnTriage",
                "--no-first-run",
                "--no-default-browser-check",
                "--window-size=1400,900",
            ])
    # No Chromium-family browser: fall back to the default browser (normal tab)
    # and idle so the daemon server thread keeps serving.
    import webbrowser
    webbrowser.open(url)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


def main():
    app = init_db()
    port = _free_port()

    server = threading.Thread(target=serve, args=(app, port), daemon=True)
    server.start()

    if not wait_until_up(port):
        sys.stderr.write("VulnTriage: backend failed to start within timeout\n")
        sys.exit(1)

    url = f"http://127.0.0.1:{port}"
    ui = os.environ.get("VULNTRIAGE_UI", "webview").strip().lower()
    if ui in ("browser", "chromium", "chrome"):
        sys.exit(open_in_browser(url))
    open_in_webview(url)


if __name__ == "__main__":
    main()
