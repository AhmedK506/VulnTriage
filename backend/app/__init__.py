import os
from flask import Flask, jsonify, send_from_directory
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_cors import CORS
from flask_jwt_extended import JWTManager

from app.config import config

db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()


def create_app(config_name: str = "default") -> Flask:
    app = Flask(__name__)
    app.config.from_object(config[config_name])

    os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)
    os.makedirs(app.config["ML_MODEL_PATH"], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    jwt.init_app(app)

    # CORS origins are configurable via env so the same image can either serve
    # the SPA same-origin (no CORS needed) or allow a separately-hosted frontend.
    cors_origins = os.environ.get(
        "CORS_ORIGINS", "http://localhost:3000,http://127.0.0.1:3000"
    )
    CORS(app, resources={
        r"/api/*": {"origins": [o.strip() for o in cors_origins.split(",") if o.strip()]}
    })

    from app.routes.auth import auth_bp
    from app.routes.upload import upload_bp
    from app.routes.vulnerabilities import vuln_bp
    from app.routes.dashboard import dashboard_bp
    from app.routes.reports import reports_bp
    from app.routes.pipeline import pipeline_bp

    app.register_blueprint(auth_bp, url_prefix="/api/auth")
    app.register_blueprint(upload_bp, url_prefix="/api/upload")
    app.register_blueprint(vuln_bp, url_prefix="/api/vulnerabilities")
    app.register_blueprint(dashboard_bp, url_prefix="/api/dashboard")
    app.register_blueprint(reports_bp, url_prefix="/api/reports")
    app.register_blueprint(pipeline_bp, url_prefix="/api/pipeline")

    @app.get("/api/health")
    def health():
        return {"status": "ok", "service": "vuln-triage-api"}

    # Optionally serve the compiled React SPA from the same origin. This is set
    # in the Docker image (FRONTEND_DIST=/app/frontend/dist). When unset — e.g.
    # local dev on Windows where Vite serves the UI on :3000 — this is skipped
    # and the backend behaves exactly as before (API-only).
    frontend_dist = os.environ.get("FRONTEND_DIST")
    if frontend_dist and os.path.isdir(frontend_dist):
        _register_spa(app, frontend_dist)

    return app


def _register_spa(app: Flask, dist_dir: str) -> None:
    """Serve the built single-page app, falling back to index.html for client-side routes."""

    @app.route("/", defaults={"path": ""})
    @app.route("/<path:path>")
    def spa(path: str):
        # The /api/* blueprint rules are more specific and match first; this is a
        # safety net so an unmatched /api path never returns the SPA shell.
        if path.startswith("api/"):
            return jsonify({"error": "Not found"}), 404
        target = os.path.join(dist_dir, path)
        if path and os.path.isfile(target):
            return send_from_directory(dist_dir, path)
        return send_from_directory(dist_dir, "index.html")
