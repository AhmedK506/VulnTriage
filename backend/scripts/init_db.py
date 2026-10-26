"""Initialise the database schema and seed a default analyst user.

Idempotent — safe to run on every container start. There are no Alembic
migrations in this project, so the schema is created directly with
``db.create_all()`` (importing ``app.models`` registers all tables).

Environment:
    FLASK_ENV        config name (default: production)
    ADMIN_USERNAME   default web-UI login   (default: admin)
    ADMIN_PASSWORD   default web-UI password (default: admin)
    ADMIN_EMAIL      default web-UI email
"""

import os

from app import create_app, db
import app.models  # noqa: F401  (registers every model on the SQLAlchemy metadata)
from app.models.user import User


def main() -> None:
    app = create_app(os.environ.get("FLASK_ENV", "production"))
    with app.app_context():
        db.create_all()

        username = os.environ.get("ADMIN_USERNAME", "admin")
        password = os.environ.get("ADMIN_PASSWORD", "admin")
        email = os.environ.get("ADMIN_EMAIL", "admin@vulntriage.local")

        if not User.query.filter_by(username=username).first():
            user = User(username=username, email=email, role="analyst")
            user.set_password(password)
            db.session.add(user)
            db.session.commit()
            print(f"[init_db] created default user '{username}'")
        else:
            print(f"[init_db] user '{username}' already exists — leaving as-is")

        print("[init_db] schema ready")


if __name__ == "__main__":
    main()
