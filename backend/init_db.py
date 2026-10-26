"""
Run this once to create all database tables and seed the CWE reference table.
  cd backend
  python init_db.py
"""

import os
from app import create_app, db
import app.models  # noqa: F401 – ensures all models are registered

application = create_app(os.environ.get("FLASK_ENV", "development"))

with application.app_context():
    db.create_all()
    print("Database tables created.")

    from app.engines.cwe_mapper import CweMapper
    added = CweMapper.seed_cwe_table()
    print(f"CWE reference table seeded: {added} entries added.")

    print("Database initialisation complete.")
