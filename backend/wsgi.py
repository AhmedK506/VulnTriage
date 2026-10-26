"""WSGI entry point for production / container deployment.

Run with gunicorn:
    gunicorn --bind 0.0.0.0:5000 wsgi:app
"""

import os
from app import create_app

app = create_app(os.environ.get("FLASK_ENV", "production"))

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
