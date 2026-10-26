import os
from datetime import timedelta
from dotenv import load_dotenv

load_dotenv()


class Config:
    SECRET_KEY = os.environ.get("SECRET_KEY", "dev-secret-key")
    JWT_SECRET_KEY = os.environ.get("JWT_SECRET_KEY", "dev-jwt-secret")
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(hours=8)

    SQLALCHEMY_DATABASE_URI = os.environ.get(
        "DATABASE_URL", "postgresql://postgres:password@localhost:5432/vuln_triage_db"
    )
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    SQLALCHEMY_ENGINE_OPTIONS = {
        "pool_pre_ping": True,
        "pool_recycle": 300,
    }

    UPLOAD_FOLDER = os.path.join(os.path.dirname(os.path.dirname(__file__)), "uploads")
    ALLOWED_EXTENSIONS = {"xml", "json", "jsonl", "csv", "nessus"}
    MAX_CONTENT_LENGTH = int(os.environ.get("MAX_CONTENT_LENGTH", 52428800))

    NVD_API_KEY = os.environ.get("NVD_API_KEY", "")
    NVD_BASE_URL = os.environ.get(
        "NVD_BASE_URL", "https://services.nvd.nist.gov/rest/json/cves/2.0"
    )

    ML_MODEL_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "ml_data", "models"
    )


class DevelopmentConfig(Config):
    DEBUG = True
    SQLALCHEMY_ECHO = False


class ProductionConfig(Config):
    DEBUG = False


class TestingConfig(Config):
    """In-memory SQLite, bound at create_app time so tests never touch Postgres.

    Uses a StaticPool so the single in-memory database is shared across every
    connection in the process (otherwise each connection gets its own empty DB
    and `create_all()` tables vanish between requests).
    """
    from sqlalchemy.pool import StaticPool

    TESTING = True
    DEBUG = True
    JWT_SECRET_KEY = "test-secret"
    # Allow an override (e.g. TEST_DATABASE_URL) but default to shared in-memory SQLite.
    SQLALCHEMY_DATABASE_URI = os.environ.get("TEST_DATABASE_URL", "sqlite://")
    SQLALCHEMY_ENGINE_OPTIONS = {
        "poolclass": StaticPool,
        "connect_args": {"check_same_thread": False},
    }


config = {
    "development": DevelopmentConfig,
    "production": ProductionConfig,
    "testing": TestingConfig,
    "default": DevelopmentConfig,
}
