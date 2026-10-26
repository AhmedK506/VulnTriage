"""Shared pytest fixtures.

Builds the app with the dedicated `testing` config so the SQLAlchemy engine is
bound to in-memory SQLite from the start (overriding the URI *after* create_app
is too late — Flask-SQLAlchemy binds the engine during db.init_app).

These fixtures also satisfy pytest-flask, whose autouse request-context fixture
calls methods on the `app` fixture value — so `app` must be a real Flask app,
never a tuple.
"""

import pytest

from app import create_app, db as _db
from app.models.scanner_upload import ScannerUpload


@pytest.fixture
def app():
    application = create_app("testing")
    with application.app_context():
        _db.create_all()
        yield application
        _db.session.remove()
        _db.drop_all()


@pytest.fixture
def db(app):
    """Expose the SQLAlchemy handle within an active app context."""
    return _db


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def upload(app):
    """A persisted ScannerUpload row for parser tests."""
    record = ScannerUpload(
        user_id=1,
        filename="test.xml",
        original_filename="test.xml",
        scanner_type="zap",
        file_size=100,
        file_path="/tmp/test.xml",
    )
    _db.session.add(record)
    _db.session.commit()
    return record
