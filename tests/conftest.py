import os
import json
import pytest
from app.app import create_app, db
from app.models import Role, DEFAULT_ROLE_PERMISSIONS


@pytest.fixture
def app(tmp_path, monkeypatch):
    # use temporary SQLite databases for testing
    monkeypatch.setenv("MTG_DB_PATH", str(tmp_path / "test.db"))
    monkeypatch.setenv("MTG_LOG_DB_PATH", str(tmp_path / "test_logs.db"))
    application = create_app()
    application.config['TESTING'] = True
    with application.app_context():
        db.create_all()
        # set up default roles
        for name, perms in DEFAULT_ROLE_PERMISSIONS.items():
            role = Role(name=name, permissions=json.dumps(perms))
            db.session.add(role)
        db.session.commit()
        yield application
        db.session.remove()


@pytest.fixture
def session(app):
    return db.session
