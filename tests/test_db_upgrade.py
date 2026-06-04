import sqlite3

from sqlalchemy import inspect

from app.app import create_app, db


def test_start_time_column_added(tmp_path, monkeypatch):
    db_path = tmp_path / "pre.db"
    log_path = tmp_path / "logs.db"
    # create an old tournament table without start_time column
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE tournament (
            id INTEGER PRIMARY KEY,
            name VARCHAR(200) NOT NULL,
            format VARCHAR(50) NOT NULL
        )
        """
    )
    conn.close()

    monkeypatch.setenv("MTG_DB_PATH", str(db_path))
    monkeypatch.setenv("MTG_LOG_DB_PATH", str(log_path))

    app = create_app()
    with app.app_context():
        inspector = inspect(db.engine)
        cols = [c['name'] for c in inspector.get_columns('tournament')]
        assert 'start_time' in cols
        db.session.remove()


def test_break_end_column_added(tmp_path, monkeypatch):
    db_path = tmp_path / "pre.db"
    log_path = tmp_path / "logs.db"
    # create an old user table without break_end column
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE user (
            id INTEGER PRIMARY KEY,
            email VARCHAR(255),
            name VARCHAR(120) NOT NULL
        )
        """
    )
    conn.close()

    monkeypatch.setenv("MTG_DB_PATH", str(db_path))
    monkeypatch.setenv("MTG_LOG_DB_PATH", str(log_path))

    app = create_app()
    with app.app_context():
        inspector = inspect(db.engine)
        cols = [c['name'] for c in inspector.get_columns('user')]
        assert 'break_end' in cols
        assert 'permission_overrides' in cols
        db.session.remove()


def test_report_table_created(tmp_path, monkeypatch):
    db_path = tmp_path / "pre.db"
    log_path = tmp_path / "logs.db"
    conn = sqlite3.connect(db_path)
    conn.close()

    monkeypatch.setenv("MTG_DB_PATH", str(db_path))
    monkeypatch.setenv("MTG_LOG_DB_PATH", str(log_path))

    app = create_app()
    with app.app_context():
        inspector = inspect(db.engine)
        tables = inspector.get_table_names()
        assert 'report' in tables
        cols = [c['name'] for c in inspector.get_columns('report')]
        for name in (
            'report_type',
            'description',
            'reporter_id',
            'status',
            'is_read',
            'assigned_to_id',
            'actions_taken',
        ):
            assert name in cols
        db.session.remove()


def test_join_requires_approval_column_added(tmp_path, monkeypatch):
    db_path = tmp_path / "pre.db"
    log_path = tmp_path / "logs.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE tournament (
            id INTEGER PRIMARY KEY,
            name VARCHAR(200) NOT NULL,
            format VARCHAR(50) NOT NULL,
            passcode VARCHAR(4) NOT NULL
        )
        """
    )
    conn.close()

    monkeypatch.setenv("MTG_DB_PATH", str(db_path))
    monkeypatch.setenv("MTG_LOG_DB_PATH", str(log_path))

    app = create_app()
    with app.app_context():
        inspector = inspect(db.engine)
        cols = [c['name'] for c in inspector.get_columns('tournament')]
        assert 'join_requires_approval' in cols
        db.session.remove()


def test_role_level_column_added(tmp_path, monkeypatch):
    db_path = tmp_path / "pre.db"
    log_path = tmp_path / "logs.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE role (
            id INTEGER PRIMARY KEY,
            name VARCHAR(50) NOT NULL,
            permissions TEXT NOT NULL
        )
        """
    )
    conn.close()

    monkeypatch.setenv("MTG_DB_PATH", str(db_path))
    monkeypatch.setenv("MTG_LOG_DB_PATH", str(log_path))

    app = create_app()
    with app.app_context():
        inspector = inspect(db.engine)
        cols = [c['name'] for c in inspector.get_columns('role')]
        assert 'level' in cols
        db.session.remove()


def test_log_tables_created_on_startup(tmp_path, monkeypatch):
    db_path = tmp_path / "pre.db"
    log_path = tmp_path / "logs.db"
    sqlite3.connect(db_path).close()

    monkeypatch.setenv("MTG_DB_PATH", str(db_path))
    monkeypatch.setenv("MTG_LOG_DB_PATH", str(log_path))

    app = create_app()
    with app.app_context():
        logs_inspector = inspect(db.engines['logs'])
        tables = logs_inspector.get_table_names()
        assert 'site_log' in tables
        assert 'tournament_log' in tables
        db.session.remove()


def test_legacy_bad_login_attempt_table_upgraded_and_used(tmp_path, monkeypatch):
    db_path = tmp_path / "pre.db"
    log_path = tmp_path / "logs.db"
    conn = sqlite3.connect(db_path)
    conn.execute(
        """
        CREATE TABLE bad_login_attempt (
            id INTEGER PRIMARY KEY,
            email VARCHAR(255)
        )
        """
    )
    conn.close()

    monkeypatch.setenv("MTG_DB_PATH", str(db_path))
    monkeypatch.setenv("MTG_LOG_DB_PATH", str(log_path))

    app = create_app()
    app.config['TESTING'] = True
    app.config['ACCOUNT_LOCKOUT_ATTEMPTS'] = 3
    with app.app_context():
        from app.models import (
            BadLoginAttempt,
            DEFAULT_ROLE_LEVELS,
            DEFAULT_ROLE_PERMISSIONS,
            Role,
            User,
        )
        import json

        db.create_all()
        user_role = Role(
            name='user',
            permissions=json.dumps(DEFAULT_ROLE_PERMISSIONS['user']),
            level=DEFAULT_ROLE_LEVELS['user'],
        )
        user = User(email='legacy-lock@example.com', name='Legacy Lock', role=user_role)
        user.set_password('secret')
        db.session.add_all([user_role, user])
        db.session.commit()

        client = app.test_client()
        for _ in range(3):
            response = client.post('/login', data={'email': user.email, 'password': 'wrong'})
            assert response.status_code == 200

        db.session.refresh(user)
        assert user.locked_at is not None
        assert user.failed_login_count == 3
        assert db.session.query(BadLoginAttempt).filter_by(email=user.email).count() == 3
        db.session.remove()
