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

    create_app()
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

    create_app()
    inspector = inspect(db.engine)
    cols = [c['name'] for c in inspector.get_columns('user')]
    assert 'break_end' in cols
    db.session.remove()
