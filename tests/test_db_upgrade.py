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
