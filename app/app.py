from fastapi import FastAPI
from nicegui import ui
import os
import hashlib
from sqlalchemy import (
    create_engine,
    inspect,
    text,
    Column,
    Integer,
    String,
    Text,
    Boolean,
    DateTime,
    ForeignKey,
    LargeBinary,
)
from sqlalchemy.orm import declarative_base, relationship, scoped_session, sessionmaker


class Database:
    def __init__(self) -> None:
        self.Model = declarative_base()
        self.Column = Column
        self.Integer = Integer
        self.String = String
        self.Text = Text
        self.Boolean = Boolean
        self.DateTime = DateTime
        self.ForeignKey = ForeignKey
        self.LargeBinary = LargeBinary
        self.relationship = relationship
        from sqlalchemy.orm import backref
        self.backref = backref
        self.engine = None
        self.session = None

    def init_app(self, url: str) -> None:
        self.engine = create_engine(url, connect_args={"check_same_thread": False})
        self.session = scoped_session(sessionmaker(bind=self.engine))

    def create_all(self) -> None:
        self.Model.metadata.create_all(self.engine)


db = Database()
PASSWORD_KEY = None
PASSWORD_SEED = None


def create_app() -> FastAPI:
    app = FastAPI()

    db_file = os.environ.get("MTG_DB_PATH", "mtg_tournament.db")
    log_db_file = os.environ.get("MTG_LOG_DB_PATH", db_file.replace(".db", "_logs.db"))
    db.init_app(f"sqlite:///{db_file}")

    seed_env = os.environ.get("PASSWORD_SEED")
    if seed_env is None:
        seed_bytes = os.urandom(32)
        seed_display = seed_bytes.hex()
    else:
        seed_bytes = seed_env.encode()
        seed_display = seed_env
    global PASSWORD_KEY, PASSWORD_SEED
    PASSWORD_KEY = hashlib.sha256(seed_bytes).digest()
    PASSWORD_SEED = seed_display

    inspector = inspect(db.engine)
    if "tournament" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("tournament")]
        if "start_time" not in columns:
            db.session.execute(text("ALTER TABLE tournament ADD COLUMN start_time DATETIME"))
            db.session.commit()
    if "user" in inspector.get_table_names():
        columns = [c["name"] for c in inspector.get_columns("user")]
        if "break_end" not in columns:
            db.session.execute(text("ALTER TABLE user ADD COLUMN break_end DATETIME"))
            db.session.commit()

    from .models import Tournament

    @ui.page("/")
    def index_page() -> None:
        tournaments = (
            db.session.query(Tournament)
            .order_by(Tournament.created_at.desc())
            .all()
        )
        with ui.column():
            ui.label("Tournaments")
            for t in tournaments:
                ui.label(f"{t.name} ({t.format})")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    ui.run_with(app)
    return app


app = create_app()
