from fastapi import FastAPI, Request
from nicegui import ui
import os
import hashlib
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
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

    from .models import Tournament, User, Message

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

    @ui.page("/messages")
    async def messages_page(request: Request) -> None:
        user_id = int(request.query_params.get("user_id", 0))
        password = request.query_params.get("password", "")
        with ui.column():
            ui.label("Messages")
            user = db.session.get(User, user_id) if user_id else None
            if not user or not password:
                ui.label("user_id and password query parameters required")
                return
            private_pem = user.decrypt_private_key(password)
            if not private_pem:
                ui.label("Cannot decrypt messages")
                return
            private_key = serialization.load_pem_private_key(private_pem, password=None)
            msgs = (
                db.session.query(Message)
                .filter_by(recipient_id=user.id)
                .order_by(Message.sent_at.desc())
                .all()
            )
            for m in msgs:
                try:
                    aes_key = private_key.decrypt(
                        m.key_encrypted,
                        padding.OAEP(
                            mgf=padding.MGF1(algorithm=hashes.SHA256()),
                            algorithm=hashes.SHA256(),
                            label=None,
                        ),
                    )
                    aesgcm = AESGCM(aes_key)
                    title = aesgcm.decrypt(m.title_nonce, m.title_encrypted, None).decode()
                    body = aesgcm.decrypt(m.body_nonce, m.body_encrypted, None).decode()
                    with ui.expansion(title):
                        ui.label(body)
                        ui.label(f"From: {m.sender.name} at {m.sent_at}")
                except Exception:
                    ui.label("Failed to decrypt message")

    @ui.page("/messages/send")
    def send_message_page() -> None:
        recipient = ui.input("To (email)")
        sender = ui.input("From (email)")
        title = ui.input("Title")
        body = ui.textarea("Body")

        def do_send() -> None:
            sender_user = db.session.query(User).filter_by(email=sender.value).first()
            recipient_user = db.session.query(User).filter_by(email=recipient.value).first()
            if not sender_user or not recipient_user or not recipient_user.public_key:
                ui.notify("Invalid sender or recipient", color="negative")
                return
            public_key = serialization.load_pem_public_key(recipient_user.public_key)
            aes_key = os.urandom(32)
            aesgcm = AESGCM(aes_key)
            nonce_title = os.urandom(12)
            nonce_body = os.urandom(12)
            title_enc = aesgcm.encrypt(nonce_title, title.value.encode(), None)
            body_enc = aesgcm.encrypt(nonce_body, body.value.encode(), None)
            key_enc = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            msg = Message(
                sender_id=sender_user.id,
                recipient_id=recipient_user.id,
                key_encrypted=key_enc,
                title_encrypted=title_enc,
                title_nonce=nonce_title,
                body_encrypted=body_enc,
                body_nonce=nonce_body,
            )
            db.session.add(msg)
            db.session.commit()
            ui.notify("Message sent", color="positive")

        ui.button("Send", on_click=do_send)

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    ui.run_with(app)
    return app


app = create_app()
