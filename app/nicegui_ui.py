"""NiceGUI front end for the WaLTER tournament manager.

This module recreates the minimal set of HTML templates using NiceGUI
components so that the application can be browsed without the
original CSS or Jinja templates.  It interacts directly with the
existing Flask/SQLAlchemy backend and therefore does not modify
backend behaviour; only the user interface layer is replaced.
"""

from __future__ import annotations

import base64
import os
import secrets
from typing import Dict

from nicegui import context, ui

from .app import create_app, db
from .models import Message, Role, Tournament, TournamentPlayer, User

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import (
    load_pem_private_key,
    load_pem_public_key,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Create the Flask app so we can access the database and models.
flask_app = create_app()


# simple in-memory session storage keyed by a cookie value
_SESSIONS: Dict[str, Dict[str, str]] = {}
_SESSION_COOKIE = "walter_session"


def _current_client():
    """Return the active NiceGUI client if available.

    Older NiceGUI versions expose the client via ``context.client`` while
    newer releases provide a ``context.get_client`` helper which itself may
    raise an ``AttributeError`` when no client is present.  This helper
    normalises those variations and simply returns ``None`` if the client
    is not accessible.
    """

    try:  # NiceGUI >= 1.3
        return context.get_client()
    except Exception:  # pragma: no cover - depends on NiceGUI internals
        return getattr(context, "client", None)


def _client_cookies() -> Dict[str, str]:
    """Best-effort retrieval of cookies from the current request.

    Some NiceGUI versions expose cookies directly on the client while others
    only expose the underlying ``request`` object.  This helper looks up the
    request and returns its cookies, falling back to an empty dictionary when
    no cookies are available.
    """

    client = _current_client()
    request = getattr(client, "request", None) if client else getattr(context, "request", None)
    return getattr(request, "cookies", {}) if request else {}


def _get_session() -> Dict[str, str]:
    cookies = _client_cookies()
    token = cookies.get(_SESSION_COOKIE)
    if token and token in _SESSIONS:
        return _SESSIONS[token]
    return {}


def _set_session(data: Dict[str, str]) -> None:
    token = secrets.token_urlsafe(16)
    _SESSIONS[token] = data
    ui.cookie(_SESSION_COOKIE, token, max_age=7 * 24 * 3600)


def _clear_session() -> None:
    cookies = _client_cookies()
    token = cookies.get(_SESSION_COOKIE)
    if token:
        _SESSIONS.pop(token, None)
    ui.cookie(_SESSION_COOKIE, "", max_age=0)


def _header() -> None:
    """Common navigation header used on all pages."""
    session = _get_session()
    with ui.header().classes("justify-between items-center"):
        ui.link("WaLTER", "/").classes("text-h5")
        with ui.row().classes("items-center gap-2"):
            if "user_id" in session:
                ui.label(f"Hi, {session['name']}")
                ui.button("Messages", on_click=lambda: ui.open("/messages"))
                ui.button("Logout", on_click=lambda: ui.open("/logout"))
            else:
                ui.button("Login", on_click=lambda: ui.open("/login"))
                ui.button("Register", on_click=lambda: ui.open("/register"))


def _login_required() -> bool:
    """Redirect to the login page if no user session exists."""
    if "user_id" not in _get_session():
        ui.open("/login")
        return False
    return True


@ui.page("/")
def index_page() -> None:
    """Display a list of tournaments."""
    _header()
    with flask_app.app_context():
        tournaments = (
            db.session.query(Tournament)
            .order_by(Tournament.created_at.desc())
            .all()
        )
        player_counts: Dict[int, int] = {t.id: len(t.players) for t in tournaments}

    with ui.column().classes("p-4 gap-4"):
        for t in tournaments:
            with ui.card().classes("p-4 w-full"):
                ui.label(t.name).classes("text-h6")
                ui.label(f"Format: {t.format}")
                ui.label(f"Cut: {t.cut.upper()}")
                ui.label(f"Players: {player_counts[t.id]}")
                ui.button(
                    "View",
                    on_click=lambda t_id=t.id: ui.open(f"/t/{t_id}"),
                )


@ui.page("/login")
def login_page() -> None:
    """Authenticate a user against the existing database."""
    _header()
    email = ui.input("Email")
    password = ui.input("Password", password=True, password_toggle_button=True)
    error = ui.label().classes("text-red-500")

    def do_login() -> None:
        with flask_app.app_context():
            user = (
                db.session.query(User)
                .filter_by(email=email.value.strip().lower())
                .first()
            )
            if not user or not user.check_password(password.value):
                error.text = "Invalid credentials"
                return
            data = {"user_id": str(user.id), "name": user.name}
            try:
                priv_pem = user.decrypt_private_key(password.value)
                if priv_pem:
                    data["private_key"] = base64.b64encode(priv_pem).decode()
            except Exception:
                pass
            _set_session(data)
        ui.open("/")

    ui.button("Login", on_click=do_login)


@ui.page("/logout")
def logout_page() -> None:
    _clear_session()
    ui.open("/")


@ui.page("/register")
def register_page() -> None:
    """Create a new user account and optionally join a tournament."""
    _header()
    name = ui.input("Name")
    email = ui.input("Email")
    password = ui.input("Password", password=True, password_toggle_button=True)

    with flask_app.app_context():
        tournaments = (
            db.session.query(Tournament)
            .order_by(Tournament.created_at.desc())
            .all()
        )

    select_items = {"": "-- None --"}
    select_items.update({str(t.id): t.name for t in tournaments})
    tournament_id = ui.select(select_items, label="Join Tournament", value="")
    passcode = ui.input("Tournament Passcode", maxlength=4)
    error = ui.label().classes("text-red-500")

    def do_register() -> None:
        with flask_app.app_context():
            if (
                db.session.query(User)
                .filter_by(email=email.value.strip().lower())
                .first()
            ):
                error.text = "Email already registered"
                return
            role_user = db.session.query(Role).filter_by(name="user").first()
            u = User(
                email=email.value.strip().lower(),
                name=name.value.strip(),
                role=role_user,
            )
            u.set_password(password.value)
            u.generate_keys(password.value)
            db.session.add(u)
            db.session.commit()

            if tournament_id.value:
                t = db.session.get(Tournament, int(tournament_id.value))
                code = passcode.value or ""
                if not t or (t.passcode and code != t.passcode):
                    error.text = "Invalid tournament passcode"
                    return
                tp = TournamentPlayer(tournament_id=t.id, user_id=u.id)
                db.session.add(tp)
                db.session.commit()

        ui.open("/login")

    ui.button("Create Account", on_click=do_register)


@ui.page("/t/{tid}")
def view_tournament_page(tid: int) -> None:
    """Display details for a tournament and allow players to join."""
    _header()
    with flask_app.app_context():
        t = db.session.get(Tournament, tid)
        if not t:
            ui.label("Tournament not found").classes("p-4")
            return
        players = [tp.user for tp in t.players]
        session = _get_session()
        is_player = False
        if "user_id" in session:
            is_player = (
                db.session.query(TournamentPlayer)
                .filter_by(tournament_id=tid, user_id=int(session["user_id"]))
                .first()
                is not None
            )

    with ui.column().classes("p-4 gap-2"):
        ui.label(t.name).classes("text-h5")
        ui.label(f"Format: {t.format}")
        ui.label(f"Cut: {t.cut.upper()}")
        ui.label("Players:")
        for p in players:
            ui.label(f"- {p.name}")

        if "user_id" in session and not is_player:
            pass_input = ui.input("Passcode", maxlength=4)

            def do_join() -> None:
                if not _login_required():
                    return
                with flask_app.app_context():
                    t2 = db.session.get(Tournament, tid)
                    if t2.passcode and pass_input.value != t2.passcode:
                        ui.notify("Invalid passcode", type="negative")
                        return
                    tp = TournamentPlayer(
                        tournament_id=tid, user_id=int(session["user_id"])
                    )
                    db.session.add(tp)
                    db.session.commit()
                ui.open(f"/t/{tid}")

            ui.button("Join", on_click=do_join)


@ui.page("/messages")
def messages_page() -> None:
    """Inbox for the logged in user."""
    if not _login_required():
        return
    _header()
    session = _get_session()
    priv_b64 = session.get("private_key")
    with flask_app.app_context():
        msgs = []
        if priv_b64:
            priv = load_pem_private_key(base64.b64decode(priv_b64), password=None)
            msgs_db = (
                db.session.query(Message)
                .filter_by(recipient_id=int(session["user_id"]))
                .order_by(Message.sent_at.desc())
                .all()
            )
            for m in msgs_db:
                try:
                    aes_key = priv.decrypt(
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
                    msgs.append({
                        "title": title,
                        "body": body,
                        "sender": m.sender.name,
                        "sent_at": m.sent_at,
                    })
                    if not m.is_read:
                        m.is_read = True
                except Exception:
                    continue
            db.session.commit()

    with ui.column().classes("p-4 gap-4"):
        if not msgs:
            ui.label("No messages")
        for m in msgs:
            with ui.card().classes("p-4 w-full"):
                ui.label(m["title"]).classes("text-h6")
                ui.label(f"From: {m['sender']} at {m['sent_at']}")
                ui.label(m["body"]).classes("mt-2")
        ui.button("Compose", on_click=lambda: ui.open("/messages/send"))


@ui.page("/messages/send")
def send_message_page() -> None:
    """Compose a new message."""
    if not _login_required():
        return
    _header()
    to_input = ui.input("To (email)")
    title_input = ui.input("Title")
    body_input = ui.textarea("Body")
    error = ui.label().classes("text-red-500")

    def do_send() -> None:
        with flask_app.app_context():
            recipient = (
                db.session.query(User)
                .filter_by(email=to_input.value.strip().lower())
                .first()
            )
            if not recipient or not recipient.public_key:
                error.text = "Recipient not found or cannot receive messages"
                return
            public_key = load_pem_public_key(recipient.public_key)
            aes_key = os.urandom(32)
            aesgcm = AESGCM(aes_key)
            nonce_title = os.urandom(12)
            nonce_body = os.urandom(12)
            title_enc = aesgcm.encrypt(nonce_title, title_input.value.encode(), None)
            body_enc = aesgcm.encrypt(nonce_body, body_input.value.encode(), None)
            key_enc = public_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            session = _get_session()
            msg = Message(
                sender_id=int(session["user_id"]),
                recipient_id=recipient.id,
                key_encrypted=key_enc,
                title_encrypted=title_enc,
                title_nonce=nonce_title,
                body_encrypted=body_enc,
                body_nonce=nonce_body,
            )
            db.session.add(msg)
            db.session.commit()
        ui.open("/messages")

    ui.button("Send", on_click=do_send)


def run() -> None:
    """Run the NiceGUI frontend application."""
    host = os.environ.get("FLASK_RUN_HOST", "127.0.0.1")
    port = int(os.environ.get("FLASK_RUN_PORT", "8080"))
    ui.run(host=host, port=port, reload=False)


if __name__ == "__main__":
    run()

