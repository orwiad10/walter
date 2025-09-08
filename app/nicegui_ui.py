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
from typing import Dict

from nicegui import ui

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


def _header() -> None:
    """Common navigation header used on all pages."""
    with ui.header().classes("justify-between items-center"):
        ui.link("WaLTER", "/").classes("text-h5")
        with ui.row().classes("items-center gap-2"):
            if "user_id" in ui.storage.user:
                ui.label(f"Hi, {ui.storage.user['name']}")
                ui.button("Messages", on_click=lambda: ui.open("/messages"))
                ui.button("Logout", on_click=lambda: ui.open("/logout"))
            else:
                ui.button("Login", on_click=lambda: ui.open("/login"))
                ui.button("Register", on_click=lambda: ui.open("/register"))


def _login_required() -> bool:
    """Redirect to the login page if no user session exists."""
    if "user_id" not in ui.storage.user:
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
            ui.storage.user["user_id"] = user.id
            ui.storage.user["name"] = user.name
            try:
                priv_pem = user.decrypt_private_key(password.value)
                if priv_pem:
                    ui.storage.user["private_key"] = base64.b64encode(priv_pem).decode()
            except Exception:
                ui.storage.user["private_key"] = None
        ui.open("/")

    ui.button("Login", on_click=do_login)


@ui.page("/logout")
def logout_page() -> None:
    ui.storage.user.clear()
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
        is_player = False
        if "user_id" in ui.storage.user:
            is_player = (
                db.session.query(TournamentPlayer)
                .filter_by(tournament_id=tid, user_id=ui.storage.user["user_id"])
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

        if "user_id" in ui.storage.user and not is_player:
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
                        tournament_id=tid, user_id=ui.storage.user["user_id"]
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
    priv_b64 = ui.storage.user.get("private_key")
    with flask_app.app_context():
        msgs = []
        if priv_b64:
            priv = load_pem_private_key(base64.b64decode(priv_b64), password=None)
            msgs_db = (
                db.session.query(Message)
                .filter_by(recipient_id=ui.storage.user["user_id"])
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
            msg = Message(
                sender_id=ui.storage.user["user_id"],
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
    ui.run()


if __name__ == "__main__":
    run()

