#!/usr/bin/env python
"""Populate the development database with rich demo data."""
from __future__ import annotations

import argparse
import json
from datetime import datetime, timedelta, timezone
from typing import Iterable, Sequence

from pathlib import Path
import sys

PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from app.app import create_app, db
from app import models


def ensure_roles() -> dict[str, models.Role]:
    """Ensure the default roles exist with up-to-date permissions."""
    roles: dict[str, models.Role] = {}
    for name, permissions in models.DEFAULT_ROLE_PERMISSIONS.items():
        role = models.Role.query.filter_by(name=name).first()
        if role is None:
            role = models.Role(name=name)
        role.permissions = json.dumps(permissions)
        role.level = models.DEFAULT_ROLE_LEVELS.get(name, 500)
        db.session.add(role)
        roles[name] = role
    db.session.commit()
    return roles


def ensure_admin_user() -> models.User:
    admin = models.User.query.filter_by(email="admin@example.com").first()
    if admin is None:
        admin = models.User(
            email="admin@example.com",
            name="Admin User",
            is_admin=True,
        )
        admin.set_password("admin123")
        db.session.add(admin)
        db.session.commit()
    return admin


def create_user(name: str, email: str, role: models.Role, password: str = "player123") -> models.User:
    user = models.User.query.filter_by(email=email).first()
    if user is None:
        user = models.User(name=name, email=email, role=role)
        user.set_password(password)
        db.session.add(user)
    return user


def attach_players(tournament: models.Tournament, users: Sequence[models.User]) -> list[models.TournamentPlayer]:
    entries: list[models.TournamentPlayer] = []
    for user in users:
        entry = models.TournamentPlayer.query.filter_by(
            tournament_id=tournament.id, user_id=user.id
        ).first()
        if entry is None:
            entry = models.TournamentPlayer(tournament=tournament, user=user)
            db.session.add(entry)
        entries.append(entry)
    db.session.commit()
    return entries


def create_round(
    tournament: models.Tournament,
    number: int,
    tables: Iterable[Sequence[models.TournamentPlayer | None]],
) -> models.Round:
    rnd = models.Round.query.filter_by(tournament_id=tournament.id, number=number).first()
    if rnd is None:
        rnd = models.Round(tournament=tournament, number=number)
        db.session.add(rnd)
        db.session.commit()
    with db.session.no_autoflush:
        for table_index, seats in enumerate(tables, start=1):
            match = models.Match.query.filter_by(
                round_id=rnd.id, table_number=table_index
            ).first()
            if match is None:
                match = models.Match(round=rnd, table_number=table_index)
            db.session.add(match)
            for seat, player in enumerate(seats, start=1):
                setattr(match, f"player{seat}_id", player.id if player else None)
            if match.result is None:
                match.result = models.MatchResult()
            db.session.add(match.result)
            match.result.player1_wins = 2
            match.result.player2_wins = 1
            match.result.draws = 0
            if len([p for p in seats if p]) == 4:
                match.result.is_draw = False
                match.result.p1_place = 1
                match.result.p2_place = 2
                match.result.p3_place = 3
                match.result.p4_place = 4
            match.completed = True
    db.session.commit()
    return rnd


def build_sample_world(reset: bool = False) -> None:
    if reset:
        db.drop_all()
        db.create_all()
    roles = ensure_roles()
    ensure_admin_user()

    manager = create_user("Morgan Reid", "morgan@example.com", roles["manager"], "manager123")
    floor_judge = create_user("Kira Lopez", "kira@example.com", roles["floor judge"], "floor123")
    venue_judge = create_user("Asher Patel", "asher@example.com", roles["venue judge"], "venue123")

    player_details = [
        ("Lena Hart", "lena@example.com"),
        ("Noah Kim", "noah@example.com"),
        ("Eli Turner", "eli@example.com"),
        ("Zara Brooks", "zara@example.com"),
        ("Theo White", "theo@example.com"),
        ("Maya Singh", "maya@example.com"),
        ("Riley Chen", "riley@example.com"),
        ("Sofia Martins", "sofia@example.com"),
        ("Jonah Price", "jonah@example.com"),
        ("Aria Wells", "aria@example.com"),
        ("Miles Becker", "miles@example.com"),
        ("Priya Das", "priya@example.com"),
    ]
    players = [create_user(name, email, roles["user"]) for name, email in player_details]
    db.session.commit()

    now = datetime.now(timezone.utc)

    def ensure_tournament(name: str, fmt: str, cut: str, round_length: int, hours_from_now: int) -> models.Tournament:
        tournament = models.Tournament.query.filter_by(name=name).first()
        if tournament is None:
            tournament = models.Tournament(name=name, format=fmt)
        tournament.cut = cut
        tournament.round_length = round_length
        tournament.rules_enforcement_level = "Regular"
        tournament.head_judge = manager
        tournament.start_time = now + timedelta(hours=hours_from_now)
        tournament.round_timer_end = now + timedelta(minutes=round_length)
        tournament.draft_time = 45 if fmt == "Draft" else None
        tournament.deck_build_time = 30 if fmt != "Commander" else None
        tournament.start_table_number = 11
        db.session.add(tournament)
        db.session.commit()
        return tournament

    modern = ensure_tournament("Modern Showdown", "Constructed", "top8", 50, 1)
    commander = ensure_tournament("Commander League", "Commander", "none", 75, 3)
    draft = ensure_tournament("Midnight Draft", "Draft", "top4", 40, 5)

    modern_players = attach_players(modern, players[:8])
    commander_players = attach_players(commander, players[:6])
    draft_players = attach_players(draft, players[6:12])

    create_round(modern, 1, [
        (modern_players[0], modern_players[1]),
        (modern_players[2], modern_players[3]),
        (modern_players[4], modern_players[5]),
        (modern_players[6], modern_players[7]),
    ])
    create_round(commander, 1, [
        (commander_players[0], commander_players[1], commander_players[2], commander_players[3]),
        (commander_players[4], commander_players[5]),
    ])
    create_round(draft, 1, [
        (draft_players[0], draft_players[1]),
        (draft_players[2], draft_players[3]),
        (draft_players[4], draft_players[5]),
    ])

    if models.LostFoundItem.query.count() == 0:
        db.session.add(
            models.LostFoundItem(
                title="Binder with Modern Staples",
                description="Blue Ultimate Guard binder with Jace sleeves.",
                location="Main Stage",
                reporter_name="Morgan Reid",
            )
        )

    if models.Report.query.count() == 0:
        db.session.add(
            models.Report(
                reporter=manager,
                reported_user=players[2],
                report_type="conduct",
                description="Player reported marked sleeves during Round 2.",
                status="investigating",
                assigned_to=floor_judge,
                actions_taken="Sleeves replaced, match result stands.",
            )
        )

    if models.Message.query.count() == 0:
        db.session.add(
            models.Message(
                sender=manager,
                recipient=players[0],
                key_encrypted=b"key",
                sender_key_encrypted=b"sender",
                title_encrypted=b"title",
                title_nonce=b"nonce1",
                body_encrypted=b"body",
                body_nonce=b"nonce2",
            )
        )

    db.session.commit()
    print("Database populated with demo content.")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--reset", action="store_true", help="drop and recreate the database before loading data")
    args = parser.parse_args()

    app = create_app()
    with app.app_context():
        build_sample_world(reset=args.reset)


if __name__ == "__main__":
    main()
