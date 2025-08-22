from .app import db, encrypt_password, verify_password
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import UniqueConstraint
import uuid

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    # Email and password are optional to allow admin bulk registration without
    # requiring login credentials.
    email = db.Column(db.String(255), unique=True, nullable=True)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.String(255), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)

    def set_password(self, pw):
        self.password_hash = encrypt_password(pw)

    def check_password(self, pw):
        if not self.password_hash:
            return False
        return verify_password(pw, self.password_hash)

class Tournament(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    format = db.Column(db.String(50), nullable=False)  # Commander, Draft, Constructed
    structure = db.Column(db.String(20), default='swiss')  # swiss or single_elim
    cut = db.Column(db.String(10), default='none')     # none, top8, top4
    rounds_override = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Comma separated points for Commander: first, second, third, fourth, draw
    commander_points = db.Column(db.String(50), default='3,2,1,0,1')
    guid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    round_length = db.Column(db.Integer, default=50)
    draft_time = db.Column(db.Integer, nullable=True)
    deck_build_time = db.Column(db.Integer, nullable=True)
    round_timer_end = db.Column(db.DateTime, nullable=True)
    draft_timer_end = db.Column(db.DateTime, nullable=True)
    deck_timer_end = db.Column(db.DateTime, nullable=True)
    round_timer_remaining = db.Column(db.Integer, nullable=True)
    draft_timer_remaining = db.Column(db.Integer, nullable=True)
    deck_timer_remaining = db.Column(db.Integer, nullable=True)

class TournamentPlayer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    # Cached totals for speed (recomputed in standings anyway)
    points = db.Column(db.Integer, default=0)  # 3 for win, 1 for draw, 0 for loss
    game_wins = db.Column(db.Integer, default=0)
    game_losses = db.Column(db.Integer, default=0)
    game_draws = db.Column(db.Integer, default=0)
    dropped = db.Column(db.Boolean, default=False)

    tournament = db.relationship(
        'Tournament',
        backref=db.backref('players', cascade='all, delete-orphan')
    )
    user = db.relationship(
        'User',
        backref=db.backref('tournament_entries', cascade='all, delete-orphan')
    )

    __table_args__ = (UniqueConstraint('tournament_id', 'user_id', name='_tournament_user_uc'),)

class Round(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=False)
    number = db.Column(db.Integer, nullable=False)

    tournament = db.relationship(
        'Tournament',
        backref=db.backref('rounds', cascade='all, delete-orphan')
    )

class MatchResult(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    player1_wins = db.Column(db.Integer, default=0)
    player2_wins = db.Column(db.Integer, default=0)
    draws = db.Column(db.Integer, default=0)
    # Commander placements; 1-4. If match is a draw, set is_draw True.
    p1_place = db.Column(db.Integer, nullable=True)
    p2_place = db.Column(db.Integer, nullable=True)
    p3_place = db.Column(db.Integer, nullable=True)
    p4_place = db.Column(db.Integer, nullable=True)
    is_draw = db.Column(db.Boolean, default=False)

class Match(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    round_id = db.Column(db.Integer, db.ForeignKey('round.id'), nullable=False)
    player1_id = db.Column(db.Integer, db.ForeignKey('tournament_player.id'), nullable=False)
    player2_id = db.Column(db.Integer, db.ForeignKey('tournament_player.id'), nullable=True)  # None means BYE
    # Commander pods can have up to four players
    player3_id = db.Column(db.Integer, db.ForeignKey('tournament_player.id'), nullable=True)
    player4_id = db.Column(db.Integer, db.ForeignKey('tournament_player.id'), nullable=True)
    table_number = db.Column(db.Integer, nullable=False)
    completed = db.Column(db.Boolean, default=False)
    result_id = db.Column(db.Integer, db.ForeignKey('match_result.id'), nullable=True)

    round = db.relationship(
        'Round',
        backref=db.backref('matches', cascade='all, delete-orphan')
    )
    player1 = db.relationship('TournamentPlayer', foreign_keys=[player1_id])
    player2 = db.relationship('TournamentPlayer', foreign_keys=[player2_id])
    player3 = db.relationship('TournamentPlayer', foreign_keys=[player3_id])
    player4 = db.relationship('TournamentPlayer', foreign_keys=[player4_id])
    result = db.relationship(
        'MatchResult',
        backref=db.backref('match', cascade='all, delete-orphan'),
        uselist=False
    )

    __table_args__ = (UniqueConstraint('round_id', 'table_number', name='_round_table_uc'),)
