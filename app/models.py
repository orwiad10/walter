from .app import db
from flask_login import UserMixin
from datetime import datetime
from sqlalchemy import UniqueConstraint
import uuid
import os
import random
import hashlib
import json
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Permission groups and default role permissions
PERMISSION_GROUPS = {
    'tournaments': {
        'manage': 'Create and manage tournaments',
        'join': 'Join tournaments',
        'approve_join': 'Approve tournament join requests',
    },
    'users': {
        'manage': 'Manage users',
        'manage_admins': 'Manage admin level users',
    },
    'admin': {
        'panel': 'Access admin panel',
        'permissions': 'Manage roles and permissions',
    },
}


def all_permission_keys():
    keys = []
    for cat, perms in PERMISSION_GROUPS.items():
        for perm in perms:
            keys.append(f"{cat}.{perm}")
    return keys


DEFAULT_ROLE_PERMISSIONS = {
    'admin': {key: True for key in all_permission_keys()},
    'manager': {
        'tournaments.manage': True,
        'users.manage': True,
        'tournaments.approve_join': True,
    },
    'venue judge': {
        'tournaments.manage': True,
        'users.manage': True,
        'tournaments.approve_join': True,
    },
    'event head judge': {
        'tournaments.manage': True,
        'users.manage': True,
        'tournaments.approve_join': True,
    },
    'floor judge': {
        'users.manage': True,
        'tournaments.approve_join': True,
    },
    'user': {
        'tournaments.join': True,
    },
}


DEFAULT_ROLE_LEVELS = {
    'admin': 0,
    'manager': 100,
    'venue judge': 200,
    'event head judge': 300,
    'floor judge': 400,
    'user': 500,
}


class Role(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(50), unique=True, nullable=False)
    permissions = db.Column(db.Text, nullable=False, default='{}')
    level = db.Column(db.Integer, nullable=False, default=500)

    def permissions_dict(self):
        return json.loads(self.permissions or '{}')


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    # Email and password are optional to allow admin bulk registration without
    # requiring login credentials.
    email = db.Column(db.String(255), unique=True, nullable=True)
    name = db.Column(db.String(120), nullable=False)
    password_hash = db.Column(db.Text, nullable=True)
    salt = db.Column(db.String(32), nullable=True)
    is_admin = db.Column(db.Boolean, default=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    notes = db.Column(db.Text, nullable=True)
    role_id = db.Column(db.Integer, db.ForeignKey('role.id'))
    role = db.relationship('Role')
    break_end = db.Column(db.DateTime, nullable=True)
    public_key = db.Column(db.LargeBinary, nullable=True)
    private_key_encrypted = db.Column(db.LargeBinary, nullable=True)
    private_key_salt = db.Column(db.LargeBinary, nullable=True)
    private_key_nonce = db.Column(db.LargeBinary, nullable=True)
    permission_overrides = db.Column(db.Text, nullable=True)

    def set_password(self, pw):
        self.salt = os.urandom(16).hex()
        self.password_hash = hashlib.sha256((self.salt + pw).encode()).hexdigest()

    def check_password(self, pw):
        if not self.password_hash or not self.salt:
            return False
        return self.password_hash == hashlib.sha256((self.salt + pw).encode()).hexdigest()

    def generate_keys(self, password):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        public_pem = public_key.public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        private_pem = private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
        salt = os.urandom(16)
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=390000)
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        nonce = os.urandom(12)
        enc = aesgcm.encrypt(nonce, private_pem, None)
        self.public_key = public_pem
        self.private_key_encrypted = enc
        self.private_key_salt = salt
        self.private_key_nonce = nonce

    def decrypt_private_key(self, password):
        if not self.private_key_encrypted or not self.private_key_salt or not self.private_key_nonce:
            return None
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=self.private_key_salt,
            iterations=390000,
        )
        key = kdf.derive(password.encode())
        aesgcm = AESGCM(key)
        private_pem = aesgcm.decrypt(self.private_key_nonce, self.private_key_encrypted, None)
        return private_pem

    def permission_overrides_dict(self):
        try:
            return json.loads(self.permission_overrides or '{}')
        except Exception:
            return {}

    def has_permission(self, key):
        if self.is_admin:
            return True
        overrides = self.permission_overrides_dict()
        if key in overrides:
            return overrides.get(key) == 'allow'
        if not self.role:
            return False
        return self.role.permissions_dict().get(key, False)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sender_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    recipient_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    key_encrypted = db.Column(db.LargeBinary, nullable=False)
    sender_key_encrypted = db.Column(db.LargeBinary, nullable=True)
    title_encrypted = db.Column(db.LargeBinary, nullable=False)
    title_nonce = db.Column(db.LargeBinary, nullable=False)
    body_encrypted = db.Column(db.LargeBinary, nullable=False)
    body_nonce = db.Column(db.LargeBinary, nullable=False)
    sent_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)

    sender = db.relationship('User', foreign_keys=[sender_id])
    recipient = db.relationship('User', foreign_keys=[recipient_id])


class Report(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    reporter_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    reported_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    report_type = db.Column(db.String(20), nullable=False)
    description = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(20), default='open')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    is_read = db.Column(db.Boolean, default=False)
    assigned_to_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    actions_taken = db.Column(db.Text, nullable=True)

    reporter = db.relationship('User', foreign_keys=[reporter_id])
    reported_user = db.relationship('User', foreign_keys=[reported_user_id])
    assigned_to = db.relationship('User', foreign_keys=[assigned_to_id])


class Tournament(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(200), nullable=False)
    format = db.Column(db.String(50), nullable=False)  # Commander, Draft, Constructed
    structure = db.Column(db.String(20), default='swiss')  # swiss or single_elim
    cut = db.Column(db.String(10), default='none')     # none, top8, top4
    rules_enforcement_level = db.Column(db.String(20), default='None')
    is_cube = db.Column(db.Boolean, default=False)
    rounds_override = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    # Comma separated points for Commander: first, second, third, fourth, draw
    commander_points = db.Column(db.String(50), default='3,2,1,0,1')
    guid = db.Column(db.String(36), unique=True, default=lambda: str(uuid.uuid4()))
    round_length = db.Column(db.Integer, default=50)
    draft_time = db.Column(db.Integer, nullable=True)
    deck_build_time = db.Column(db.Integer, nullable=True)
    # Optional scheduled start time for tournament
    start_time = db.Column(db.DateTime, nullable=True)
    # Judge assignments
    head_judge_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    floor_judges = db.Column(db.Text, default='[]')  # store list of user ids as JSON
    round_timer_end = db.Column(db.DateTime, nullable=True)
    draft_timer_end = db.Column(db.DateTime, nullable=True)
    deck_timer_end = db.Column(db.DateTime, nullable=True)
    round_timer_remaining = db.Column(db.Integer, nullable=True)
    draft_timer_remaining = db.Column(db.Integer, nullable=True)
    deck_timer_remaining = db.Column(db.Integer, nullable=True)
    passcode = db.Column(db.String(4), nullable=False, default=lambda: f"{random.randint(0,9999):04d}")
    join_requires_approval = db.Column(db.Boolean, default=False)

    head_judge = db.relationship('User', foreign_keys=[head_judge_id])

    def floor_judge_ids(self):
        """Return list of user IDs assigned as floor judges."""
        try:
            return json.loads(self.floor_judges or '[]')
        except Exception:
            return []

class SiteLog(db.Model):
    __bind_key__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    action = db.Column(db.String(200), nullable=False)
    result = db.Column(db.String(200), nullable=False)
    error = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True)
    # relationship loaded manually to avoid cross-db foreign key

class TournamentLog(db.Model):
    __bind_key__ = 'logs'
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, nullable=False)
    action = db.Column(db.String(200), nullable=False)
    result = db.Column(db.String(200), nullable=False)
    error = db.Column(db.Text, nullable=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, nullable=True)
    # relationship loaded manually to avoid cross-db foreign key

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


class TournamentJoinRequest(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    tournament_id = db.Column(db.Integer, db.ForeignKey('tournament.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    status = db.Column(db.String(20), default='pending')
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    note = db.Column(db.Text, nullable=True)
    approved_by_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    tournament = db.relationship(
        'Tournament',
        backref=db.backref('join_requests', cascade='all, delete-orphan')
    )
    user = db.relationship('User', foreign_keys=[user_id])
    approved_by = db.relationship('User', foreign_keys=[approved_by_id])

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


class LostFoundItem(db.Model):
    __bind_key__ = 'media'
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text, nullable=True)
    status = db.Column(db.String(20), default='unclaimed')
    location = db.Column(db.String(200), nullable=True)
    image_path = db.Column(db.String(500), nullable=True)
    reporter_name = db.Column(db.String(120), nullable=True)
    reporter_contact = db.Column(db.String(200), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
