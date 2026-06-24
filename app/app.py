from flask import (
    Flask,
    render_template,
    redirect,
    url_for,
    request,
    flash,
    abort,
    session,
    send_from_directory,
    send_file,
    Response,
    jsonify,
)
from flask_sqlalchemy import SQLAlchemy
from flask_login import (
    LoginManager,
    login_user,
    logout_user,
    login_required,
    current_user,
)
from datetime import datetime, timedelta, timezone
import math
import os
import random
import re
import click
import psutil
import json
import base64
import io
import glob
import secrets
import csv
import hashlib
import time
import urllib.parse
import urllib.request

import qrcode

from collections import OrderedDict
from urllib.parse import urlparse
from html.parser import HTMLParser
from sqlalchemy import inspect, text, or_
from sqlalchemy.exc import SQLAlchemyError
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hmac as crypto_hmac
from werkzeug.exceptions import HTTPException, MethodNotAllowed, NotFound
from werkzeug.routing import RequestRedirect
from werkzeug.utils import safe_join, secure_filename
from PIL import Image, ImageOps

from . import card_db


db = SQLAlchemy()
login_manager = LoginManager()
PASSWORD_KEY = None
PASSWORD_SEED = None
CURRENT_CONNECTIONS = OrderedDict()
CUBE_COBRA_IMAGE_MAX_BYTES = 2 * 1024 * 1024
CUBE_COBRA_FALLBACK_IMAGE_URL = 'https://assets.cubecobra.com/content/sticker.png'
CUBE_PREVIEW_IMAGE_HOSTS = {
    'cubecobra.com',
    'scryfall.io',
}

MAJOR_60_CARD_FORMATS = [
    'Standard',
    'Pioneer',
    'Modern',
    'Legacy',
    'Vintage',
    'Pauper',
]
BASE_TOURNAMENT_FORMATS = ['Commander', 'Draft']
TOURNAMENT_FORMATS = BASE_TOURNAMENT_FORMATS + MAJOR_60_CARD_FORMATS
MAILGUN_DOMAIN_PATTERN = re.compile(r'^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$')


class CubeCobraMetadataParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.meta = {}
        self.title = None
        self._in_title = False

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() == 'title':
            self._in_title = True
        if tag.lower() == 'meta':
            key = attrs.get('property') or attrs.get('name')
            content = attrs.get('content')
            if key and content:
                self.meta[key.lower()] = content.strip()

    def handle_endtag(self, tag):
        if tag.lower() == 'title':
            self._in_title = False

    def handle_data(self, data):
        if self._in_title:
            value = data.strip()
            if value:
                self.title = value


def normalize_cube_cobra_url(raw_url):
    url = (raw_url or '').strip()
    if not url:
        raise ValueError('Cube Cobra link is required.')
    if not re.match(r'^https?://', url, re.I):
        url = f'https://{url}'
    parsed = urllib.parse.urlparse(url)
    host = (parsed.netloc or '').lower()
    if host.startswith('www.'):
        host = host[4:]
    if host != 'cubecobra.com':
        raise ValueError('Only Cube Cobra links are supported.')
    if parsed.scheme not in {'http', 'https'}:
        raise ValueError('Cube Cobra link must use http or https.')
    return urllib.parse.urlunparse(('https', parsed.netloc, parsed.path, '', parsed.query, ''))


def clean_cube_cobra_title(raw_title):
    title = (raw_title or '').strip()
    previous = None
    while title and title != previous:
        previous = title
        title = re.sub(r'^\s*Cube Cobra(?:\s+List)?\s*:\s*', '', title, flags=re.I)
        title = re.sub(r'\s*[|\-]\s*Cube Cobra(?:\s+List)?\s*$', '', title, flags=re.I)
        title = title.strip()
    return title or 'Cube Cobra Cube'


def is_allowed_cube_preview_image_url(image_url):
    parsed = urllib.parse.urlparse(image_url)
    host = (parsed.hostname or '').lower()
    return parsed.scheme == 'https' and any(
        host == allowed_host or host.endswith(f'.{allowed_host}')
        for allowed_host in CUBE_PREVIEW_IMAGE_HOSTS
    )


def fetch_cube_cobra_metadata(raw_url):
    url = normalize_cube_cobra_url(raw_url)
    title = 'Cube Cobra Cube'
    image_url = None
    try:
        req = urllib.request.Request(
            url,
            headers={'User-Agent': 'WaLTER cube preview bot/1.0'},
        )
        with urllib.request.urlopen(req, timeout=8) as response:
            content_type = response.headers.get('Content-Type', '')
            if 'text/html' in content_type or not content_type:
                html = response.read(512000).decode('utf-8', errors='ignore')
                parser = CubeCobraMetadataParser()
                parser.feed(html)
                title = (
                    parser.meta.get('og:title')
                    or parser.meta.get('twitter:title')
                    or parser.title
                    or title
                ).strip()
                image_url = (
                    parser.meta.get('og:image')
                    or parser.meta.get('twitter:image')
                    or None
                )
    except Exception:
        title = title
    title = clean_cube_cobra_title(title)
    if image_url:
        image_url = urllib.parse.urljoin(url, image_url)
    return url, title[:250], image_url


def _mailgun_messages_url(domain):
    if not domain or not MAILGUN_DOMAIN_PATTERN.fullmatch(domain) or '..' in domain:
        raise RuntimeError('Mailgun domain must be a valid domain name.')
    url = f'https://api.mailgun.net/v3/{domain}/messages'
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != 'https' or parsed.netloc != 'api.mailgun.net':
        raise RuntimeError('Mailgun API URL must use https://api.mailgun.net/.')
    return url


def format_tournament_name(fmt, start_time, provided_name):
    clean_name = (provided_name or '').strip()
    timestamp = start_time or datetime.utcnow()
    return f"{fmt} - {timestamp.strftime('%Y%m%d')} - {timestamp.strftime('%H%M')} - {clean_name}"


def extract_provided_tournament_name(name):
    parts = (name or '').split(' - ', 3)
    if len(parts) == 4 and len(parts[1]) == 8 and len(parts[2]) == 4:
        return parts[3]
    return name or ''


def create_app():
    app = Flask(__name__)
    db_file = os.environ.get('MTG_DB_PATH', 'mtg_tournament.db')
    log_db_file = os.environ.get('MTG_LOG_DB_PATH', db_file.replace('.db', '_logs.db'))
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_file}'
    os.makedirs(app.instance_path, exist_ok=True)
    db_base = os.path.splitext(os.path.basename(db_file))[0]
    media_dir = os.path.join(app.instance_path, db_base)
    os.makedirs(media_dir, exist_ok=True)
    media_pattern = os.path.join(app.instance_path, f"{db_base}_media_*.db")
    existing_media = sorted(glob.glob(media_pattern))
    if existing_media:
        media_db_path = existing_media[-1]
    else:
        timestamp = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
        media_db_filename = f"{db_base}_media_{timestamp}.db"
        media_db_path = os.path.join(app.instance_path, media_db_filename)
    if not os.path.exists(media_db_path):
        open(media_db_path, 'a').close()
    app.config['SQLALCHEMY_BINDS'] = {
        'logs': f'sqlite:///{log_db_file}',
        'media': f'sqlite:///{media_db_path}',
    }
    app.config['MEDIA_STORAGE_DIR'] = media_dir
    app.config['MEDIA_DB_PATH'] = media_db_path
    card_db_path = os.environ.get('MTG_CARD_DB_PATH')
    if not card_db_path:
        card_db_path = os.path.join(app.instance_path, f"{db_base}_cards.db")
    app.config['CARD_DB_PATH'] = card_db_path
    app.config['CARD_DB_URL'] = os.environ.get('MTG_CARD_DB_URL', card_db.ATOMIC_CARDS_URL)
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret-change-me')
    app.config['MAILGUN_API_KEY'] = os.environ.get('MAILGUN_API_KEY', '')
    app.config['MAILGUN_DOMAIN'] = os.environ.get('MAILGUN_DOMAIN', '')
    app.config['MAILGUN_FROM_EMAIL'] = os.environ.get('MAILGUN_FROM_EMAIL', '')
    app.config['ACCOUNT_CREATION_INVITE_ONLY'] = os.environ.get('ACCOUNT_CREATION_INVITE_ONLY', '').strip().lower() in {'1', 'true', 'yes', 'on'}
    app.config['REGISTRATION_INVITE_TTL_DAYS'] = int(os.environ.get('REGISTRATION_INVITE_TTL_DAYS', '14') or '14')
    app.config['REGISTRATION_PIN_TTL_MINUTES'] = int(os.environ.get('REGISTRATION_PIN_TTL_MINUTES', '15'))
    app.config['ACCOUNT_LOCKOUT_ATTEMPTS'] = int(os.environ.get('ACCOUNT_LOCKOUT_ATTEMPTS', '3') or '3')
    app.config['IP_BLACKLIST_ATTEMPTS'] = int(os.environ.get('IP_BLACKLIST_ATTEMPTS', '10') or '10')
    app.config['PASSWORD_RESET_TTL_MINUTES'] = int(os.environ.get('PASSWORD_RESET_TTL_MINUTES', '60') or '60')

    last_table_env = os.environ.get('MTG_LAST_TABLE_NUMBER', '').strip()
    if last_table_env:
        try:
            app.config['LAST_TABLE_NUMBER'] = int(last_table_env)
        except ValueError:
            app.logger.warning('Invalid MTG_LAST_TABLE_NUMBER value %r; ignoring.', last_table_env)
            app.config['LAST_TABLE_NUMBER'] = None
    else:
        app.config['LAST_TABLE_NUMBER'] = None

    try:
        card_db.ensure_card_database(card_db_path, source_url=app.config['CARD_DB_URL'])
    except Exception as exc:  # pragma: no cover - startup fetch errors are logged
        app.logger.warning('Unable to prepare card database: %s', exc)

    seed_env = os.environ.get('PASSWORD_SEED')
    if seed_env is None:
        seed_bytes = os.urandom(32)
        seed_display = seed_bytes.hex()
    else:
        seed_bytes = seed_env.encode()
        seed_display = seed_env
    global PASSWORD_KEY, PASSWORD_SEED
    PASSWORD_KEY = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b'walter password seed key',
    ).derive(seed_bytes)
    PASSWORD_SEED = seed_display

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    # Automatically upgrade existing databases missing newer columns.
    # Older installations may not have the ``start_time`` column on the
    # ``tournament`` table which leads to ``OperationalError`` when the model
    # is loaded.  We inspect the current schema and add the column if it's
    # absent to keep backwards compatibility without requiring manual
    # migrations.
    with app.app_context():
        inspector = inspect(db.engine)
        if 'tournament' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('tournament')]
            if 'start_time' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN start_time DATETIME'))
                db.session.commit()
            if 'rules_enforcement_level' not in columns:
                db.session.execute(text("ALTER TABLE tournament ADD COLUMN rules_enforcement_level VARCHAR(20)"))
                db.session.execute(text("UPDATE tournament SET rules_enforcement_level='None' WHERE rules_enforcement_level IS NULL"))
                db.session.commit()
            if 'is_cube' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN is_cube BOOLEAN DEFAULT 0'))
                db.session.execute(text('UPDATE tournament SET is_cube=0 WHERE is_cube IS NULL'))
                db.session.commit()
            if 'join_requires_approval' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN join_requires_approval BOOLEAN DEFAULT 0'))
                db.session.execute(text('UPDATE tournament SET join_requires_approval=0 WHERE join_requires_approval IS NULL'))
                db.session.commit()
            if 'player_cap' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN player_cap INTEGER'))
                db.session.commit()
            if 'start_table_number' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN start_table_number INTEGER DEFAULT 1'))
                db.session.execute(text('UPDATE tournament SET start_table_number=1 WHERE start_table_number IS NULL'))
                db.session.commit()
            if 'pairing_type' not in columns:
                db.session.execute(
                    text("ALTER TABLE tournament ADD COLUMN pairing_type VARCHAR(20) DEFAULT 'swiss'")
                )
                db.session.execute(
                    text("UPDATE tournament SET pairing_type='swiss' WHERE pairing_type IS NULL")
                )
                db.session.commit()
            if 'pairing_options' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN pairing_options TEXT'))
                db.session.execute(
                    text("UPDATE tournament SET pairing_options='{}' WHERE pairing_options IS NULL")
                )
                db.session.commit()
            if 'league_id' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN league_id INTEGER'))
                db.session.commit()
            if 'venue_id' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN venue_id INTEGER'))
                db.session.commit()
            if 'started_at' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN started_at DATETIME'))
                db.session.commit()
            if 'ended_at' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN ended_at DATETIME'))
                db.session.commit()
            if 'manually_completed' not in columns:
                db.session.execute(text('ALTER TABLE tournament ADD COLUMN manually_completed BOOLEAN DEFAULT 0'))
                db.session.execute(text('UPDATE tournament SET manually_completed=0 WHERE manually_completed IS NULL'))
                db.session.commit()
        if 'user' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('user')]
            if 'break_end' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN break_end DATETIME'))
                db.session.commit()
            if 'permission_overrides' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN permission_overrides TEXT'))
                db.session.commit()
            if 'first_name' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN first_name VARCHAR(80)'))
                db.session.execute(text("UPDATE user SET first_name=trim(substr(name, 1, CASE WHEN instr(name, ' ') = 0 THEN length(name) ELSE instr(name, ' ') - 1 END)) WHERE first_name IS NULL"))
                db.session.commit()
            if 'last_name' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN last_name VARCHAR(80)'))
                db.session.execute(text("UPDATE user SET last_name=trim(CASE WHEN instr(name, ' ') = 0 THEN '' ELSE substr(name, instr(name, ' ') + 1) END) WHERE last_name IS NULL"))
                db.session.commit()
        if 'message' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('message')]
            if 'sender_key_encrypted' not in columns:
                db.session.execute(text('ALTER TABLE message ADD COLUMN sender_key_encrypted BLOB'))
                db.session.commit()
        if 'role' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('role')]
            if 'level' not in columns:
                db.session.execute(text('ALTER TABLE role ADD COLUMN level INTEGER DEFAULT 500'))
                db.session.execute(text('UPDATE role SET level=500 WHERE level IS NULL'))
                db.session.commit()
            from .models import DEFAULT_ROLE_LEVELS  # lazy import to avoid circular reference

            for role_name, level in DEFAULT_ROLE_LEVELS.items():
                db.session.execute(
                    text(
                        'UPDATE role SET level=:level WHERE name=:name AND (level IS NULL OR level != :level)'
                    ),
                    {'level': level, 'name': role_name},
                )
            db.session.commit()
            from .models import DEFAULT_ROLE_PERMISSIONS, Role  # lazy import to avoid circular reference
            for role_name, default_perms in DEFAULT_ROLE_PERMISSIONS.items():
                role = db.session.query(Role).filter_by(name=role_name).first()
                if role:
                    current_perms = role.permissions_dict()
                    changed = False
                    for key, allowed in default_perms.items():
                        if key not in current_perms:
                            current_perms[key] = allowed
                            changed = True
                    if changed:
                        role.permissions = json.dumps(current_perms)
            db.session.commit()
        from .models import (
            Report,
            TournamentJoinRequest,
            PendingRegistration,
            BadLoginAttempt,
            BlacklistedIP,
            PasswordResetToken,
            SiteSetting,
            RegistrationInvite,
            Venue,
            Vendor,
            ArtistProfile,
            ApiKey,
            ApiLog,
            SiteLog,
            TournamentLog,
        )  # lazy import to avoid circular reference

        if 'user' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('user')]
            if 'failed_login_count' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN failed_login_count INTEGER DEFAULT 0'))
                db.session.execute(text('UPDATE user SET failed_login_count=0 WHERE failed_login_count IS NULL'))
                db.session.commit()
            if 'locked_at' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN locked_at DATETIME'))
                db.session.commit()
            if 'lock_reason' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN lock_reason TEXT'))
                db.session.commit()
            if 'color_mode' not in columns:
                db.session.execute(text("ALTER TABLE user ADD COLUMN color_mode VARCHAR(10) DEFAULT 'light'"))
                db.session.execute(text("UPDATE user SET color_mode='light' WHERE color_mode IS NULL"))
                db.session.commit()
            if 'discord_username' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN discord_username VARCHAR(120)'))
                db.session.commit()
            if 'discord_user_id' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN discord_user_id VARCHAR(32)'))
                db.session.commit()
            if 'discord_authorization_token_hash' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN discord_authorization_token_hash VARCHAR(64)'))
                db.session.commit()

        BadLoginAttempt.__table__.create(bind=db.engine, checkfirst=True)
        inspector = inspect(db.engine)
        if 'bad_login_attempt' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('bad_login_attempt')]
            if 'email' not in columns:
                db.session.execute(text('ALTER TABLE bad_login_attempt ADD COLUMN email VARCHAR(255)'))
                db.session.commit()
            if 'user_id' not in columns:
                db.session.execute(text('ALTER TABLE bad_login_attempt ADD COLUMN user_id INTEGER'))
                db.session.commit()
            if 'ip_address' not in columns:
                db.session.execute(
                    text("ALTER TABLE bad_login_attempt ADD COLUMN ip_address VARCHAR(64) NOT NULL DEFAULT ''")
                )
                db.session.commit()
            if 'user_agent' not in columns:
                db.session.execute(text('ALTER TABLE bad_login_attempt ADD COLUMN user_agent TEXT'))
                db.session.commit()
            if 'result' not in columns:
                db.session.execute(
                    text("ALTER TABLE bad_login_attempt ADD COLUMN result VARCHAR(50) NOT NULL DEFAULT 'bad_password'")
                )
                db.session.commit()
            if 'created_at' not in columns:
                db.session.execute(text('ALTER TABLE bad_login_attempt ADD COLUMN created_at DATETIME'))
                db.session.execute(
                    text('UPDATE bad_login_attempt SET created_at=CURRENT_TIMESTAMP WHERE created_at IS NULL')
                )
                db.session.commit()

        BlacklistedIP.__table__.create(bind=db.engine, checkfirst=True)
        PasswordResetToken.__table__.create(bind=db.engine, checkfirst=True)
        SiteSetting.__table__.create(bind=db.engine, checkfirst=True)
        RegistrationInvite.__table__.create(bind=db.engine, checkfirst=True)
        Venue.__table__.create(bind=db.engine, checkfirst=True)
        Vendor.__table__.create(bind=db.engine, checkfirst=True)
        ArtistProfile.__table__.create(bind=db.engine, checkfirst=True)
        ApiKey.__table__.create(bind=db.engine, checkfirst=True)

        logs_engine = db.engines['logs']
        ApiLog.__table__.create(bind=logs_engine, checkfirst=True)
        SiteLog.__table__.create(bind=logs_engine, checkfirst=True)
        logs_inspector = inspect(logs_engine)
        if 'site_log' in logs_inspector.get_table_names():
            log_columns = [c['name'] for c in logs_inspector.get_columns('site_log')]
            if 'ip_address' not in log_columns:
                with logs_engine.begin() as conn:
                    conn.execute(text('ALTER TABLE site_log ADD COLUMN ip_address VARCHAR(64)'))
        TournamentLog.__table__.create(bind=logs_engine, checkfirst=True)
        logs_inspector = inspect(logs_engine)
        log_tables = logs_inspector.get_table_names()
        if 'site_log' in log_tables:
            columns = [c['name'] for c in logs_inspector.get_columns('site_log')]
            if 'user_id' not in columns:
                with logs_engine.begin() as conn:
                    conn.execute(text('ALTER TABLE site_log ADD COLUMN user_id INTEGER'))
        if 'tournament_log' in log_tables:
            columns = [c['name'] for c in logs_inspector.get_columns('tournament_log')]
            if 'user_id' not in columns:
                with logs_engine.begin() as conn:
                    conn.execute(text('ALTER TABLE tournament_log ADD COLUMN user_id INTEGER'))

        if 'report' not in inspector.get_table_names():
            Report.__table__.create(bind=db.engine)
        else:
            columns = [c['name'] for c in inspector.get_columns('report')]
            if 'is_read' not in columns:
                db.session.execute(text('ALTER TABLE report ADD COLUMN is_read BOOLEAN DEFAULT 0'))
                db.session.execute(text('UPDATE report SET is_read=0 WHERE is_read IS NULL'))
                db.session.commit()
            if 'assigned_to_id' not in columns:
                db.session.execute(text('ALTER TABLE report ADD COLUMN assigned_to_id INTEGER'))
                db.session.commit()
            if 'actions_taken' not in columns:
                db.session.execute(text('ALTER TABLE report ADD COLUMN actions_taken TEXT'))
                db.session.commit()
        TournamentJoinRequest.__table__.create(bind=db.engine, checkfirst=True)
        PendingRegistration.__table__.create(bind=db.engine, checkfirst=True)
        from .models import (
            LostFoundItem, TournamentPlayerDeck, League, LeaguePlayer, LeagueResult,
            LeagueCube, LeaguePlayDate, LeaguePlayDateCube, LeagueCubeVote,
            LeagueCubeDiscordPoll,
        )

        League.__table__.create(bind=db.engine, checkfirst=True)
        LeaguePlayer.__table__.create(bind=db.engine, checkfirst=True)
        LeagueResult.__table__.create(bind=db.engine, checkfirst=True)
        if 'league' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('league')]
            if 'is_cube_league' not in columns:
                db.session.execute(text('ALTER TABLE league ADD COLUMN is_cube_league BOOLEAN DEFAULT 0'))
                db.session.execute(text('UPDATE league SET is_cube_league=0 WHERE is_cube_league IS NULL'))
                db.session.commit()
        LeagueCube.__table__.create(bind=db.engine, checkfirst=True)
        LeaguePlayDate.__table__.create(bind=db.engine, checkfirst=True)
        LeaguePlayDateCube.__table__.create(bind=db.engine, checkfirst=True)
        LeagueCubeVote.__table__.create(bind=db.engine, checkfirst=True)
        LeagueCubeDiscordPoll.__table__.create(bind=db.engine, checkfirst=True)

        media_engine = db.engines['media']
        LostFoundItem.__table__.create(bind=media_engine, checkfirst=True)
        media_inspector = inspect(media_engine)
        if 'lost_found_item' in media_inspector.get_table_names():
            columns = [c['name'] for c in media_inspector.get_columns('lost_found_item')]
            if 'venue_id' not in columns:
                with media_engine.begin() as conn:
                    conn.execute(text('ALTER TABLE lost_found_item ADD COLUMN venue_id INTEGER'))
        if 'pending_registration' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('pending_registration')]
            if 'verification_token_hash' not in columns:
                db.session.execute(text('ALTER TABLE pending_registration ADD COLUMN verification_token_hash VARCHAR(64)'))
                db.session.commit()
            if 'invite_id' not in columns:
                db.session.execute(text('ALTER TABLE pending_registration ADD COLUMN invite_id INTEGER'))
                db.session.commit()
        if 'tournament_player_deck' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('tournament_player_deck')]
            if 'is_submitted' not in columns:
                db.session.execute(text('ALTER TABLE tournament_player_deck ADD COLUMN is_submitted BOOLEAN DEFAULT 0'))
                db.session.execute(text('UPDATE tournament_player_deck SET is_submitted=0 WHERE is_submitted IS NULL'))
                db.session.commit()
            if 'submitted_at' not in columns:
                db.session.execute(text('ALTER TABLE tournament_player_deck ADD COLUMN submitted_at DATETIME'))
                db.session.commit()
        TournamentPlayerDeck.__table__.create(bind=db.engine, checkfirst=True)

    from .models import (
        User,
        Tournament,
        TournamentPlayer,
        Round,
        Match,
        MatchResult,
        Role,
        PERMISSION_GROUPS,
        DEFAULT_ROLE_PERMISSIONS,
        DEFAULT_ROLE_LEVELS,
        SiteLog,
        ApiLog,
        TournamentLog,
        Message,
        Report,
        TournamentJoinRequest,
        PendingRegistration,
        LostFoundItem,
        League,
        LeaguePlayer,
        LeagueResult,
        LeagueCube,
        LeaguePlayDate,
        LeaguePlayDateCube,
        LeagueCubeVote,
        LeagueCubeDiscordPoll,
        BadLoginAttempt,
        BlacklistedIP,
        PasswordResetToken,
        SiteSetting,
        RegistrationInvite,
        Venue,
        Vendor,
        ArtistProfile,
        ApiKey,
        all_permission_keys,
        utc_now,
    )
    from .pairing import pair_round, recommended_rounds, compute_standings, player_points, draft_seating_tables, seeded_cut_pairs

    TYPE_SORT_ORDER = [
        'Creature',
        'Planeswalker',
        'Battle',
        'Instant',
        'Sorcery',
        'Artifact',
        'Enchantment',
        'Land',
        'Tribal',
    ]
    TYPE_SORT_INDEX = {name: idx for idx, name in enumerate(TYPE_SORT_ORDER)}

    def _tournament_group_size(tournament):
        # Table reservations are based on physical two-seat tables.
        return 2

    def _active_player_count(tournament):
        return sum(1 for p in getattr(tournament, 'players', []) if not getattr(p, 'dropped', False))

    def compute_table_allocation(tournament, start_number=None):
        start = start_number if start_number is not None else (tournament.start_table_number or 1)
        actual_player_count = _active_player_count(tournament)
        player_count = getattr(tournament, 'player_cap', None) or actual_player_count
        group_size = _tournament_group_size(tournament)
        tables_needed = math.ceil(player_count / group_size) if player_count else 0
        end = start + tables_needed - 1 if tables_needed else start - 1
        return start, end, tables_needed, player_count

    def _format_table_range(start, end, tables_needed):
        if tables_needed <= 0:
            return str(start)
        if start == end:
            return str(start)
        return f"{start}-{end}"

    def find_available_table_start(tournament):
        _, _, tables_needed, _ = compute_table_allocation(tournament)
        last_table = app.config.get('LAST_TABLE_NUMBER') or None
        if tables_needed <= 1:
            max_start = last_table or 1
        elif last_table is not None:
            max_start = last_table - tables_needed + 1
            if max_start < 1:
                return 1
        else:
            max_existing_end = 0
            query = db.session.query(Tournament)
            if getattr(tournament, 'id', None):
                query = query.filter(Tournament.id != tournament.id)
            for other in query.all():
                _, other_end, other_tables, _ = compute_table_allocation(other)
                if other_tables:
                    max_existing_end = max(max_existing_end, other_end)
            max_start = max(max_existing_end + 1, 1)
        for candidate in range(1, max_start + 1):
            errors, _, _, _, _ = validate_table_assignment(tournament, start_number=candidate)
            if not errors:
                return candidate
        return max_start

    def table_reservations(exclude_tournament_id=None):
        reservations = []
        query = db.session.query(Tournament)
        if exclude_tournament_id:
            query = query.filter(Tournament.id != exclude_tournament_id)
        for other in query.all():
            start, end, tables, _ = compute_table_allocation(other)
            if tables:
                reservations.append({'start': start, 'end': end, 'name': other.name})
        return reservations

    def tournament_has_capacity(tournament, slots=1):
        cap = getattr(tournament, 'player_cap', None)
        if not cap:
            return True
        return len(getattr(tournament, 'players', []) or []) + slots <= cap

    def validate_table_assignment(tournament, start_number=None):
        errors = []
        start, end, tables_needed, player_count = compute_table_allocation(tournament, start_number=start_number)
        last_table = app.config.get('LAST_TABLE_NUMBER') or None
        if start < 1:
            errors.append('Starting table number must be at least 1.')
        if last_table is not None:
            if start > last_table:
                errors.append(f'Starting table number must be at most {last_table}.')
            if tables_needed and end > last_table:
                errors.append(
                    f'Tournament requires tables up to {end}, exceeding the venue limit of {last_table}.'
                )
        if tables_needed:
            query = db.session.query(Tournament)
            if getattr(tournament, 'id', None):
                query = query.filter(Tournament.id != tournament.id)
            for other in query.all():
                other_start, other_end, other_tables, _ = compute_table_allocation(other)
                if other_tables == 0:
                    continue
                if not (end < other_start or start > other_end):
                    errors.append(
                        f'Table range {_format_table_range(start, end, tables_needed)} overlaps with '
                        f'tournament "{other.name}" '
                        f'({_format_table_range(other_start, other_end, other_tables)}).'
                    )
                    break
        return errors, start, end, tables_needed, player_count


    def tournament_is_complete(tournament):
        players = list(getattr(tournament, 'players', []) or [])
        rounds = sorted(list(getattr(tournament, 'rounds', []) or []), key=lambda r: r.number)
        if getattr(tournament, 'ended_at', None) or getattr(tournament, 'manually_completed', False):
            return True
        if not rounds:
            return False
        round_limit = tournament.rounds_override or recommended_rounds(len(players))
        if tournament.structure == 'single_elim':
            round_limit = 0
        relevant_rounds = [r for r in rounds if r.number <= round_limit]
        if len(relevant_rounds) < round_limit:
            return False
        if any(not (m.completed and m.result) for r in relevant_rounds for m in r.matches):
            return False
        if tournament.cut and tournament.cut.startswith('top'):
            elim_rounds = [r for r in rounds if r.number > round_limit]
            if not elim_rounds:
                return False
            final_round = elim_rounds[-1]
            return bool(final_round.matches) and all(m.completed and m.result for m in final_round.matches)
        return True

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ---------- CLI ----------
    @app.cli.command('db-init')
    def db_init():
        db.create_all()
        db.create_all(bind_key='media')
        # Ensure default roles
        for name, perms in DEFAULT_ROLE_PERMISSIONS.items():
            level = DEFAULT_ROLE_LEVELS.get(name, 500)
            existing = db.session.query(Role).filter_by(name=name).first()
            if not existing:
                r = Role(name=name, permissions=json.dumps(perms), level=level)
                db.session.add(r)
            else:
                current_perms = existing.permissions_dict()
                changed = False
                for key, allowed in perms.items():
                    if key not in current_perms:
                        current_perms[key] = allowed
                        changed = True
                if changed:
                    existing.permissions = json.dumps(current_perms)
                if existing.level != level:
                    existing.level = level
        db.session.commit()
        # Ensure a default admin account exists for first-time login
        if not db.session.query(User).filter_by(
            email="admin@example.com"
        ).first():
            admin_role = db.session.query(Role).filter_by(name='admin').first()
            u = User(email="admin@example.com", name="Admin", role=admin_role, is_admin=True)
            u.set_password("admin123")
            u.generate_keys("admin123")
            db.session.add(u)
            db.session.commit()
            print("Created default admin: admin@example.com / admin123")
        print("Database initialized.")

    @app.cli.command('create-admin')
    @click.option('--email', help='Email for the admin user')
    @click.option('--password', help='Password for the admin user')
    def create_admin(email, password):
        if not email:
            email = click.prompt("Admin email", default="admin@example.com")
        if not password:
            password = click.prompt("Password", hide_input=True, confirmation_prompt=True)
        if db.session.query(User).filter_by(email=email).first():
            print("User exists")
            return
        admin_role = db.session.query(Role).filter_by(name='admin').first()
        u = User(email=email, name="Admin", role=admin_role, is_admin=True)
        u.set_password(password)
        u.generate_keys(password)
        db.session.add(u)
        db.session.commit()
        print("Admin created.")

    # ---------- Routes ----------
    @app.route('/')
    def index():
        if not current_user.is_authenticated:
            return render_template(
                'index.html',
                tournaments=[],
                player_counts={},
                server_now=datetime.utcnow(),
            )

        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        visible_tournaments = [t for t in tournaments if not tournament_is_complete(t)]
        player_counts = {t.id: len(t.players) for t in visible_tournaments}
        return render_template('index.html', tournaments=visible_tournaments, player_counts=player_counts,
                               server_now=datetime.utcnow())


    @app.route('/home')
    @login_required
    def login_home():
        active_count = db.session.query(Tournament).filter(Tournament.ended_at.is_(None)).count()
        my_tournament_count = db.session.query(TournamentPlayer).filter_by(user_id=current_user.id).count()
        my_league_count = db.session.query(LeaguePlayer).filter_by(user_id=current_user.id).count()
        return render_template(
            'home.html',
            active_count=active_count,
            my_tournament_count=my_tournament_count,
            my_league_count=my_league_count,
        )

    @app.route('/admin/tournaments/ended')
    @login_required
    def ended_tournaments():
        require_permission('tournaments.manage')
        tournaments = (
            db.session.query(Tournament)
            .filter(Tournament.ended_at.isnot(None))
            .order_by(Tournament.ended_at.desc(), Tournament.created_at.desc())
            .all()
        )
        player_counts = {t.id: len(t.players) for t in tournaments}
        return render_template('admin/ended_tournaments.html', tournaments=tournaments, player_counts=player_counts)

    def _send_mailgun_email(to_email, subject, text):
        api_key = app.config.get('MAILGUN_API_KEY')
        domain = app.config.get('MAILGUN_DOMAIN')
        from_email = app.config.get('MAILGUN_FROM_EMAIL') or (f"Walter <mailgun@{domain}>" if domain else '')
        if not api_key or not domain or not from_email:
            raise RuntimeError('Mailgun is not configured. Set mailgun_api_key, mailgun_domain, and mailgun_from_email in config.yaml.')
        data = urllib.parse.urlencode({
            'from': from_email,
            'to': to_email,
            'subject': subject,
            'text': text,
        }).encode()
        request_obj = urllib.request.Request(
            _mailgun_messages_url(domain),
            data=data,
            headers={
                'Authorization': 'Basic ' + base64.b64encode(f'api:{api_key}'.encode()).decode(),
                'Content-Type': 'application/x-www-form-urlencoded',
            },
            method='POST',
        )
        # _mailgun_messages_url pins the destination to https://api.mailgun.net/.
        with urllib.request.urlopen(request_obj, timeout=10) as response:  # nosec B310
            if response.status >= 400:
                raise RuntimeError(f'Mailgun returned HTTP {response.status}')

    def _send_registration_pin(email, pin):
        _send_mailgun_email(
            email,
            'Your Walter verification PIN',
            f'Use this one-time PIN to verify your Walter account: {pin}\n\nThis PIN expires in {app.config.get("REGISTRATION_PIN_TTL_MINUTES", 15)} minutes.',
        )

    def _client_ip():
        cf_connecting_ip = request.headers.get('CF-Connecting-IP', '')
        if cf_connecting_ip:
            return cf_connecting_ip.split(',')[0].strip()
        real_ip = request.headers.get('X-Real-IP', '')
        if real_ip:
            return real_ip.split(',')[0].strip()
        forwarded = request.headers.get('X-Forwarded-For', '')
        if forwarded:
            return forwarded.split(',')[0].strip()
        return request.remote_addr or 'unknown'

    def _browser_fingerprint():
        user_agent = request.headers.get('User-Agent', '')
        accept_language = request.headers.get('Accept-Language', '')
        raw = f'{user_agent}|{accept_language}'
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def _split_name(name):
        parts = (name or '').strip().split(None, 1)
        return (parts[0] if parts else '', parts[1] if len(parts) > 1 else '')

    def _set_user_name_parts(user, first_name=None, last_name=None, fallback_name=None):
        first = (first_name or '').strip()
        last = (last_name or '').strip()
        if not first and not last and fallback_name:
            first, last = _split_name(fallback_name)
        user.first_name = first or None
        user.last_name = last or None
        user.name = ' '.join(part for part in [first, last] if part).strip() or (fallback_name or '').strip()

    def _hash_reset_token(token):
        key_material = app.config['SECRET_KEY'].encode()
        hmac_ctx = crypto_hmac.HMAC(key_material, hashes.SHA256())
        hmac_ctx.update(token.encode())
        return hmac_ctx.finalize().hex()

    def _hash_registration_token(token):
        key_material = app.config['SECRET_KEY'].encode()
        hmac_ctx = crypto_hmac.HMAC(key_material, hashes.SHA256())
        hmac_ctx.update(('registration:' + token).encode())
        return hmac_ctx.finalize().hex()

    def get_site_setting(key, default=None):
        setting = db.session.get(SiteSetting, key)
        return setting.value if setting else default

    def set_site_setting(key, value):
        setting = db.session.get(SiteSetting, key)
        if not setting:
            setting = SiteSetting(key=key)
            db.session.add(setting)
        setting.value = value
        setting.updated_by_id = current_user.id if current_user.is_authenticated else None
        return setting

    def registration_mode():
        mode = get_site_setting('registration_mode')
        if mode in {'open', 'invite_only', 'closed'}:
            return mode
        return 'invite_only' if app.config.get('ACCOUNT_CREATION_INVITE_ONLY', False) else 'open'

    def site_theme():
        if current_user.is_authenticated:
            theme = getattr(current_user, 'color_mode', None)
            if theme in {'light', 'dark'}:
                return theme
        theme = get_site_setting('site_theme', 'light')
        if theme in {'light', 'dark'}:
            return theme
        return 'light'

    def _send_registration_verification(email, token, pin=None):
        verify_url = url_for('verify_registration_token', token=token, _external=True)
        pin_text = f'\n\nIf prompted, your fallback PIN is: {pin}' if pin else ''
        _send_mailgun_email(
            email,
            'Verify your Walter account',
            (
                'Click this link to verify your Walter account:\n\n'
                f'{verify_url}\n\n'
                f'This link expires in {app.config.get("REGISTRATION_PIN_TTL_MINUTES", 15)} minutes.'
                f'{pin_text}'
            ),
        )

    def _send_registration_invite(invite, token):
        invite_url = url_for('register', invite=token, _external=True)
        _send_mailgun_email(
            invite.email,
            'Your Walter registration invite',
            (
                'An administrator invited you to create a Walter account. Use this link to register:\n\n'
                f'{invite_url}\n\n'
                f'This invite expires on {invite.expires_at}.'
            ),
        )

    def _valid_registration_invite(token, email=None):
        if not token:
            return None
        invite = db.session.query(RegistrationInvite).filter_by(token_hash=_hash_registration_token(token)).first()
        now = datetime.utcnow()
        if not invite or invite.used_at or invite.status != 'sent':
            return None
        if invite.expires_at and invite.expires_at < now:
            invite.status = 'expired'
            db.session.commit()
            return None
        if email and invite.email.lower() != email.lower():
            return None
        return invite

    def _send_password_reset_email(user, token):
        reset_url = url_for('password_reset_token', token=token, _external=True)
        _send_mailgun_email(
            user.email,
            'Reset your Walter password',
            (
                'A password reset was requested for your Walter account. '
                f'Use this link within {app.config.get("PASSWORD_RESET_TTL_MINUTES", 60)} minutes:\n\n'
                f'{reset_url}\n\nIf you did not request this reset, ignore this email.'
            ),
        )

    def _create_password_reset_token(user):
        token = secrets.token_urlsafe(32)
        reset = PasswordResetToken(
            user=user,
            token_hash=_hash_reset_token(token),
            expires_at=datetime.utcnow() + timedelta(minutes=app.config.get('PASSWORD_RESET_TTL_MINUTES', 60)),
        )
        db.session.add(reset)
        db.session.commit()
        return token

    def _record_bad_login(email, user, result):
        ip_address = _client_ip()
        user_agent = request.headers.get('User-Agent', '')
        user_id = user.id if user else None
        failed_count_before = user.failed_login_count if user else None
        locked_before = bool(user and user.locked_at)
        site_log_events = []
        app.logger.info(
            'Bad login audit start: email=%r user_id=%s result=%s ip=%s failed_count_before=%s locked_before=%s user_agent=%r',
            email,
            user_id,
            result,
            ip_address,
            failed_count_before,
            locked_before,
            user_agent,
        )
        attempt = BadLoginAttempt(
            email=email or None,
            user_id=user_id,
            ip_address=ip_address,
            user_agent=user_agent,
            result=result,
        )
        db.session.add(attempt)
        if user and result == 'bad_password':
            user.failed_login_count = (user.failed_login_count or 0) + 1
            lockout_attempts = max(app.config.get('ACCOUNT_LOCKOUT_ATTEMPTS', 3), 1)
            is_admin_account = bool(user.is_admin or (user.role and user.role.name == 'admin'))
            app.logger.info(
                'Bad password count updated: user_id=%s email=%r failed_count=%s lockout_attempts=%s locked_at=%s is_admin_account=%s',
                user.id,
                user.email,
                user.failed_login_count,
                lockout_attempts,
                user.locked_at,
                is_admin_account,
            )
            if user.failed_login_count >= lockout_attempts and not user.locked_at:
                if is_admin_account:
                    app.logger.warning(
                        'Admin account lock threshold reached; blacklisting IP instead: user_id=%s email=%r ip=%s failed_count=%s',
                        user.id,
                        user.email,
                        ip_address,
                        user.failed_login_count,
                    )
                    site_log_events.append(
                        ('admin_ip_blacklist', 'success', f'user_id={user.id}; ip={ip_address}; attempts={user.failed_login_count}')
                    )
                else:
                    user.locked_at = datetime.now(timezone.utc).replace(tzinfo=None)
                    user.lock_reason = f'{user.failed_login_count} incorrect password attempts'
                    app.logger.warning(
                        'Account lock threshold reached: user_id=%s email=%r ip=%s failed_count=%s lock_reason=%r',
                        user.id,
                        user.email,
                        ip_address,
                        user.failed_login_count,
                        user.lock_reason,
                    )
                    site_log_events.append(
                        ('account_lock', 'success', f'user_id={user.id}; ip={ip_address}; attempts={user.failed_login_count}')
                    )
        db.session.commit()
        app.logger.info(
            'Bad login audit persisted: attempt_id=%s email=%r user_id=%s result=%s ip=%s',
            attempt.id,
            email,
            user_id,
            result,
            ip_address,
        )
        ip_attempts = db.session.query(BadLoginAttempt).filter_by(ip_address=ip_address).count()
        threshold = max(app.config.get('IP_BLACKLIST_ATTEMPTS', 10), 1)
        app.logger.info(
            'Bad login IP threshold check: ip=%s attempts=%s threshold=%s latest_result=%s',
            ip_address,
            ip_attempts,
            threshold,
            result,
        )
        admin_lockout_reached = bool(
            user
            and result == 'bad_password'
            and (user.is_admin or (user.role and user.role.name == 'admin'))
            and (user.failed_login_count or 0) >= max(app.config.get('ACCOUNT_LOCKOUT_ATTEMPTS', 3), 1)
        )
        if ip_attempts >= threshold or admin_lockout_reached:
            existing = db.session.query(BlacklistedIP).filter_by(ip_address=ip_address).first()
            if not existing:
                existing = BlacklistedIP(ip_address=ip_address)
                db.session.add(existing)
                app.logger.info('Creating IP blacklist entry after bad logins: ip=%s attempts=%s', ip_address, ip_attempts)
            if not existing.is_active:
                existing.is_active = True
                app.logger.info('Reactivating IP blacklist entry after bad logins: ip=%s attempts=%s', ip_address, ip_attempts)
            existing.reason = (
                f'Admin account bad login threshold reached ({user.failed_login_count} attempts)'
                if admin_lockout_reached
                else f'{ip_attempts} bad login attempts'
            )
            db.session.commit()
            app.logger.warning('IP address %s blacklisted after %s bad login attempts', ip_address, ip_attempts)
            site_log_events.append(('ip_blacklist', 'success', f'ip={ip_address}; attempts={ip_attempts}'))
        for action, event_result, error in site_log_events:
            _safe_log_site(action, event_result, error)

    @app.route('/register', methods=['GET','POST'])
    def register():
        from .models import User, Tournament, PendingRegistration
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        prefill_tournament_id = request.args.get('tournament_id', '').strip()
        prefill_passcode = request.args.get('passcode', '').strip()
        invite_token = request.values.get('invite', '').strip()
        invite = _valid_registration_invite(invite_token)
        mode = registration_mode()
        if request.method == 'GET' and mode == 'closed' and not invite:
            flash('Registration is currently closed. Contact an administrator for access.', 'error')
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            name = request.form.get('name', '').strip() or ' '.join(part for part in [first_name, last_name] if part).strip()
            password = request.form['password']
            confirm = request.form.get('password_confirm', '')
            tournament_id = request.form.get('tournament_id')
            tournament_passcode = request.form.get('passcode', '').strip()
            invite_token = request.form.get('invite', '').strip()
            invite = _valid_registration_invite(invite_token, email=email)
            if password != confirm:
                flash("Passwords do not match", "error")
                log_site('register', 'failure', 'password mismatch')
                return redirect(url_for('register', invite=invite_token) if invite_token else url_for('register'))
            if db.session.query(User).filter_by(email=email).first():
                flash("Email already registered", "error")
                log_site('register', 'failure', 'email exists')
                return redirect(url_for('register', invite=invite_token) if invite_token else url_for('register'))
            mode = registration_mode()
            if mode == 'closed' and not invite:
                flash('Registration is currently closed.', 'error')
                log_site('register', 'failure', 'registration closed')
                return redirect(url_for('register'))
            selected_tournament = None
            if tournament_id:
                try:
                    selected_tournament = db.session.get(Tournament, int(tournament_id))
                except (TypeError, ValueError):
                    selected_tournament = None
                if not selected_tournament:
                    flash("Selected tournament was not found", "error")
                    log_site('register', 'failure', 'invalid tournament selection')
                    return redirect(url_for('register', invite=invite_token) if invite_token else url_for('register'))
            if mode == 'invite_only' and not invite and not selected_tournament:
                flash('Account creation is invite only. Use the invite link sent by an administrator.', 'error')
                log_site('register', 'failure', 'invite required')
                return redirect(url_for('register'))

            db.session.query(PendingRegistration).filter(PendingRegistration.expires_at < datetime.utcnow()).delete()
            existing_pending = db.session.query(PendingRegistration).filter_by(email=email).first()
            if existing_pending:
                db.session.delete(existing_pending)
                db.session.flush()
            pin = PendingRegistration.generate_pin()
            verification_token = secrets.token_urlsafe(32)
            pending = PendingRegistration(
                email=email,
                name=name,
                verification_pin=pin,
                verification_token_hash=_hash_registration_token(verification_token),
                invite_id=invite.id if invite else None,
                tournament_id=selected_tournament.id if selected_tournament else None,
                tournament_passcode=None,
                expires_at=datetime.utcnow() + timedelta(minutes=app.config.get('REGISTRATION_PIN_TTL_MINUTES', 15)),
            )
            pending.set_password(password)
            db.session.add(pending)
            try:
                _send_registration_verification(email, verification_token, pin)
            except Exception as exc:
                db.session.rollback()
                app.logger.warning('Unable to send registration verification via Mailgun: %s', exc)
                flash("We could not send your verification email. Please contact an administrator.", "error")
                log_site('register', 'failure', 'mailgun send failed')
                return redirect(url_for('register', invite=invite_token) if invite_token else url_for('register'))
            db.session.commit()
            log_site('register', 'verification_sent', f'invite_id={invite.id if invite else ""}')
            flash("Check your email and click the verification link to finish creating your account.", "success")
            return redirect(url_for('verify_registration', email=email, next=request.args.get('next')))
        return render_template(
            'register.html',
            tournaments=tournaments,
            prefill_tournament_id=prefill_tournament_id,
            prefill_passcode=prefill_passcode,
            invite_only=(mode == 'invite_only'),
            registration_mode=mode,
            invite=invite,
            invite_token=invite_token,
        )

    def _complete_pending_registration(pending, password=None):
        from .models import User, Tournament, TournamentPlayer, Role
        if db.session.query(User).filter_by(email=pending.email).first():
            db.session.delete(pending)
            db.session.commit()
            flash("Email already registered. Please login.", "error")
            log_site('register_verify', 'failure', 'email exists')
            return redirect(url_for('login'))
        selected_tournament = None
        if pending.tournament_id:
            selected_tournament = db.session.get(Tournament, pending.tournament_id)
            if not selected_tournament:
                db.session.delete(pending)
                db.session.commit()
                flash("Tournament invite expired or is no longer valid. Please register again.", "error")
                log_site('register_verify', 'failure', 'invalid pending tournament')
                return redirect(url_for('register'))
        role_user = db.session.query(Role).filter_by(name='user').first()
        u = User(email=pending.email, name=pending.name, role=role_user)
        _set_user_name_parts(u, fallback_name=pending.name)
        stored_password = password or ''
        u.password_hash = pending.password_hash
        u.salt = pending.salt
        if stored_password:
            u.generate_keys(stored_password)
        db.session.add(u)
        db.session.flush()
        if selected_tournament:
            db.session.add(TournamentPlayer(tournament_id=selected_tournament.id, user_id=u.id))
        if pending.invite:
            pending.invite.used_at = datetime.utcnow()
            pending.invite.used_by_id = u.id
            pending.invite.status = 'used'
        db.session.delete(pending)
        db.session.commit()
        log_site('register_verify', 'success', f'user_id={u.id}')
        flash("Email verified and account created. Please login.", "success")
        return redirect(url_for('login'))

    @app.route('/register/verify', methods=['GET', 'POST'])
    def verify_registration():
        from .models import PendingRegistration
        email = (request.values.get('email') or '').strip().lower()
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            pin = request.form.get('pin', '').strip()
            password = request.form.get('password', '')
            pending = db.session.query(PendingRegistration).filter_by(email=email).first()
            if not pending or pending.expires_at < datetime.utcnow():
                if pending:
                    db.session.delete(pending)
                    db.session.commit()
                flash("Verification link expired or was not found. Please register again.", "error")
                log_site('register_verify', 'failure', 'missing or expired')
                return redirect(url_for('register'))
            if pending.verification_pin != pin or not pending.check_password(password):
                flash("Invalid PIN or password.", "error")
                log_site('register_verify', 'failure', 'invalid pin or password')
                return redirect(url_for('verify_registration', email=email))
            return _complete_pending_registration(pending, password=password)
        return render_template('verify_registration.html', email=email)

    @app.route('/register/verify/<token>')
    def verify_registration_token(token):
        from .models import PendingRegistration
        pending = db.session.query(PendingRegistration).filter_by(verification_token_hash=_hash_registration_token(token)).first()
        if not pending or pending.expires_at < datetime.utcnow():
            if pending:
                db.session.delete(pending)
                db.session.commit()
            flash('Verification link expired or was not found. Please register again.', 'error')
            log_site('register_verify', 'failure', 'invalid token')
            return redirect(url_for('register'))
        return _complete_pending_registration(pending)

    @app.route('/login', methods=['GET','POST'])
    def login():
        next_url = request.args.get('next')
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            password = request.form['password']
            from .models import User
            u = db.session.query(User).filter_by(email=email).first()
            if u and u.locked_at:
                flash("Account locked. Use password reset or contact an administrator.", "error")
                try:
                    _record_bad_login(email, u, 'account_locked')
                except Exception:
                    db.session.rollback()
                    app.logger.exception(
                        'Bad login audit failed for already-locked account: email=%r user_id=%s ip=%s',
                        email,
                        u.id,
                        _client_ip(),
                    )
                _safe_log_site('login', 'failure', 'account locked')
                return render_template('login.html')
            if u and u.check_password(password):
                u.failed_login_count = 0
                u.lock_reason = None
                db.session.commit()
                login_user(u)
                try:
                    priv_pem = u.decrypt_private_key(password)
                    if priv_pem:
                        session['private_key'] = base64.b64encode(priv_pem).decode()
                except Exception:
                    session['private_key'] = None
                log_site('login', 'success', f'ip={_client_ip()}')
                post_login_url = allowed_post_login_redirect(next_url)
                if post_login_url:
                    return redirect(post_login_url)
                if next_url:
                    return redirect(url_for('index'))
                return redirect(url_for('login_home'))
            bad_login_result = 'bad_password' if u else 'unknown_user'
            try:
                _record_bad_login(email, u, bad_login_result)
            except Exception:
                db.session.rollback()
                app.logger.exception(
                    'Bad login audit failed: email=%r user_id=%s result=%s ip=%s',
                    email,
                    u.id if u else None,
                    bad_login_result,
                    _client_ip(),
                )
            flash("Invalid credentials", "error")
            _safe_log_site('login', 'failure', f'invalid credentials; ip={_client_ip()}')
        return render_template('login.html')

    @app.route('/password-reset', methods=['GET', 'POST'])
    def password_reset_request():
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            user = db.session.query(User).filter_by(email=email).first() if email else None
            if user and user.email:
                try:
                    token = _create_password_reset_token(user)
                    _send_password_reset_email(user, token)
                    log_site('password_reset_request', 'success', f'user_id={user.id}; ip={_client_ip()}')
                except Exception as exc:
                    db.session.rollback()
                    log_site('password_reset_request', 'failure', str(exc))
                    flash('Password reset email could not be sent. Contact an administrator.', 'error')
                    return redirect(url_for('password_reset_request'))
            else:
                log_site('password_reset_request', 'failure', f'unknown email; ip={_client_ip()}')
            flash('If the email exists, a reset link has been sent.', 'success')
            return redirect(url_for('login'))
        return render_template('password_reset_request.html')

    @app.route('/password-reset/<token>', methods=['GET', 'POST'])
    def password_reset_token(token):
        token_hash = _hash_reset_token(token)
        reset = db.session.query(PasswordResetToken).filter_by(token_hash=token_hash).first()
        valid = reset and not reset.used_at and reset.expires_at and reset.expires_at >= datetime.utcnow()
        if not valid:
            log_site('password_reset', 'failure', f'invalid or expired token; ip={_client_ip()}')
            flash('Password reset link is invalid or expired.', 'error')
            return redirect(url_for('password_reset_request'))
        if request.method == 'POST':
            password = request.form.get('password', '')
            password_confirm = request.form.get('password_confirm', '')
            if password != password_confirm:
                flash('Passwords do not match.', 'error')
                return render_template('password_reset_form.html', token=token)
            reset.user.set_password(password)
            reset.user.generate_keys(password)
            reset.used_at = datetime.utcnow()
            db.session.commit()
            log_site('password_reset', 'success', f'user_id={reset.user_id}; ip={_client_ip()}')
            flash('Password reset successfully. Please login.', 'success')
            return redirect(url_for('login'))
        return render_template('password_reset_form.html', token=token)

    @app.route('/t/<int:tid>/join-link')
    def tournament_join_link(tid):
        from .models import Tournament, TournamentPlayer
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        join_url = url_for('tournament_join_link', tid=tid, _external=True)
        qr_url = url_for('tournament_join_qr', tid=tid)
        is_player = False
        if current_user.is_authenticated:
            is_player = (
                db.session.query(TournamentPlayer)
                .filter_by(tournament_id=tid, user_id=current_user.id)
                .first()
                is not None
            )
        return render_template('tournament/join_link.html', t=t, join_url=join_url, qr_url=qr_url, is_player=is_player)

    @app.route('/t/<int:tid>/join-qr.png')
    def tournament_join_qr(tid):
        from .models import Tournament
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        join_url = url_for('tournament_join_link', tid=tid, _external=True)
        qr = qrcode.QRCode(
            version=None,
            error_correction=qrcode.constants.ERROR_CORRECT_M,
            box_size=10,
            border=4,
        )
        qr.add_data(join_url)
        qr.make(fit=True)
        img = qr.make_image(fill_color='black', back_color='white')
        buf = io.BytesIO()
        img.save(buf, format='PNG')
        buf.seek(0)
        return send_file(buf, mimetype='image/png', max_age=3600)

    @app.route('/logout')
    @login_required
    def logout():
        session.pop('private_key', None)
        logout_user()
        log_site('logout', 'success')
        return redirect(url_for('index'))

    def create_encrypted_message(sender, recipient, title, body):
        if not recipient or not recipient.public_key:
            return None
        if not sender or not sender.public_key:
            return None
        try:
            recipient_key = serialization.load_pem_public_key(recipient.public_key)
            sender_key = serialization.load_pem_public_key(sender.public_key)
        except Exception:
            return None
        aes_key = os.urandom(32)
        aesgcm = AESGCM(aes_key)
        nonce_title = os.urandom(12)
        nonce_body = os.urandom(12)
        try:
            title_enc = aesgcm.encrypt(nonce_title, title.encode(), None)
            body_enc = aesgcm.encrypt(nonce_body, body.encode(), None)
        except Exception:
            return None
        try:
            key_enc = recipient_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            sender_key_enc = sender_key.encrypt(
                aes_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
        except Exception:
            return None
        return Message(
            sender_id=sender.id,
            recipient_id=recipient.id,
            key_encrypted=key_enc,
            sender_key_encrypted=sender_key_enc,
            title_encrypted=title_enc,
            title_nonce=nonce_title,
            body_encrypted=body_enc,
            body_nonce=nonce_body,
        )

    def load_private_key_from_session():
        priv_b64 = session.get('private_key')
        if not priv_b64:
            return None
        try:
            return serialization.load_pem_private_key(base64.b64decode(priv_b64), password=None)
        except Exception:
            return None

    def decrypt_message_for_user(message, private_key, *, for_sender=False):
        if not private_key:
            return None
        encrypted_key = message.sender_key_encrypted if for_sender else message.key_encrypted
        if not encrypted_key:
            return None
        try:
            aes_key = private_key.decrypt(
                encrypted_key,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )
            aesgcm = AESGCM(aes_key)
            title = aesgcm.decrypt(message.title_nonce, message.title_encrypted, None).decode()
            body = aesgcm.decrypt(message.body_nonce, message.body_encrypted, None).decode()
        except Exception:
            return None
        return {
            'id': message.id,
            'title': title,
            'body': body,
            'sender': message.sender,
            'recipient': message.recipient,
            'sent_at': message.sent_at,
        }

    @app.route('/messages')
    @login_required
    def messages_home():
        judge_access = current_user.has_permission('tournaments.manage')
        admin_access = current_user.has_permission('admin.panel')
        return render_template('messages/index.html', judge_access=judge_access, admin_access=admin_access)

    @app.route('/messages/player')
    @app.route('/messages/inbox')
    @login_required
    def messages_inbox():
        from .models import Message
        private_key = load_private_key_from_session()
        msgs = []
        if not private_key:
            flash('Cannot decrypt messages', 'error')
        else:
            msgs_db = (
                db.session.query(Message)
                .filter_by(recipient_id=current_user.id)
                .order_by(Message.sent_at.desc())
                .all()
            )
            updated = False
            for m in msgs_db:
                payload = decrypt_message_for_user(m, private_key)
                if not payload:
                    continue
                was_read = m.is_read
                if not was_read:
                    m.is_read = True
                    updated = True
                payload['is_read'] = True
                payload['was_unread'] = not was_read
                msgs.append(payload)
            if updated:
                db.session.commit()
        return render_template('messages/player.html', messages=msgs)

    @app.route('/messages/sent')
    @login_required
    def messages_sent():
        from .models import Message

        private_key = load_private_key_from_session()
        msgs_db = (
            db.session.query(Message)
            .filter_by(sender_id=current_user.id)
            .order_by(Message.sent_at.desc())
            .all()
        )
        messages = []
        if not private_key:
            flash('Cannot decrypt sent messages', 'error')
        for m in msgs_db:
            payload = (
                decrypt_message_for_user(m, private_key, for_sender=True)
                if private_key
                else None
            )
            title = payload['title'] if payload else 'Encrypted message'
            body = payload['body'] if payload else ''
            messages.append(
                {
                    'id': m.id,
                    'recipient': m.recipient,
                    'sent_at': m.sent_at,
                    'title': title,
                    'body': body,
                    'can_view': payload is not None,
                }
            )
        return render_template('messages/sent.html', messages=messages)

    @app.route('/messages/player/send', methods=['GET', 'POST'])
    @app.route('/messages/send', methods=['GET', 'POST'])
    @login_required
    def send_message():
        from .models import User
        if request.method == 'POST':
            recipient_id_raw = request.form.get('recipient_id', '').strip()
            to_email = (request.form.get('to') or '').strip().lower()
            title = request.form['title'].strip()
            body = request.form['body'].strip()
            if not title or not body:
                flash('Title and message are required.', 'error')
                return redirect(url_for('send_message'))
            recipient = None
            if recipient_id_raw:
                try:
                    recipient = db.session.get(User, int(recipient_id_raw))
                except (TypeError, ValueError):
                    recipient = None
            if not recipient and to_email:
                recipient = db.session.query(User).filter_by(email=to_email).first()
            msg = create_encrypted_message(current_user, recipient, title, body)
            if not msg:
                flash('Recipient not found or cannot receive messages', 'error')
                return redirect(url_for('send_message'))
            db.session.add(msg)
            db.session.commit()
            flash('Message sent', 'success')
            return redirect(url_for('messages_inbox'))
        return render_template('messages/player_send.html')

    @app.route('/messages/view/<int:mid>')
    @login_required
    def view_message(mid):
        from .models import Message

        msg = db.session.get(Message, mid)
        if not msg:
            abort(404)
        if msg.recipient_id != current_user.id and msg.sender_id != current_user.id:
            abort(403)
        is_sender = msg.sender_id == current_user.id
        private_key = load_private_key_from_session()
        payload = None
        if private_key:
            payload = decrypt_message_for_user(msg, private_key, for_sender=is_sender)
        other_user = msg.sender if msg.recipient_id == current_user.id else msg.recipient
        if msg.recipient_id == current_user.id and not msg.is_read:
            msg.is_read = True
            db.session.commit()
        reply_subject = ''
        can_reply = False
        if payload:
            subject = payload['title']
            reply_subject = subject if subject.lower().startswith('re:') else f"Re: {subject}"
            can_reply = other_user is not None
        else:
            flash('Unable to decrypt this message.', 'error')
        return render_template(
            'messages/view.html',
            message=msg,
            payload=payload,
            is_sender=is_sender,
            can_reply=can_reply,
            reply_subject=reply_subject,
            other_user=other_user,
        )

    @app.route('/messages/<int:mid>/reply', methods=['POST'])
    @login_required
    def reply_message(mid):
        from .models import Message

        msg = db.session.get(Message, mid)
        if not msg:
            abort(404)
        if msg.recipient_id != current_user.id and msg.sender_id != current_user.id:
            abort(403)
        target_user = msg.sender if msg.recipient_id == current_user.id else msg.recipient
        if not target_user:
            flash('Cannot find the other participant for this message.', 'error')
            return redirect(url_for('view_message', mid=mid))
        title = request.form.get('title', '').strip()
        body = request.form.get('body', '').strip()
        if not title or not body:
            flash('Title and message are required.', 'error')
            return redirect(url_for('view_message', mid=mid))
        reply = create_encrypted_message(current_user, target_user, title, body)
        if not reply:
            flash('Unable to send reply.', 'error')
            return redirect(url_for('view_message', mid=mid))
        db.session.add(reply)
        db.session.commit()
        flash('Reply sent.', 'success')
        return redirect(url_for('view_message', mid=mid))

    @app.route('/messages/judge', methods=['GET', 'POST'])
    @login_required
    def messages_judge():
        require_permission('tournaments.manage')
        tournaments = db.session.query(Tournament).order_by(Tournament.name).all()
        if request.method == 'POST':
            tournament_id = request.form.get('tournament_id')
            title = request.form['title'].strip()
            body = request.form['body'].strip()
            if not tournament_id:
                flash('Select a tournament.', 'error')
                return redirect(url_for('messages_judge'))
            tournament = db.session.get(Tournament, int(tournament_id))
            if not tournament:
                flash('Tournament not found.', 'error')
                return redirect(url_for('messages_judge'))
            if not title or not body:
                flash('Title and message are required.', 'error')
                return redirect(url_for('messages_judge'))
            delivered = 0
            skipped = []
            for tp in tournament.players:
                recipient = tp.user
                msg = create_encrypted_message(current_user, recipient, title, body)
                if msg:
                    db.session.add(msg)
                    delivered += 1
                elif recipient:
                    skipped.append(recipient.name)
            if delivered:
                db.session.commit()
                log_site('group_message', 'success', f'tournament:{tournament.id} recipients:{delivered}')
                if skipped:
                    flash(f'Message sent to {delivered} recipients; {len(skipped)} could not receive.', 'warning')
                else:
                    flash(f'Message sent to {delivered} recipients.', 'success')
            else:
                flash('No recipients were able to receive this message.', 'error')
            return redirect(url_for('messages_judge'))
        return render_template('messages/judge.html', tournaments=tournaments)

    @app.route('/messages/admin', methods=['GET', 'POST'])
    @login_required
    def messages_admin():
        require_admin()
        roles = db.session.query(Role).order_by(Role.name).all()
        if request.method == 'POST':
            target = request.form.get('role_id')
            title = request.form['title'].strip()
            body = request.form['body'].strip()
            recipients = []
            target_label = ''
            if not title or not body:
                flash('Title and message are required.', 'error')
                return redirect(url_for('messages_admin'))
            if target == 'all':
                recipients = db.session.query(User).all()
                target_label = 'all users'
            else:
                role = db.session.get(Role, int(target)) if target else None
                if not role:
                    flash('Select a recipient group.', 'error')
                    return redirect(url_for('messages_admin'))
                recipients = db.session.query(User).filter(User.role_id == role.id).all()
                target_label = role.name
            delivered = 0
            skipped = []
            for recipient in recipients:
                msg = create_encrypted_message(current_user, recipient, title, body)
                if msg:
                    db.session.add(msg)
                    delivered += 1
                elif recipient:
                    skipped.append(recipient.name)
            if delivered:
                db.session.commit()
                log_site('group_message_admin', 'success', f'{target_label}:{delivered}')
                if skipped:
                    flash(f'Message sent to {delivered} recipients; {len(skipped)} could not receive.', 'warning')
                else:
                    flash(f'Message sent to {delivered} recipients.', 'success')
            else:
                flash('No recipients were able to receive this message.', 'error')
            return redirect(url_for('messages_admin'))
        return render_template('messages/admin.html', roles=roles)

    @app.route('/api/users/search')
    @login_required
    def api_user_search():
        term = (request.args.get('q') or '').strip()
        results = []
        if term:
            pattern = f"%{term}%"
            users = (
                db.session.query(User)
                .filter(or_(User.name.ilike(pattern), User.email.ilike(pattern)))
                .order_by(User.name)
                .limit(10)
                .all()
            )
            for user in users:
                results.append({
                    'id': user.id,
                    'name': user.name,
                    'email': user.email or '',
                })
        return {'results': results}

    @app.route('/api/messages/unread')
    @login_required
    def api_unread_messages():
        count = (
            db.session.query(Message)
            .filter_by(recipient_id=current_user.id, is_read=False)
            .count()
        )
        return {'count': count}

    def _json_error(message, status=400):
        response = jsonify({'error': message})
        response.status_code = status
        return response

    def _api_log(action, result, error=None):
        _safe_log_site(f'api.{action}', result, error)

    def _is_api_logging_request():
        return request.path.startswith('/api/') or request.path.rstrip('/') == '/connect'

    def _redacted_api_headers():
        headers = {}
        sensitive = {'authorization', 'cookie', 'set-cookie', 'x-api-key'}
        for key, value in request.headers.items():
            headers[key] = '[redacted]' if key.lower() in sensitive else value
        return headers

    def _decode_body(data):
        if not data:
            return ''
        text_value = data.decode('utf-8', errors='replace')
        max_len = 20000
        if len(text_value) > max_len:
            return text_value[:max_len] + f'… [truncated {len(text_value) - max_len} chars]'
        return text_value

    def _safe_api_log_entry(response=None, error=None):
        if not getattr(request, '_walter_api_log_enabled', False):
            return
        try:
            response_body = ''
            status_code = getattr(response, 'status_code', None)
            if response is not None and not response.direct_passthrough:
                response_body = _decode_body(response.get_data())
            duration_ms = int((time.monotonic() - getattr(request, '_walter_api_started_at', time.monotonic())) * 1000)
            user = None
            api_key = None
            try:
                user, api_key = _api_current_user()
            except Exception:
                db.session.rollback()
            entry = ApiLog(
                method=request.method,
                path=request.path,
                query_string=request.query_string.decode('utf-8', errors='replace'),
                status_code=status_code,
                request_headers=json.dumps(_redacted_api_headers(), sort_keys=True),
                request_body=_decode_body(getattr(request, '_walter_api_request_body', b'')),
                response_body=response_body,
                error=str(error) if error else None,
                duration_ms=duration_ms,
                api_key_id=api_key.id if api_key else None,
                api_user_id=user.id if user else None,
                ip_address=_client_ip(),
                user_agent=request.headers.get('User-Agent', ''),
            )
            db.session.add(entry)
            db.session.commit()
        except Exception:
            db.session.rollback()
            app.logger.exception('Unable to write API log entry for %s %s', request.method, request.path)

    @app.before_request
    def capture_api_log_request():
        if not _is_api_logging_request():
            return
        request._walter_api_log_enabled = True
        request._walter_api_started_at = time.monotonic()
        request._walter_api_request_body = request.get_data(cache=True)

    @app.after_request
    def capture_api_log_response(response):
        _safe_api_log_entry(response=response)
        return response

    @app.teardown_request
    def capture_api_log_exception(exc):
        if exc is not None:
            _safe_api_log_entry(error=exc)

    def _api_current_user():
        auth = request.headers.get('Authorization', '')
        token = ''
        if auth.lower().startswith('bearer '):
            token = auth.split(None, 1)[1].strip()
        token = token or request.headers.get('X-API-Key', '').strip()
        if not token:
            return None, None
        api_key = db.session.query(ApiKey).filter_by(key_hash=ApiKey.hash_token(token), revoked_at=None).first()
        if not api_key or not api_key.user:
            return None, None
        api_key.last_used_at = utc_now()
        db.session.commit()
        return api_key.user, api_key

    def require_api_permission(perm):
        user, api_key = _api_current_user()
        if not user:
            _api_log('auth', 'failure', 'missing or invalid api key')
            abort(401)
        if not user.has_permission(perm):
            _api_log('auth', 'failure', perm)
            abort(403)
        return user, api_key

    def user_payload(user):
        return {'id': user.id, 'name': user.name, 'email': user.email or '', 'role': user.role.name if user.role else None, 'is_admin': bool(user.is_admin)}

    def _normalize_discord_username(value):
        return (value or '').strip().lstrip('@')

    def tournament_payload(t):
        return {'id': t.id, 'name': t.name, 'format': t.format, 'structure': t.structure, 'start_time': t.start_time.isoformat() if t.start_time else None, 'league_id': t.league_id, 'venue_id': t.venue_id}

    def league_payload(league):
        return {'id': league.id, 'name': league.name, 'start_date': league.start_date.isoformat() if league.start_date else None, 'end_date': league.end_date.isoformat() if league.end_date else None, 'is_cube_league': bool(league.is_cube_league)}

    def standings_payload(t):
        standings = compute_standings(t, db.session)
        rows = []
        for index, row in enumerate(standings, start=1):
            tp = row['tp']
            rows.append({
                'rank': index,
                'tournament_player_id': tp.id,
                'user_id': tp.user_id,
                'name': tp.user.name if tp.user else 'Unknown',
                'points': row.get('points', 0),
                'omw': row.get('omw', 0),
                'gw': row.get('gw', 0),
                'ogw': row.get('ogw', 0),
                'dropped': bool(tp.dropped),
            })
        return rows

    def league_standings_payload(league):
        league_players = db.session.query(LeaguePlayer).filter_by(league_id=league.id).all()
        results = db.session.query(LeagueResult).filter_by(league_id=league.id).all()
        results_by_player = {}
        for result in results:
            results_by_player.setdefault(result.user_id, []).append(result)

        rows = []
        for league_player in league_players:
            player_results = sorted(
                results_by_player.get(league_player.user_id, []),
                key=lambda result: (result.points or 0, result.wins or 0, -(result.losses or 0)),
                reverse=True,
            )
            played = len(player_results)
            counted_count = math.ceil(played * 0.75) if played else 0
            counted = player_results[:counted_count]
            rows.append({
                'user_id': league_player.user_id,
                'name': league_player.user.name if league_player.user else 'Unknown',
                'played': played,
                'counted_count': counted_count,
                'league_points': sum(result.points or 0 for result in counted),
                'raw_points': sum(result.points or 0 for result in player_results),
                'wins': sum(result.wins or 0 for result in counted),
                'draws': sum(result.draws or 0 for result in counted),
                'losses': sum(result.losses or 0 for result in counted),
            })
        rows.sort(key=lambda row: (-row['league_points'], -row['wins'], row['losses'], row['name'].lower()))
        for index, row in enumerate(rows, start=1):
            row['rank'] = index
        return rows

    def match_payload(match):
        players = []
        for player in (match.player1, match.player2, match.player3, match.player4):
            if not player:
                continue
            players.append({
                'tournament_player_id': player.id,
                'user_id': player.user_id,
                'name': player.user.name if player.user else 'Unknown',
                'dropped': bool(player.dropped),
            })
        return {
            'id': match.id,
            'table_number': match.table_number,
            'players': players,
            'is_bye': match.player2_id is None,
            'completed': bool(match.completed),
        }

    def round_payload(round_obj):
        matches = sorted(round_obj.matches, key=lambda match: match.table_number)
        return {
            'id': round_obj.id,
            'number': round_obj.number,
            'matches': [match_payload(match) for match in matches],
        }

    @app.route('/settings', methods=['GET', 'POST'])
    @login_required
    def user_settings():
        new_api_key = None
        new_discord_pass = None
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'appearance':
                color_mode = request.form.get('color_mode', 'light')
                if color_mode not in {'light', 'dark'}:
                    color_mode = 'light'
                current_user.color_mode = color_mode
                db.session.commit()
                flash('Settings saved.', 'success')
                return redirect(url_for('user_settings'))
            if action == 'discord_connection':
                discord_username = _normalize_discord_username(request.form.get('discord_username'))
                if len(discord_username) > 120:
                    discord_username = discord_username[:120]
                current_user.discord_username = discord_username or None
                if request.form.get('generate_discord_pass') == '1':
                    new_discord_pass = secrets.token_urlsafe(8)
                    current_user.set_discord_authorization_token(new_discord_pass)
                    current_user.discord_user_id = None
                    flash('Discord connection pass generated. Use it with /connect in Discord.', 'success')
                else:
                    flash('Discord settings saved.', 'success')
                db.session.commit()
                log_site('discord_settings_update', 'success', f'user_id={current_user.id}')
            if action == 'api_key':
                if not current_user.has_permission('admin.api_keys'):
                    log_site('api_key_create', 'failure', 'missing admin.api_keys')
                    abort(403)
                name = (request.form.get('name') or 'API key').strip()[:120]
                token = ApiKey.create_token()
                db.session.add(ApiKey.from_token(token, current_user, name, created_by=current_user))
                db.session.commit()
                log_site('api_key_create', 'success', f'api_key_name={name}')
                new_api_key = token
        keys = db.session.query(ApiKey).filter_by(user_id=current_user.id).order_by(ApiKey.created_at.desc()).all()
        return render_template(
            'user_settings.html',
            api_keys=keys,
            new_api_key=new_api_key,
            new_discord_pass=new_discord_pass,
            selected_color_mode=site_theme(),
        )

    @app.route('/settings/api-keys/<int:key_id>/revoke', methods=['POST'])
    @login_required
    def revoke_api_key(key_id):
        key = db.session.get(ApiKey, key_id)
        if not key or key.user_id != current_user.id:
            abort(404)
        key.revoked_at = utc_now()
        db.session.commit()
        log_site('api_key_revoke', 'success', f'api_key_id={key.id}')
        flash('API key revoked.', 'success')
        return redirect(url_for('user_settings'))

    @app.route('/api/v1/users', methods=['GET', 'POST'])
    def api_users():
        api_user, _ = require_api_permission('users.manage')
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            name = (data.get('name') or '').strip()
            email = (data.get('email') or '').strip().lower() or None
            if not name:
                return _json_error('name is required')
            user = User(name=name, email=email)
            if data.get('password'):
                user.set_password(data['password'])
            db.session.add(user)
            db.session.commit()
            _api_log('users.create', 'success', f'user_id={user.id}; api_user_id={api_user.id}')
            return jsonify(user_payload(user)), 201
        users = db.session.query(User).order_by(User.name).all()
        _api_log('users.list', 'success')
        return jsonify({'users': [user_payload(u) for u in users]})

    @app.route('/api/v1/tournaments', methods=['GET', 'POST'])
    def api_tournaments():
        api_user, _ = require_api_permission('tournaments.manage')
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            name = (data.get('name') or '').strip()
            fmt = (data.get('format') or 'Commander').strip()
            if not name:
                return _json_error('name is required')
            tournament = Tournament(name=name, format=fmt, structure=data.get('structure') or 'swiss')
            db.session.add(tournament)
            db.session.commit()
            _api_log('tournaments.create', 'success', f'tournament_id={tournament.id}; api_user_id={api_user.id}')
            return jsonify(tournament_payload(tournament)), 201
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        _api_log('tournaments.list', 'success')
        return jsonify({'tournaments': [tournament_payload(t) for t in tournaments]})

    @app.route('/api/v1/leagues', methods=['GET', 'POST'])
    def api_leagues():
        api_user, _ = require_api_permission('tournaments.manage')
        if request.method == 'POST':
            data = request.get_json(silent=True) or {}
            name = (data.get('name') or '').strip()
            if not name:
                return _json_error('name is required')
            league = League(name=name, is_cube_league=bool(data.get('is_cube_league')))
            db.session.add(league)
            db.session.commit()
            _api_log('leagues.create', 'success', f'league_id={league.id}; api_user_id={api_user.id}')
            return jsonify(league_payload(league)), 201
        leagues = db.session.query(League).order_by(League.name).all()
        _api_log('leagues.list', 'success')
        return jsonify({'leagues': [league_payload(l) for l in leagues]})

    @app.route('/api/v1/users/<int:user_id>', methods=['GET', 'PATCH', 'DELETE'])
    def api_user_detail(user_id):
        api_user, _ = require_api_permission('users.manage')
        user = db.session.get(User, user_id)
        if not user:
            return _json_error('not found', 404)
        if request.method == 'PATCH':
            data = request.get_json(silent=True) or {}
            if 'name' in data:
                user.name = (data.get('name') or user.name).strip()
            if 'email' in data:
                user.email = (data.get('email') or '').strip().lower() or None
            if data.get('password'):
                user.set_password(data['password'])
            db.session.commit()
            _api_log('users.update', 'success', f'user_id={user.id}; api_user_id={api_user.id}')
        elif request.method == 'DELETE':
            deleted_id = user.id
            db.session.delete(user)
            db.session.commit()
            _api_log('users.delete', 'success', f'user_id={deleted_id}; api_user_id={api_user.id}')
            return jsonify({'deleted': True})
        else:
            _api_log('users.get', 'success', f'user_id={user.id}')
        return jsonify(user_payload(user))

    @app.route('/api/v1/tournaments/<int:tournament_id>', methods=['GET', 'PATCH', 'DELETE'])
    def api_tournament_detail(tournament_id):
        api_user, _ = require_api_permission('tournaments.manage')
        tournament = db.session.get(Tournament, tournament_id)
        if not tournament:
            return _json_error('not found', 404)
        if request.method == 'PATCH':
            data = request.get_json(silent=True) or {}
            for field in ('name', 'format', 'structure'):
                if field in data and data[field]:
                    setattr(tournament, field, str(data[field]).strip())
            db.session.commit()
            _api_log('tournaments.update', 'success', f'tournament_id={tournament.id}; api_user_id={api_user.id}')
        elif request.method == 'DELETE':
            deleted_id = tournament.id
            db.session.delete(tournament)
            db.session.commit()
            _api_log('tournaments.delete', 'success', f'tournament_id={deleted_id}; api_user_id={api_user.id}')
            return jsonify({'deleted': True})
        else:
            _api_log('tournaments.get', 'success', f'tournament_id={tournament.id}')
        return jsonify(tournament_payload(tournament))

    @app.route('/api/v1/tournaments/<int:tournament_id>/standings')
    def api_tournament_standings(tournament_id):
        require_api_permission('tournaments.manage')
        tournament = db.session.get(Tournament, tournament_id)
        if not tournament:
            return _json_error('not found', 404)
        _api_log('tournaments.standings', 'success', f'tournament_id={tournament.id}')
        return jsonify({
            'tournament': tournament_payload(tournament),
            'standings': standings_payload(tournament),
        })

    @app.route('/api/v1/tournaments/<int:tournament_id>/rounds')
    def api_tournament_rounds(tournament_id):
        require_api_permission('tournaments.manage')
        tournament = db.session.get(Tournament, tournament_id)
        if not tournament:
            return _json_error('not found', 404)
        rounds = (
            db.session.query(Round)
            .filter_by(tournament_id=tournament.id)
            .order_by(Round.number)
            .all()
        )
        _api_log('tournaments.rounds', 'success', f'tournament_id={tournament.id}')
        return jsonify({
            'tournament': tournament_payload(tournament),
            'rounds': [round_payload(round_obj) for round_obj in rounds],
        })

    @app.route('/api/v1/tournaments/<int:tournament_id>/rounds/latest')
    def api_tournament_latest_round(tournament_id):
        require_api_permission('tournaments.manage')
        tournament = db.session.get(Tournament, tournament_id)
        if not tournament:
            return _json_error('not found', 404)
        round_obj = (
            db.session.query(Round)
            .filter_by(tournament_id=tournament.id)
            .order_by(Round.number.desc())
            .first()
        )
        if not round_obj:
            return _json_error('not found', 404)
        _api_log('tournaments.rounds.latest', 'success', f'tournament_id={tournament.id}; round={round_obj.number}')
        return jsonify({
            'tournament': tournament_payload(tournament),
            'round': round_payload(round_obj),
        })

    @app.route('/connect', methods=['GET', 'POST'], strict_slashes=False)
    @app.route('/api/v1/discord/authorize', methods=['POST'], strict_slashes=False)
    def api_discord_authorize():
        require_api_permission('tournaments.manage')
        data = request.get_json(silent=True) or request.values.to_dict()
        discord_user_id = str(data.get('discord_user_id') or '').strip()
        discord_username = _normalize_discord_username(data.get('discord_username'))
        one_time_pass = str(data.get('one_time_pass') or '').strip()
        discord_display_name = _normalize_discord_username(data.get('discord_display_name'))
        discord_global_name = _normalize_discord_username(data.get('discord_global_name'))

        def _discord_authorize_log_details(**extra):
            details = {
                'discord_user_id': discord_user_id,
                'discord_username': discord_username,
                'discord_display_name': discord_display_name,
                'discord_global_name': discord_global_name,
                **extra,
            }
            return '; '.join(f'{key}={value}' for key, value in details.items() if value not in (None, ''))

        if request.method != 'POST':
            _api_log('discord.authorize', 'failure', _discord_authorize_log_details(error='method not allowed'))
            return _json_error('Use POST with discord_user_id, discord_username, and one_time_pass to connect a Discord account.', 405)
        if not discord_user_id or not discord_username or not one_time_pass:
            _api_log('discord.authorize', 'failure', _discord_authorize_log_details(error='missing required connection fields'))
            return _json_error('discord_user_id, discord_username, and one_time_pass are required')
        user = None
        for candidate in db.session.query(User).filter(User.discord_authorization_token_hash.isnot(None)).all():
            if candidate.check_discord_authorization_token(one_time_pass):
                user = candidate
                break
        if not user:
            _api_log('discord.authorize', 'failure', _discord_authorize_log_details(error='invalid pass'))
            return _json_error('invalid or expired one-time pass', 403)
        if not user.discord_username:
            return _json_error('add your Discord username in Walter user settings before authorizing', 403)
        if user.discord_username.lower() != discord_username.lower():
            _api_log('discord.authorize', 'failure', _discord_authorize_log_details(user_id=user.id, error='username mismatch'))
            return _json_error('Discord username does not match Walter user settings', 403)
        existing = db.session.query(User).filter(User.discord_user_id == discord_user_id, User.id != user.id).first()
        if existing:
            return _json_error('Discord account is already connected to another Walter user', 409)
        user.discord_user_id = discord_user_id
        user.discord_authorization_token_hash = None
        db.session.commit()
        _api_log('discord.authorize', 'success', _discord_authorize_log_details(user_id=user.id))
        return jsonify({'authorized': True, 'user': user_payload(user)})

    @app.route('/api/v1/discord/report-pairing', methods=['POST'], strict_slashes=False)
    def api_discord_report_pairing():
        require_api_permission('tournaments.manage')
        data = request.get_json(silent=True) or {}
        discord_user_id = str(data.get('discord_user_id') or '').strip()
        tournament_id = data.get('tournament_id')
        table_number = data.get('table_number')
        if not discord_user_id or tournament_id is None or table_number is None:
            return _json_error('discord_user_id, tournament_id, and table_number are required')
        user = db.session.query(User).filter_by(discord_user_id=discord_user_id).first()
        if not user or not user.discord_username:
            return _json_error('Discord account is not authorized with a Walter user that has a Discord username', 403)
        tournament = db.session.get(Tournament, int(tournament_id))
        if not tournament:
            return _json_error('tournament not found', 404)
        round_obj = (
            db.session.query(Round)
            .filter_by(tournament_id=tournament.id)
            .order_by(Round.number.desc())
            .first()
        )
        if not round_obj:
            return _json_error('no active round found', 404)
        match = db.session.query(Match).filter_by(round_id=round_obj.id, table_number=int(table_number)).first()
        if not match:
            return _json_error('table not found in the latest round', 404)
        participant_ids = {
            player.user_id for player in (match.player1, match.player2, match.player3, match.player4) if player
        }
        if user.id not in participant_ids:
            return _json_error('only a player in this pairing can report it from Discord', 403)
        next_round = db.session.query(Round).filter(Round.tournament_id == tournament.id, Round.number > round_obj.number).first()
        if next_round:
            return _json_error('cannot modify result after next round has been paired', 409)
        if tournament.format.lower() == 'commander':
            return _json_error('Commander pairing reports are not supported from Discord yet', 400)
        try:
            p1_wins = int(data.get('player1_wins', 0))
            p2_wins = int(data.get('player2_wins', 0))
            draws = int(data.get('draws', 0))
        except (TypeError, ValueError):
            return _json_error('wins and draws must be whole numbers')
        if min(p1_wins, p2_wins, draws) < 0:
            return _json_error('wins and draws cannot be negative')
        match.result = MatchResult(player1_wins=p1_wins, player2_wins=p2_wins, draws=draws)
        match.completed = True
        db.session.commit()
        log_tournament(tournament.id, 'discord_report', 'success', f'user_id={user.id}; match_id={match.id}')
        _api_log('discord.report_pairing', 'success', f'tournament_id={tournament.id}; match_id={match.id}; user_id={user.id}')
        return jsonify({'reported': True, 'match': match_payload(match), 'round': round_payload(round_obj)})

    @app.route('/api/v1/leagues/<int:league_id>/standings')
    def api_league_standings(league_id):
        require_api_permission('tournaments.manage')
        league = db.session.get(League, league_id)
        if not league:
            return _json_error('not found', 404)
        _api_log('leagues.standings', 'success', f'league_id={league.id}')
        return jsonify({
            'league': league_payload(league),
            'standings': league_standings_payload(league),
        })


    def league_play_date_payload(play_date):
        return {
            'id': play_date.id,
            'play_date': play_date.play_date.isoformat(),
            'is_active': bool(play_date.is_active),
            'available_cube_count': len(play_date.available_cubes),
        }

    @app.route('/api/v1/leagues/<int:league_id>/play-dates')
    def api_league_play_dates(league_id):
        require_api_permission('tournaments.manage')
        league = db.session.get(League, league_id)
        if not league or not league.is_cube_league:
            return _json_error('cube league not found', 404)
        play_dates = (
            db.session.query(LeaguePlayDate)
            .filter_by(league_id=league.id)
            .order_by(LeaguePlayDate.play_date, LeaguePlayDate.id)
            .all()
        )
        _api_log('leagues.play_dates', 'success', f'league_id={league.id}')
        return jsonify({
            'league': league_payload(league),
            'play_dates': [league_play_date_payload(play_date) for play_date in play_dates],
        })

    def cube_vote_poll_payload(league, play_date):
        available_links = sorted(play_date.available_cubes, key=lambda link: link.cube.title.lower())
        totals = {
            cube_id: total or 0
            for cube_id, total in (
                db.session.query(
                    LeagueCubeVote.cube_id,
                    db.func.coalesce(db.func.sum(LeagueCubeVote.votes), 0),
                )
                .filter(LeagueCubeVote.play_date_id == play_date.id)
                .group_by(LeagueCubeVote.cube_id)
                .all()
            )
        }
        return {
            'league': league_payload(league),
            'play_date': {'id': play_date.id, 'play_date': play_date.play_date.isoformat(), 'is_active': bool(play_date.is_active)},
            'cubes': [
                {
                    'id': link.cube.id,
                    'title': link.cube.title,
                    'cube_cobra_url': link.cube.cube_cobra_url,
                    'image_url': link.cube.image_url,
                    'votes': totals.get(link.cube.id, 0),
                }
                for link in available_links
            ],
        }

    @app.route('/api/v1/leagues/<int:league_id>/cube-votes/<int:play_date_id>')
    def api_cube_vote_poll(league_id, play_date_id):
        require_api_permission('tournaments.manage')
        league = db.session.get(League, league_id)
        play_date = db.session.get(LeaguePlayDate, play_date_id)
        if not league or not league.is_cube_league or not play_date or play_date.league_id != league.id:
            return _json_error('cube vote not found', 404)
        return jsonify(cube_vote_poll_payload(league, play_date))

    def discord_cube_poll_payload(poll):
        return {
            'poll': {
                'league_id': poll.league_id,
                'play_date_id': poll.play_date_id,
                'channel_id': poll.channel_id,
                'message_id': poll.message_id,
            },
            'cube_vote': cube_vote_poll_payload(poll.league, poll.play_date),
        }

    @app.route('/api/v1/discord/cube-polls/<message_id>')
    def api_discord_cube_poll(message_id):
        require_api_permission('tournaments.manage')
        poll = db.session.query(LeagueCubeDiscordPoll).filter_by(message_id=str(message_id)).first()
        if not poll:
            return _json_error('Discord cube poll not found', 404)
        return jsonify(discord_cube_poll_payload(poll))

    @app.route('/api/v1/discord/cube-polls', methods=['POST'], strict_slashes=False)
    def api_discord_cube_poll_register():
        require_api_permission('tournaments.manage')
        data = request.get_json(silent=True) or {}
        league_id = data.get('league_id')
        play_date_id = data.get('play_date_id')
        channel_id = str(data.get('channel_id') or '').strip()
        message_id = str(data.get('message_id') or '').strip()
        if not league_id or not play_date_id or not channel_id or not message_id:
            return _json_error('league_id, play_date_id, channel_id, and message_id are required')
        league = db.session.get(League, int(league_id))
        play_date = db.session.get(LeaguePlayDate, int(play_date_id))
        if not league or not league.is_cube_league or not play_date or play_date.league_id != league.id:
            return _json_error('cube vote not found', 404)
        poll = db.session.query(LeagueCubeDiscordPoll).filter_by(message_id=message_id).first()
        if not poll:
            poll = LeagueCubeDiscordPoll(message_id=message_id)
            db.session.add(poll)
        poll.league_id = league.id
        poll.play_date_id = play_date.id
        poll.channel_id = channel_id
        db.session.commit()
        return jsonify({'registered': True, **discord_cube_poll_payload(poll)})

    @app.route('/api/v1/discord/cube-vote', methods=['POST'], strict_slashes=False)
    def api_discord_cube_vote():
        require_api_permission('tournaments.manage')
        data = request.get_json(silent=True) or {}
        discord_user_id = str(data.get('discord_user_id') or '').strip()
        league_id = data.get('league_id')
        play_date_id = data.get('play_date_id')
        cube_id = data.get('cube_id')
        selected = bool(data.get('selected'))
        if not discord_user_id or not league_id or not play_date_id or not cube_id:
            return _json_error('discord_user_id, league_id, play_date_id, and cube_id are required')
        user = db.session.query(User).filter_by(discord_user_id=discord_user_id).first()
        if not user:
            return _json_error('Discord account is not connected to Walter', 403)
        league = db.session.get(League, int(league_id))
        play_date = db.session.get(LeaguePlayDate, int(play_date_id))
        cube_id = int(cube_id)
        if not league or not league.is_cube_league or not play_date or play_date.league_id != league.id:
            return _json_error('cube vote not found', 404)
        if cube_id not in {link.cube_id for link in play_date.available_cubes}:
            return _json_error('cube is not on this ballot', 404)
        vote = db.session.query(LeagueCubeVote).filter_by(play_date_id=play_date.id, cube_id=cube_id, user_id=user.id).first()
        if selected:
            other_votes = (
                db.session.query(db.func.coalesce(db.func.sum(LeagueCubeVote.votes), 0))
                .filter(LeagueCubeVote.play_date_id == play_date.id, LeagueCubeVote.user_id == user.id, LeagueCubeVote.cube_id != cube_id)
                .scalar()
                or 0
            )
            if other_votes >= 3:
                return _json_error('use no more than 3 total votes for this play date', 409)
            if not vote:
                vote = LeagueCubeVote(league_id=league.id, play_date_id=play_date.id, cube_id=cube_id, user_id=user.id)
                db.session.add(vote)
            vote.votes = 1
        elif vote:
            db.session.delete(vote)
        db.session.commit()
        return jsonify(cube_vote_poll_payload(league, play_date))

    @app.route('/api/v1/leagues/<int:league_id>', methods=['GET', 'PATCH', 'DELETE'])
    def api_league_detail(league_id):
        api_user, _ = require_api_permission('tournaments.manage')
        league = db.session.get(League, league_id)
        if not league:
            return _json_error('not found', 404)
        if request.method == 'PATCH':
            data = request.get_json(silent=True) or {}
            if 'name' in data and data['name']:
                league.name = str(data['name']).strip()
            if 'is_cube_league' in data:
                league.is_cube_league = bool(data['is_cube_league'])
            db.session.commit()
            _api_log('leagues.update', 'success', f'league_id={league.id}; api_user_id={api_user.id}')
        elif request.method == 'DELETE':
            deleted_id = league.id
            db.session.delete(league)
            db.session.commit()
            _api_log('leagues.delete', 'success', f'league_id={deleted_id}; api_user_id={api_user.id}')
            return jsonify({'deleted': True})
        else:
            _api_log('leagues.get', 'success', f'league_id={league.id}')
        return jsonify(league_payload(league))

    @app.template_filter('cube_cobra_title')
    def cube_cobra_title_filter(title):
        return clean_cube_cobra_title(title)

    @app.context_processor
    def inject_navigation_counts():
        unread = 0
        open_reports = 0
        if current_user.is_authenticated:
            unread = (
                db.session.query(Message)
                .filter_by(recipient_id=current_user.id, is_read=False)
                .count()
            )
            if current_user.has_permission('admin.panel'):
                open_reports = (
                    db.session.query(Report)
                    .filter(or_(Report.is_read.is_(None), Report.is_read.is_(False)))
                    .count()
                )
        return {
            'nav_unread_messages': unread,
            'nav_open_reports': open_reports,
            'nav_registration_mode': registration_mode(),
            'site_theme': site_theme(),
            'cube_cobra_fallback_image_url': CUBE_COBRA_FALLBACK_IMAGE_URL,
        }

    @app.route('/reports', methods=['GET', 'POST'])
    @login_required
    def submit_report():
        if request.method == 'POST':
            report_type = request.form.get('report_type')
            description = (request.form.get('description') or '').strip()
            if not description:
                flash('Description is required.', 'error')
                return redirect(url_for('submit_report'))
            if report_type not in ('bug', 'player'):
                flash('Invalid report type.', 'error')
                return redirect(url_for('submit_report'))
            report = Report(report_type=report_type, description=description, reporter_id=current_user.id)
            if report_type == 'player':
                reported_user_id_raw = (request.form.get('reported_user_id') or '').strip()
                if reported_user_id_raw:
                    try:
                        reported_user_id = int(reported_user_id_raw)
                    except ValueError:
                        flash('Select a valid user to report.', 'error')
                        return redirect(url_for('submit_report'))
                    target = db.session.get(User, reported_user_id)
                    if not target:
                        flash('Selected user could not be found.', 'error')
                        return redirect(url_for('submit_report'))
                    report.reported_user_id = target.id
                else:
                    flash('Select a user to report.', 'error')
                    return redirect(url_for('submit_report'))
            db.session.add(report)
            db.session.commit()
            log_site('report_submit', 'success', report_type)
            flash('Report submitted. Thank you for your feedback!', 'success')
            return redirect(url_for('submit_report'))
        return render_template('reports/index.html')

    def can_manage_lost_found():
        if not current_user.is_authenticated:
            return False
        return current_user.has_permission('tournaments.manage') or current_user.has_permission('admin.panel')

    @app.route('/lost-and-found', methods=['GET', 'POST'])
    @app.route('/admin/venues/<int:venue_id>/lost-and-found', methods=['GET', 'POST'])
    @login_required
    def lost_and_found(venue_id=None):
        if venue_id is None:
            return redirect(url_for('venue_management'))
        venue = _get_visible_venue_or_404(venue_id)
        manage_access = can_manage_lost_found()
        status_options = [
            ('unclaimed', 'Unclaimed'),
            ('claimed', 'Claimed'),
            ('returned', 'Returned'),
        ]
        if request.method == 'POST':
            if not manage_access:
                abort(403)
            title = request.form.get('title', '').strip()
            description = (request.form.get('description') or '').strip()
            location = (request.form.get('location') or '').strip()
            reporter_name = (request.form.get('reporter_name') or '').strip()
            reporter_contact = (request.form.get('reporter_contact') or '').strip()
            status = request.form.get('status', 'unclaimed')
            if status not in dict(status_options):
                status = 'unclaimed'
            if not title:
                flash('Item name is required.', 'error')
                return redirect(url_for('lost_and_found', venue_id=venue.id))
            image_filename = None
            upload = request.files.get('photo')
            if upload and upload.filename:
                image_filename = sanitize_image_upload(upload)
                if not image_filename:
                    flash('Image could not be processed. Please upload a different picture.', 'error')
                    return redirect(url_for('lost_and_found', venue_id=venue.id))
            item = LostFoundItem(
                title=title,
                description=description,
                location=location,
                reporter_name=reporter_name,
                reporter_contact=reporter_contact,
                status=status,
                venue_id=venue.id,
            )
            if image_filename:
                item.image_path = image_filename
            db.session.add(item)
            db.session.commit()
            log_site('lost_found_create', 'success', title)
            flash('Lost & Found entry created.', 'success')
            return redirect(url_for('lost_and_found', venue_id=venue.id))
        items = (
            db.session.query(LostFoundItem)
            .filter(LostFoundItem.venue_id == venue.id)
            .order_by(LostFoundItem.created_at.desc())
            .all()
        )
        return render_template(
            'lost_found/index.html',
            items=items,
            venue=venue,
            manage_access=manage_access,
            status_options=status_options,
        )

    @app.route('/admin/venues/<int:venue_id>/lost-and-found/<int:item_id>/update', methods=['POST'])
    @login_required
    def update_lost_and_found(venue_id, item_id):
        if not can_manage_lost_found():
            abort(403)
        venue = _get_visible_venue_or_404(venue_id)
        item = db.session.get(LostFoundItem, item_id)
        if not item or item.venue_id != venue.id:
            abort(404)
        status_options = {'unclaimed', 'claimed', 'returned'}
        status = request.form.get('status', item.status or 'unclaimed')
        if status not in status_options:
            status = item.status or 'unclaimed'
        item.status = status
        item.location = (request.form.get('location') or '').strip()
        item.reporter_contact = (request.form.get('reporter_contact') or '').strip()
        upload = request.files.get('photo')
        if upload and upload.filename:
            image_filename = sanitize_image_upload(upload)
            if image_filename:
                item.image_path = image_filename
        db.session.commit()
        log_site('lost_found_update', 'success', f'id={item_id}')
        flash('Lost & Found entry updated.', 'success')
        return redirect(url_for('lost_and_found', venue_id=venue.id))


    @app.route('/cube-cobra-image')
    @login_required
    def cube_cobra_image():
        image_url = request.args.get('url', '').strip()
        if not is_allowed_cube_preview_image_url(image_url):
            abort(404)
        try:
            req = urllib.request.Request(
                image_url,
                headers={'User-Agent': 'WaLTER cube preview bot/1.0'},
            )
            with urllib.request.urlopen(req, timeout=8) as response:
                content_type = (
                    response.headers.get('Content-Type', 'application/octet-stream')
                    .split(';', 1)[0]
                    .strip()
                    .lower()
                )
                if not content_type.startswith('image/'):
                    abort(404)
                content_length = response.headers.get('Content-Length')
                if content_length and int(content_length) > CUBE_COBRA_IMAGE_MAX_BYTES:
                    abort(413)
                body = response.read(CUBE_COBRA_IMAGE_MAX_BYTES + 1)
                if len(body) > CUBE_COBRA_IMAGE_MAX_BYTES:
                    abort(413)
                return Response(body, content_type=content_type)
        except HTTPException:
            raise
        except Exception:
            abort(404)

    @app.route('/media/<path:filename>')
    @login_required
    def media_file(filename):
        media_dir = app.config.get('MEDIA_STORAGE_DIR')
        if not media_dir:
            abort(404)
        safe_name = secure_filename(os.path.basename(filename))
        path = os.path.join(media_dir, safe_name)
        if not os.path.exists(path):
            abort(404)
        return send_from_directory(media_dir, safe_name)

    @app.route('/admin/reports')
    @login_required
    def admin_reports():
        require_admin()
        reports = (
            db.session.query(Report)
            .order_by(Report.is_read.asc(), Report.created_at.desc())
            .all()
        )
        assignees = (
            db.session.query(User)
            .outerjoin(Role)
            .filter(
                or_(
                    User.is_admin.is_(True),
                    Role.level <= 400,
                )
            )
            .order_by(Role.level, User.name)
            .all()
        )
        status_options = ['open', 'in_progress', 'closed']
        return render_template(
            'admin/reports.html',
            reports=reports,
            assignees=assignees,
            status_options=status_options,
        )

    @app.route('/admin/reports/<int:rid>/update', methods=['POST'])
    @login_required
    def update_report(rid):
        require_admin()
        report = db.session.get(Report, rid)
        if not report:
            abort(404)
        status = request.form.get('status', report.status or 'open')
        if status not in {'open', 'in_progress', 'closed'}:
            status = report.status or 'open'
        assigned_raw = (request.form.get('assigned_to_id') or '').strip()
        assigned_user = None
        if assigned_raw:
            try:
                assigned_id = int(assigned_raw)
                assigned_user = db.session.get(User, assigned_id)
            except (TypeError, ValueError):
                assigned_user = None
        report.status = status
        report.assigned_to = assigned_user
        report.is_read = request.form.get('is_read') == '1'
        actions_taken = (request.form.get('actions_taken') or '').strip()
        report.actions_taken = actions_taken or None
        db.session.commit()
        log_site('report_update', 'success', f'id={rid}')
        flash('Report updated.', 'success')
        return redirect(url_for('admin_reports'))

    @app.route('/admin/reports/export.csv')
    @login_required
    def export_reports_csv():
        require_admin()
        reports = db.session.query(Report).order_by(Report.created_at.desc()).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow([
            'Type',
            'Reporter',
            'Reported User',
            'Description',
            'Status',
            'Assigned To',
            'Read',
            'Actions Taken',
            'Created At',
        ])
        for r in reports:
            writer.writerow([
                r.report_type,
                r.reporter.name if r.reporter else '',
                r.reported_user.name if r.reported_user else '',
                r.description.replace('\n', ' ').strip(),
                r.status,
                r.assigned_to.name if r.assigned_to else '',
                'yes' if r.is_read else 'no',
                (r.actions_taken or '').replace('\n', ' ').strip(),
                r.created_at.isoformat() if r.created_at else '',
            ])
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=reports.csv'},
        )

    # ---------- Admin ----------
    def require_permission(perm):
        if not current_user.is_authenticated or not current_user.has_permission(perm):
            log_site('unauthorized_access', 'failure', perm)
            abort(403)

    def require_admin():
        require_permission('admin.panel')

    def venue_ids_for_user(user):
        if not user or not getattr(user, 'is_authenticated', False):
            return set()
        if hasattr(user, 'has_permission') and user.has_permission('venues.manage'):
            return {venue.id for venue in db.session.query(Venue.id).all()}
        rows = (
            db.session.query(Tournament.venue_id)
            .join(TournamentPlayer, TournamentPlayer.tournament_id == Tournament.id)
            .filter(TournamentPlayer.user_id == user.id, Tournament.venue_id.isnot(None))
            .distinct()
            .all()
        )
        return {row[0] for row in rows}

    def restrict_to_visible_venues(query, model):
        visible_ids = venue_ids_for_user(current_user)
        if current_user.has_permission('venues.manage'):
            return query
        if not visible_ids:
            return query.filter(False)
        return query.filter(model.venue_id.in_(visible_ids))

    def log_site(action, result, error=None):
        log = SiteLog(action=action, result=result, error=error,
                      user_id=current_user.id if current_user.is_authenticated else None,
                      ip_address=_client_ip())
        db.session.add(log)
        db.session.commit()

    def _safe_log_site(action, result, error=None):
        try:
            log_site(action, result, error)
        except SQLAlchemyError:
            db.session.rollback()
            app.logger.exception(
                'Unable to write site log entry during login/security flow: action=%s result=%s error=%r',
                action,
                result,
                error,
            )
        except Exception:
            db.session.rollback()
            app.logger.exception(
                'Unexpected failure writing site log entry during login/security flow: action=%s result=%s error=%r',
                action,
                result,
                error,
            )

    def log_tournament(tid, action, result, error=None):
        log = TournamentLog(tournament_id=tid, action=action, result=result, error=error,
                             user_id=current_user.id if current_user.is_authenticated else None)
        db.session.add(log)
        db.session.commit()

    @app.before_request
    def track_current_connection():
        if request.endpoint == 'static':
            return
        ip_address = _client_ip()
        fingerprint = _browser_fingerprint()
        key = f'{ip_address}:{fingerprint}'
        CURRENT_CONNECTIONS[key] = {
            'ip_address': ip_address,
            'fingerprint': fingerprint,
            'user_id': current_user.id if current_user.is_authenticated else None,
            'user_name': current_user.name if current_user.is_authenticated else None,
            'user_agent': request.headers.get('User-Agent', ''),
            'last_seen': datetime.utcnow(),
        }
        while len(CURRENT_CONNECTIONS) > 250:
            CURRENT_CONNECTIONS.popitem(last=False)

    @app.before_request
    def block_blacklisted_ip():
        ip_address = _client_ip()
        blocked = db.session.query(BlacklistedIP).filter_by(ip_address=ip_address, is_active=True).first()
        if blocked:
            app.logger.warning('Blocked blacklisted IP address %s from %s', ip_address, request.path)
            log_site('blocked_blacklisted_ip', 'failure', f'ip={ip_address}; path={request.path}')
            abort(403)

    def parse_datetime_local(value):
        if not value:
            return None
        value = value.strip()
        if not value:
            return None
        candidates = [value]
        if 'T' not in value and ' ' in value:
            candidates.append(value.replace(' ', 'T'))
        for candidate in candidates:
            try:
                return datetime.fromisoformat(candidate)
            except ValueError:
                continue
        formats = (
            '%Y-%m-%d %H:%M',
            '%Y-%m-%d %H:%M:%S',
            '%Y-%m-%dT%H:%M',
            '%Y-%m-%dT%H:%M:%S',
        )
        for candidate in candidates:
            for fmt in formats:
                try:
                    return datetime.strptime(candidate, fmt)
                except ValueError:
                    continue
        return None

    def sanitize_image_upload(file_storage, prefix='lf'):
        if not file_storage or not file_storage.filename:
            return None
        storage_dir = app.config.get('MEDIA_STORAGE_DIR')
        if not storage_dir:
            return None
        storage_dir = os.path.realpath(storage_dir)
        try:
            file_storage.stream.seek(0)
            image = Image.open(file_storage.stream)
            image = ImageOps.exif_transpose(image)
        except Exception:
            return None
        max_dim = 1600
        image.thumbnail((max_dim, max_dim))
        buffer = io.BytesIO()
        try:
            image.save(buffer, format='PNG')
        except Exception:
            return None
        buffer.seek(0)
        safe_prefix = ''.join(ch for ch in str(prefix) if ch.isalnum()) or 'deck'
        filename = secure_filename(
            f"{safe_prefix}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}.png"
        )
        if not filename:
            return None
        os.makedirs(storage_dir, exist_ok=True)
        path = safe_join(storage_dir, filename)
        if not path:
            return None
        path = os.path.realpath(path)
        if os.path.commonpath([storage_dir, path]) != storage_dir:
            return None
        with open(path, 'wb') as handle:
            handle.write(buffer.read())
        return filename

    def get_card_database_path():
        path = app.config.get('CARD_DB_PATH')
        if not path:
            base = os.path.join(app.instance_path, 'mtg_cards.db')
            app.config['CARD_DB_PATH'] = base
            path = base
        return path

    def ensure_card_database_ready():
        path = get_card_database_path()
        source_url = app.config.get('CARD_DB_URL', card_db.ATOMIC_CARDS_URL)
        return card_db.ensure_card_database(path, source_url=source_url)

    def combine_card_entries(entries):
        combined = OrderedDict()
        for entry in entries:
            name = (entry.get('name') or '').strip()
            count = int(entry.get('count') or 0)
            if not name or count <= 0:
                continue
            if name in combined:
                combined[name] += count
            else:
                combined[name] = count
        return [{'name': name, 'count': count} for name, count in combined.items()]

    def parse_counted_sections(text):
        main_entries = []
        side_entries = []
        current = main_entries
        errors = []
        for raw_line in text.splitlines():
            line = (raw_line or '').strip()
            if not line:
                continue
            if line.lower().startswith('sideboard'):
                current = side_entries
                continue
            parts = line.split(None, 1)
            if len(parts) != 2:
                errors.append(f"Invalid deck line: '{raw_line}'")
                continue
            try:
                count = int(parts[0])
            except ValueError:
                errors.append(f"Invalid card count in line: '{raw_line}'")
                continue
            card_name = parts[1].strip()
            if not card_name:
                errors.append(f"Missing card name in line: '{raw_line}'")
                continue
            current.append({'name': card_name, 'count': count})
        return combine_card_entries(main_entries), combine_card_entries(side_entries), errors

    def parse_deck_json(payload):
        errors = []

        def parse_section(items):
            entries = []
            if not isinstance(items, list):
                return entries
            for item in items:
                if not isinstance(item, dict):
                    errors.append('Invalid entry in deck data.')
                    continue
                name = (item.get('name') or '').strip()
                count_raw = item.get('count', 0)
                try:
                    count = int(count_raw)
                except (TypeError, ValueError):
                    errors.append(f"Invalid quantity for '{name or 'card'}' in deck data.")
                    continue
                if count <= 0 or not name:
                    continue
                entries.append({'name': name, 'count': count})
            return combine_card_entries(entries)

        main_entries = parse_section(payload.get('main') if isinstance(payload, dict) else [])
        side_entries = parse_section(payload.get('side') if isinstance(payload, dict) else [])
        return main_entries, side_entries, errors

    def canonicalize_card_group(card_entries, db_path=None):
        if not card_entries:
            return [], []
        path = db_path or ensure_card_database_ready()
        canonical_names = card_db.canonicalize_names(path, [c['name'] for c in card_entries])
        resolved = []
        missing = []
        for entry, canonical in zip(card_entries, canonical_names):
            if canonical:
                resolved.append({'name': canonical, 'count': entry['count']})
            else:
                missing.append(entry['name'])
        return resolved, missing

    def save_player_deck(tp, source, main_cards, side_cards, raw_text=None, submitted=False):
        from .models import TournamentPlayerDeck  # lazy import

        deck = tp.deck
        if not deck:
            deck = TournamentPlayerDeck(tournament_player=tp, source=source)
        deck.source = source
        deck.mainboard = json.dumps(main_cards, ensure_ascii=False)
        deck.sideboard = json.dumps(side_cards, ensure_ascii=False)
        deck.raw_text = raw_text
        if hasattr(deck, 'moxfield_url'):
            deck.moxfield_url = None
        deck.is_submitted = bool(submitted)
        if deck.is_submitted:
            deck.submitted_at = datetime.utcnow()
        else:
            deck.submitted_at = None
        db.session.add(deck)
        db.session.commit()
        return deck

    def update_deck_image(tp, filename):
        from .models import TournamentPlayerDeck  # lazy import

        deck = tp.deck
        if not deck:
            deck = TournamentPlayerDeck(tournament_player=tp, source='image', mainboard='[]', sideboard='[]')
        if deck.source is None:
            deck.source = 'image'
        old_image = deck.image_path
        deck.image_path = filename
        db.session.add(deck)
        db.session.commit()
        storage_dir = app.config.get('MEDIA_STORAGE_DIR')
        if storage_dir and old_image and old_image != filename:
            old_safe = secure_filename(os.path.basename(old_image))
            old_path = os.path.join(storage_dir, old_safe)
            if os.path.exists(old_path):
                try:
                    os.remove(old_path)
                except OSError:
                    pass
        return deck

    def parse_mtgo_deck_text(text):
        return parse_counted_sections(text)

    def validate_deck_lists(main_cards, side_cards, db_path):
        errors = []
        total_main = sum(card.get('count', 0) for card in main_cards)
        if total_main < 60:
            errors.append('Mainboard must contain at least 60 cards.')
        total_side = sum(card.get('count', 0) for card in side_cards)
        if total_side > 15:
            errors.append('Sideboard may contain at most 15 cards.')
        combined = OrderedDict()
        for card in main_cards + side_cards:
            name = card.get('name')
            count = int(card.get('count', 0))
            if not name or count <= 0:
                continue
            combined[name] = combined.get(name, 0) + count
        if not combined:
            return errors
        metadata = card_db.get_card_metadata(db_path, list(combined.keys()))
        for name, total in combined.items():
            info = metadata.get(name)
            if not info:
                continue
            if info.get('is_land') and not info.get('is_basic_land') and total > 4:
                errors.append(f"{name} exceeds the 4-copy limit for non-basic lands.")
            if info.get('is_standard_banned'):
                errors.append(f"{name} is banned in Standard.")
            if info.get('is_vintage_restricted') and total > 1:
                errors.append(f"{name} is restricted to a single copy.")
        return errors

    def get_player_entry(tournament_id, user_id):
        from .models import TournamentPlayer  # lazy import

        return (
            db.session.query(TournamentPlayer)
            .filter_by(tournament_id=tournament_id, user_id=user_id)
            .first()
        )

    def user_can_view_player_decks(user, tournament, assigned_judge_ids=None):
        """Return True if ``user`` may view decks for ``tournament``."""
        if not user or not getattr(user, 'is_authenticated', False):
            return False
        if hasattr(user, 'has_permission') and user.has_permission('tournaments.manage'):
            return True
        if assigned_judge_ids is None:
            assigned = set(tournament.floor_judge_ids() or [])
            if tournament.head_judge_id:
                assigned.add(tournament.head_judge_id)
        else:
            assigned = set(assigned_judge_ids)
        return user.id in assigned

    def deck_modifications_locked(tournament):
        from .models import Round  # lazy import

        return (
            db.session.query(Round)
            .filter_by(tournament_id=tournament.id, number=1)
            .first()
            is not None
        )

    def estimate_end_time(t):
        """Estimate tournament end time based on start time and timers."""
        if not t.start_time:
            return None
        rounds = t.rounds_override or recommended_rounds(len(t.players))
        total = (t.draft_time or 0) + (t.deck_build_time or 0) + rounds * (t.round_length or 50)
        if t.cut != 'none':
            total += (t.round_length or 50)
        return t.start_time + timedelta(minutes=total)

    def iso_datetime(value):
        return value.isoformat() if value else None

    def iso_date(value):
        return value.isoformat() if value else None

    def parse_iso_datetime(value):
        if not value:
            return None
        try:
            return datetime.fromisoformat(value)
        except (TypeError, ValueError):
            return None

    def parse_iso_date(value):
        if not value:
            return None
        try:
            return datetime.fromisoformat(value).date()
        except (TypeError, ValueError):
            return None

    def encode_binary(value):
        if value is None:
            return None
        return base64.b64encode(value).decode('ascii')

    def decode_binary(value):
        if not value:
            return None
        try:
            return base64.b64decode(value.encode('ascii'))
        except Exception:
            return None

    def json_loads_safe(value, default=None):
        if default is None:
            default = []
        try:
            return json.loads(value or 'null') or default
        except Exception:
            return default

    BACKUP_FORMAT = 'walter-admin-backup'
    ENCRYPTED_BACKUP_FORMAT = 'walter-admin-backup-encrypted'
    BACKUP_ENCRYPTION_ITERATIONS = 390000

    def export_backup_payload():
        roles = db.session.query(Role).order_by(Role.level, Role.name).all()
        users = db.session.query(User).order_by(User.id).all()
        leagues = db.session.query(League).order_by(League.id).all()
        venues = db.session.query(Venue).order_by(Venue.id).all()
        vendors = db.session.query(Vendor).order_by(Vendor.id).all()
        artists = db.session.query(ArtistProfile).order_by(ArtistProfile.id).all()
        tournaments = db.session.query(Tournament).order_by(Tournament.id).all()
        tournament_ids = [t.id for t in tournaments]
        players = db.session.query(TournamentPlayer).order_by(TournamentPlayer.id).all()
        player_ids = [p.id for p in players]
        rounds = db.session.query(Round).order_by(Round.id).all()
        round_ids = [r.id for r in rounds]
        matches = db.session.query(Match).order_by(Match.id).all()
        decks = db.session.query(TournamentPlayerDeck).order_by(TournamentPlayerDeck.id).all()
        join_requests = db.session.query(TournamentJoinRequest).order_by(TournamentJoinRequest.id).all()
        league_players = db.session.query(LeaguePlayer).order_by(LeaguePlayer.id).all()
        league_results = db.session.query(LeagueResult).order_by(LeagueResult.id).all()
        league_cubes = db.session.query(LeagueCube).order_by(LeagueCube.id).all()
        league_play_dates = db.session.query(LeaguePlayDate).order_by(LeaguePlayDate.id).all()
        league_play_date_cubes = db.session.query(LeaguePlayDateCube).order_by(LeaguePlayDateCube.id).all()
        league_cube_votes = db.session.query(LeagueCubeVote).order_by(LeagueCubeVote.id).all()
        registration_invites = db.session.query(RegistrationInvite).order_by(RegistrationInvite.id).all()

        return {
            'format': BACKUP_FORMAT,
            'version': 1,
            'exported_at': datetime.now(timezone.utc).replace(tzinfo=None).isoformat(),
            'permissions': PERMISSION_GROUPS,
            'roles': [
                {
                    'id': r.id,
                    'name': r.name,
                    'permissions': r.permissions_dict(),
                    'level': r.level,
                }
                for r in roles
            ],
            'users': [
                {
                    'id': u.id,
                    'email': u.email,
                    'name': u.name,
                    'first_name': u.first_name,
                    'last_name': u.last_name,
                    'password_hash': u.password_hash,
                    'salt': u.salt,
                    'is_admin': bool(u.is_admin),
                    'created_at': iso_datetime(u.created_at),
                    'notes': u.notes,
                    'role_id': u.role_id,
                    'role_name': u.role.name if u.role else None,
                    'break_end': iso_datetime(u.break_end),
                    'public_key': encode_binary(u.public_key),
                    'private_key_encrypted': encode_binary(u.private_key_encrypted),
                    'private_key_salt': encode_binary(u.private_key_salt),
                    'private_key_nonce': encode_binary(u.private_key_nonce),
                    'permission_overrides': u.permission_overrides_dict(),
                }
                for u in users
            ],
            'leagues': [
                {
                    'id': l.id,
                    'name': l.name,
                    'start_date': iso_date(l.start_date),
                    'end_date': iso_date(l.end_date),
                    'created_at': iso_datetime(l.created_at),
                    'is_cube_league': bool(l.is_cube_league),
                }
                for l in leagues
            ],
            'venues': [
                {
                    'id': v.id,
                    'name': v.name,
                    'address': v.address,
                    'website': v.website,
                    'notes': v.notes,
                    'created_at': iso_datetime(v.created_at),
                }
                for v in venues
            ],
            'vendors': [
                {
                    'id': vendor.id,
                    'venue_id': vendor.venue_id,
                    'name': vendor.name,
                    'website': vendor.website,
                    'booth_number': vendor.booth_number,
                    'services_provided': vendor.services_provided,
                    'created_at': iso_datetime(vendor.created_at),
                }
                for vendor in vendors
            ],
            'artists': [
                {
                    'id': artist.id,
                    'venue_id': artist.venue_id,
                    'name': artist.name,
                    'website': artist.website,
                    'booth_number': artist.booth_number,
                    'services_provided': artist.services_provided,
                    'created_at': iso_datetime(artist.created_at),
                }
                for artist in artists
            ],
            'league_players': [
                {
                    'id': lp.id,
                    'league_id': lp.league_id,
                    'user_id': lp.user_id,
                    'created_at': iso_datetime(lp.created_at),
                }
                for lp in league_players
            ],
            'tournaments': [
                {
                    'id': t.id,
                    'name': t.name,
                    'format': t.format,
                    'structure': t.structure,
                    'cut': t.cut,
                    'pairing_type': t.pairing_type,
                    'pairing_options': json_loads_safe(t.pairing_options, {}) if t.pairing_options else None,
                    'rules_enforcement_level': t.rules_enforcement_level,
                    'is_cube': bool(t.is_cube),
                    'rounds_override': t.rounds_override,
                    'start_table_number': t.start_table_number,
                    'created_at': iso_datetime(t.created_at),
                    'commander_points': t.commander_points,
                    'guid': t.guid,
                    'round_length': t.round_length,
                    'draft_time': t.draft_time,
                    'deck_build_time': t.deck_build_time,
                    'start_time': iso_datetime(t.start_time),
                    'started_at': iso_datetime(t.started_at),
                    'ended_at': iso_datetime(t.ended_at),
                    'manually_completed': bool(t.manually_completed),
                    'head_judge_id': t.head_judge_id,
                    'floor_judges': t.floor_judge_ids(),
                    'round_timer_end': iso_datetime(t.round_timer_end),
                    'draft_timer_end': iso_datetime(t.draft_timer_end),
                    'deck_timer_end': iso_datetime(t.deck_timer_end),
                    'round_timer_remaining': t.round_timer_remaining,
                    'draft_timer_remaining': t.draft_timer_remaining,
                    'deck_timer_remaining': t.deck_timer_remaining,
                    'passcode': t.passcode,
                    'join_requires_approval': bool(t.join_requires_approval),
                    'player_cap': t.player_cap,
                    'league_id': t.league_id,
                    'venue_id': t.venue_id,
                }
                for t in tournaments
            ],
            'tournament_players': [
                {
                    'id': p.id,
                    'tournament_id': p.tournament_id,
                    'user_id': p.user_id,
                    'points': p.points,
                    'game_wins': p.game_wins,
                    'game_losses': p.game_losses,
                    'game_draws': p.game_draws,
                    'dropped': bool(p.dropped),
                }
                for p in players
            ],
            'tournament_player_decks': [
                {
                    'id': d.id,
                    'tournament_player_id': d.tournament_player_id,
                    'source': d.source,
                    'mainboard': json_loads_safe(d.mainboard, []),
                    'sideboard': json_loads_safe(d.sideboard, []),
                    'raw_text': d.raw_text,
                    'moxfield_url': d.moxfield_url,
                    'image_path': d.image_path,
                    'created_at': iso_datetime(d.created_at),
                    'updated_at': iso_datetime(d.updated_at),
                    'is_submitted': bool(d.is_submitted),
                    'submitted_at': iso_datetime(d.submitted_at),
                }
                for d in decks if d.tournament_player_id in player_ids
            ],
            'tournament_join_requests': [
                {
                    'id': jr.id,
                    'tournament_id': jr.tournament_id,
                    'user_id': jr.user_id,
                    'status': jr.status,
                    'created_at': iso_datetime(jr.created_at),
                    'updated_at': iso_datetime(jr.updated_at),
                    'note': jr.note,
                    'approved_by_id': jr.approved_by_id,
                }
                for jr in join_requests if jr.tournament_id in tournament_ids
            ],
            'rounds': [
                {
                    'id': r.id,
                    'tournament_id': r.tournament_id,
                    'number': r.number,
                }
                for r in rounds if r.tournament_id in tournament_ids
            ],
            'matches': [
                {
                    'id': m.id,
                    'round_id': m.round_id,
                    'player1_id': m.player1_id,
                    'player2_id': m.player2_id,
                    'player3_id': m.player3_id,
                    'player4_id': m.player4_id,
                    'table_number': m.table_number,
                    'completed': bool(m.completed),
                    'result': {
                        'player1_wins': m.result.player1_wins,
                        'player2_wins': m.result.player2_wins,
                        'draws': m.result.draws,
                        'p1_place': m.result.p1_place,
                        'p2_place': m.result.p2_place,
                        'p3_place': m.result.p3_place,
                        'p4_place': m.result.p4_place,
                        'is_draw': bool(m.result.is_draw),
                    } if m.result else None,
                }
                for m in matches if m.round_id in round_ids
            ],
            'registration_invites': [
                {
                    'id': i.id, 'email': i.email, 'token_hash': i.token_hash,
                    'created_by_id': i.created_by_id, 'created_at': iso_datetime(i.created_at),
                    'expires_at': iso_datetime(i.expires_at), 'used_at': iso_datetime(i.used_at),
                    'used_by_id': i.used_by_id, 'status': i.status,
                } for i in registration_invites
            ],
            'league_cubes': [
                {'id': c.id, 'league_id': c.league_id, 'cube_cobra_url': c.cube_cobra_url, 'title': c.title, 'image_url': c.image_url, 'created_at': iso_datetime(c.created_at)} for c in league_cubes
            ],
            'league_play_dates': [
                {'id': d.id, 'league_id': d.league_id, 'play_date': iso_date(d.play_date), 'is_active': bool(d.is_active), 'created_at': iso_datetime(d.created_at)} for d in league_play_dates
            ],
            'league_play_date_cubes': [
                {'id': x.id, 'play_date_id': x.play_date_id, 'cube_id': x.cube_id} for x in league_play_date_cubes
            ],
            'league_cube_votes': [
                {'id': v.id, 'league_id': v.league_id, 'play_date_id': v.play_date_id, 'cube_id': v.cube_id, 'user_id': v.user_id, 'votes': v.votes, 'updated_at': iso_datetime(v.updated_at)} for v in league_cube_votes
            ],
            'league_results': [
                {
                    'id': lr.id,
                    'league_id': lr.league_id,
                    'tournament_id': lr.tournament_id,
                    'user_id': lr.user_id,
                    'points': lr.points,
                    'wins': lr.wins,
                    'draws': lr.draws,
                    'losses': lr.losses,
                    'deck_archetype': lr.deck_archetype,
                    'imported_at': iso_datetime(lr.imported_at),
                }
                for lr in league_results
            ],
        }

    def derive_backup_key(password, salt):
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=BACKUP_ENCRYPTION_ITERATIONS,
        )
        return kdf.derive(password.encode('utf-8'))

    def encrypt_backup_payload(payload, password):
        salt = os.urandom(16)
        nonce = os.urandom(12)
        key = derive_backup_key(password, salt)
        plaintext = json.dumps(payload, sort_keys=True).encode('utf-8')
        ciphertext = AESGCM(key).encrypt(nonce, plaintext, None)
        return {
            'format': ENCRYPTED_BACKUP_FORMAT,
            'version': 1,
            'encryption': {
                'algorithm': 'AES-256-GCM',
                'kdf': 'PBKDF2-HMAC-SHA256',
                'iterations': BACKUP_ENCRYPTION_ITERATIONS,
                'salt': encode_binary(salt),
                'nonce': encode_binary(nonce),
            },
            'ciphertext': encode_binary(ciphertext),
        }

    def decrypt_backup_payload(payload, password):
        if not password:
            raise ValueError('This backup is encrypted. Enter the backup password to import it.')
        encryption = payload.get('encryption') or {}
        if payload.get('version') != 1:
            raise ValueError('Unsupported encrypted backup version.')
        if encryption.get('algorithm') != 'AES-256-GCM' or encryption.get('kdf') != 'PBKDF2-HMAC-SHA256':
            raise ValueError('Unsupported backup encryption settings.')
        if int(encryption.get('iterations') or 0) != BACKUP_ENCRYPTION_ITERATIONS:
            raise ValueError('Unsupported backup encryption settings.')
        salt = decode_binary(encryption.get('salt'))
        nonce = decode_binary(encryption.get('nonce'))
        ciphertext = decode_binary(payload.get('ciphertext'))
        if not salt or not nonce or not ciphertext:
            raise ValueError('Encrypted backup is missing encryption data.')
        try:
            key = derive_backup_key(password, salt)
            plaintext = AESGCM(key).decrypt(nonce, ciphertext, None)
            return json.loads(plaintext.decode('utf-8'))
        except Exception as exc:
            raise ValueError('Unable to decrypt backup. Check the backup password and try again.') from exc

    def decode_backup_file(payload, password=None):
        if isinstance(payload, dict) and payload.get('format') == ENCRYPTED_BACKUP_FORMAT:
            return decrypt_backup_payload(payload, password)
        return payload

    def apply_backup_payload(payload, overwrite=False):
        if not isinstance(payload, dict) or payload.get('format') != BACKUP_FORMAT:
            raise ValueError('This is not a valid WaLTER backup file.')
        if payload.get('version') != 1:
            raise ValueError('Unsupported backup version.')

        counts = {key: 0 for key in ['roles', 'users', 'leagues', 'venues', 'vendors', 'artists', 'tournaments', 'players', 'decks', 'join_requests', 'rounds', 'matches', 'league_players', 'league_results', 'league_cubes', 'league_play_dates', 'league_play_date_cubes', 'league_cube_votes', 'registration_invites']}
        role_map = {}
        user_map = {}
        league_map = {}
        tournament_map = {}
        venue_map = {}
        player_map = {}
        round_map = {}
        cube_map = {}
        play_date_map = {}

        for item in payload.get('roles', []):
            name = (item.get('name') or '').strip()
            if not name:
                continue
            role = db.session.query(Role).filter_by(name=name).first()
            if not role:
                role = Role(name=name)
                db.session.add(role)
            if overwrite or not role.id:
                role.permissions = json.dumps(item.get('permissions') or {})
                role.level = int(item.get('level') or 500)
                counts['roles'] += 1
            role_map[item.get('id')] = role
        db.session.flush()

        for item in payload.get('users', []):
            email = (item.get('email') or '').strip().lower() or None
            name = (item.get('name') or '').strip()
            if not name:
                continue
            user = db.session.query(User).filter_by(email=email).first() if email else None
            if not user:
                user = db.session.query(User).filter(User.email.is_(None), User.name == name).first()
            is_new = user is None
            if is_new:
                user = User(name=name)
                _set_user_name_parts(user, fallback_name=name)
                db.session.add(user)
            if overwrite or is_new:
                role = role_map.get(item.get('role_id'))
                if not role and item.get('role_name'):
                    role = db.session.query(Role).filter_by(name=item.get('role_name')).first()
                user.email = email
                _set_user_name_parts(user, item.get('first_name'), item.get('last_name'), name)
                user.password_hash = item.get('password_hash')
                user.salt = item.get('salt')
                user.is_admin = bool(item.get('is_admin'))
                user.created_at = parse_iso_datetime(item.get('created_at')) or user.created_at
                user.notes = item.get('notes')
                user.role = role
                user.break_end = parse_iso_datetime(item.get('break_end'))
                user.public_key = decode_binary(item.get('public_key'))
                user.private_key_encrypted = decode_binary(item.get('private_key_encrypted'))
                user.private_key_salt = decode_binary(item.get('private_key_salt'))
                user.private_key_nonce = decode_binary(item.get('private_key_nonce'))
                overrides = item.get('permission_overrides') or {}
                user.permission_overrides = json.dumps(overrides) if overrides else None
                counts['users'] += 1
            user_map[item.get('id')] = user
        db.session.flush()

        for item in payload.get('leagues', []):
            name = (item.get('name') or '').strip()
            if not name:
                continue
            league = db.session.query(League).filter_by(name=name).first()
            is_new = league is None
            if is_new:
                league = League(name=name)
                db.session.add(league)
            if overwrite or is_new:
                league.name = name
                league.start_date = parse_iso_date(item.get('start_date'))
                league.end_date = parse_iso_date(item.get('end_date'))
                league.created_at = parse_iso_datetime(item.get('created_at')) or league.created_at
                league.is_cube_league = bool(item.get('is_cube_league'))
                counts['leagues'] += 1
            league_map[item.get('id')] = league
        db.session.flush()


        for item in payload.get('venues', []):
            name = (item.get('name') or '').strip()
            if not name:
                continue
            venue = db.session.query(Venue).filter_by(name=name).first()
            is_new = venue is None
            if is_new:
                venue = Venue(name=name)
                db.session.add(venue)
            if overwrite or is_new:
                venue.name = name
                venue.address = item.get('address')
                venue.website = item.get('website')
                venue.notes = item.get('notes')
                venue.created_at = parse_iso_datetime(item.get('created_at')) or venue.created_at
                counts['venues'] += 1
            venue_map[item.get('id')] = venue
        db.session.flush()

        for item in payload.get('vendors', []):
            name = (item.get('name') or '').strip()
            if not name:
                continue
            vendor = db.session.query(Vendor).filter_by(name=name).first()
            is_new = vendor is None
            if is_new:
                vendor = Vendor(name=name)
                db.session.add(vendor)
            if overwrite or is_new:
                vendor.name = name
                vendor.venue = venue_map.get(item.get('venue_id'))
                vendor.website = item.get('website')
                vendor.booth_number = item.get('booth_number')
                vendor.services_provided = item.get('services_provided')
                vendor.created_at = parse_iso_datetime(item.get('created_at')) or vendor.created_at
                counts['vendors'] += 1
        db.session.flush()

        for item in payload.get('artists', []):
            name = (item.get('name') or '').strip()
            if not name:
                continue
            artist = db.session.query(ArtistProfile).filter_by(name=name).first()
            is_new = artist is None
            if is_new:
                artist = ArtistProfile(name=name)
                db.session.add(artist)
            if overwrite or is_new:
                artist.name = name
                artist.venue = venue_map.get(item.get('venue_id'))
                artist.website = item.get('website')
                artist.booth_number = item.get('booth_number')
                artist.services_provided = item.get('services_provided')
                artist.created_at = parse_iso_datetime(item.get('created_at')) or artist.created_at
                counts['artists'] += 1
        db.session.flush()

        for item in payload.get('tournaments', []):
            guid = (item.get('guid') or '').strip() or None
            tournament = db.session.query(Tournament).filter_by(guid=guid).first() if guid else None
            if not tournament:
                tournament = db.session.query(Tournament).filter_by(name=item.get('name')).first()
            is_new = tournament is None
            if is_new:
                tournament = Tournament(name=item.get('name') or 'Imported Tournament', format=item.get('format') or 'Constructed')
                db.session.add(tournament)
            if overwrite or is_new:
                tournament.name = item.get('name') or tournament.name
                tournament.format = item.get('format') or tournament.format
                tournament.structure = item.get('structure') or tournament.structure
                tournament.cut = item.get('cut') or tournament.cut
                tournament.pairing_type = item.get('pairing_type') or tournament.pairing_type
                pairing_options = item.get('pairing_options')
                tournament.pairing_options = json.dumps(pairing_options) if pairing_options is not None else None
                tournament.rules_enforcement_level = item.get('rules_enforcement_level') or tournament.rules_enforcement_level
                tournament.is_cube = bool(item.get('is_cube'))
                tournament.rounds_override = item.get('rounds_override')
                tournament.start_table_number = item.get('start_table_number') or 1
                tournament.created_at = parse_iso_datetime(item.get('created_at')) or tournament.created_at
                tournament.commander_points = item.get('commander_points') or tournament.commander_points
                if guid:
                    tournament.guid = guid
                tournament.round_length = item.get('round_length') or tournament.round_length
                tournament.draft_time = item.get('draft_time')
                tournament.deck_build_time = item.get('deck_build_time')
                tournament.start_time = parse_iso_datetime(item.get('start_time'))
                tournament.started_at = parse_iso_datetime(item.get('started_at'))
                tournament.ended_at = parse_iso_datetime(item.get('ended_at'))
                tournament.manually_completed = bool(item.get('manually_completed'))
                tournament.head_judge = user_map.get(item.get('head_judge_id'))
                floor_ids = [user_map[uid].id for uid in item.get('floor_judges') or [] if uid in user_map and user_map[uid].id]
                tournament.floor_judges = json.dumps(floor_ids)
                tournament.round_timer_end = parse_iso_datetime(item.get('round_timer_end'))
                tournament.draft_timer_end = parse_iso_datetime(item.get('draft_timer_end'))
                tournament.deck_timer_end = parse_iso_datetime(item.get('deck_timer_end'))
                tournament.round_timer_remaining = item.get('round_timer_remaining')
                tournament.draft_timer_remaining = item.get('draft_timer_remaining')
                tournament.deck_timer_remaining = item.get('deck_timer_remaining')
                tournament.passcode = item.get('passcode') or tournament.passcode
                tournament.join_requires_approval = bool(item.get('join_requires_approval'))
                tournament.player_cap = int(item.get('player_cap') or 8)
                tournament.league = league_map.get(item.get('league_id'))
                tournament.venue = venue_map.get(item.get('venue_id'))
                counts['tournaments'] += 1
            tournament_map[item.get('id')] = tournament
        db.session.flush()

        for item in payload.get('tournament_players', []):
            tournament = tournament_map.get(item.get('tournament_id'))
            user = user_map.get(item.get('user_id'))
            if not tournament or not user:
                continue
            player = db.session.query(TournamentPlayer).filter_by(tournament_id=tournament.id, user_id=user.id).first()
            is_new = player is None
            if is_new:
                player = TournamentPlayer(tournament=tournament, user=user)
                db.session.add(player)
            if overwrite or is_new:
                player.points = item.get('points') or 0
                player.game_wins = item.get('game_wins') or 0
                player.game_losses = item.get('game_losses') or 0
                player.game_draws = item.get('game_draws') or 0
                player.dropped = bool(item.get('dropped'))
                counts['players'] += 1
            player_map[item.get('id')] = player
        db.session.flush()

        for item in payload.get('registration_invites', []):
            email = (item.get('email') or '').strip().lower()
            token_hash = item.get('token_hash')
            creator = user_map.get(item.get('created_by_id'))
            if not email or not token_hash or not creator:
                continue
            invite = db.session.query(RegistrationInvite).filter_by(token_hash=token_hash).first()
            is_new = invite is None
            if is_new:
                invite = RegistrationInvite(email=email, token_hash=token_hash, created_by=creator)
                db.session.add(invite)
            if overwrite or is_new:
                invite.email = email
                invite.created_by = creator
                invite.created_at = parse_iso_datetime(item.get('created_at')) or invite.created_at
                invite.expires_at = parse_iso_datetime(item.get('expires_at'))
                invite.used_at = parse_iso_datetime(item.get('used_at'))
                invite.used_by = user_map.get(item.get('used_by_id'))
                invite.status = item.get('status') or invite.status
                counts['registration_invites'] += 1
        db.session.flush()

        for item in payload.get('league_players', []):
            league = league_map.get(item.get('league_id'))
            user = user_map.get(item.get('user_id'))
            if not league or not user:
                continue
            lp = db.session.query(LeaguePlayer).filter_by(league_id=league.id, user_id=user.id).first()
            is_new = lp is None
            if is_new:
                lp = LeaguePlayer(league=league, user=user)
                db.session.add(lp)
            if overwrite or is_new:
                lp.created_at = parse_iso_datetime(item.get('created_at')) or lp.created_at
                counts['league_players'] += 1
        db.session.flush()

        for item in payload.get('tournament_player_decks', []):
            player = player_map.get(item.get('tournament_player_id'))
            if not player:
                continue
            deck = db.session.query(TournamentPlayerDeck).filter_by(tournament_player_id=player.id).first()
            is_new = deck is None
            if is_new:
                deck = TournamentPlayerDeck(tournament_player=player, source=item.get('source') or 'text')
                db.session.add(deck)
            if overwrite or is_new:
                deck.source = item.get('source') or deck.source
                deck.mainboard = json.dumps(item.get('mainboard') or [])
                deck.sideboard = json.dumps(item.get('sideboard') or [])
                deck.raw_text = item.get('raw_text')
                deck.moxfield_url = item.get('moxfield_url')
                deck.image_path = item.get('image_path')
                deck.created_at = parse_iso_datetime(item.get('created_at')) or deck.created_at
                deck.updated_at = parse_iso_datetime(item.get('updated_at')) or deck.updated_at
                deck.is_submitted = bool(item.get('is_submitted'))
                deck.submitted_at = parse_iso_datetime(item.get('submitted_at'))
                counts['decks'] += 1
        db.session.flush()

        for item in payload.get('tournament_join_requests', []):
            tournament = tournament_map.get(item.get('tournament_id'))
            user = user_map.get(item.get('user_id'))
            if not tournament or not user:
                continue
            jr = db.session.query(TournamentJoinRequest).filter_by(tournament_id=tournament.id, user_id=user.id).first()
            is_new = jr is None
            if is_new:
                jr = TournamentJoinRequest(tournament=tournament, user=user)
                db.session.add(jr)
            if overwrite or is_new:
                jr.status = item.get('status') or jr.status
                jr.created_at = parse_iso_datetime(item.get('created_at')) or jr.created_at
                jr.updated_at = parse_iso_datetime(item.get('updated_at')) or jr.updated_at
                jr.note = item.get('note')
                jr.approved_by = user_map.get(item.get('approved_by_id'))
                counts['join_requests'] += 1
        db.session.flush()

        for item in payload.get('rounds', []):
            tournament = tournament_map.get(item.get('tournament_id'))
            if not tournament:
                continue
            round_obj = db.session.query(Round).filter_by(tournament_id=tournament.id, number=item.get('number')).first()
            is_new = round_obj is None
            if is_new:
                round_obj = Round(tournament=tournament, number=item.get('number') or 1)
                db.session.add(round_obj)
            if overwrite or is_new:
                counts['rounds'] += 1
            round_map[item.get('id')] = round_obj
        db.session.flush()

        for item in payload.get('matches', []):
            round_obj = round_map.get(item.get('round_id'))
            player1 = player_map.get(item.get('player1_id'))
            if not round_obj or not player1:
                continue
            match = db.session.query(Match).filter_by(round_id=round_obj.id, table_number=item.get('table_number')).first()
            is_new = match is None
            if is_new:
                match = Match(round=round_obj, player1=player1, table_number=item.get('table_number') or 1)
                db.session.add(match)
            if overwrite or is_new:
                match.player1 = player1
                match.player2 = player_map.get(item.get('player2_id'))
                match.player3 = player_map.get(item.get('player3_id'))
                match.player4 = player_map.get(item.get('player4_id'))
                match.table_number = item.get('table_number') or match.table_number
                match.completed = bool(item.get('completed'))
                result_data = item.get('result')
                if result_data:
                    if not match.result:
                        match.result = MatchResult()
                    match.result.player1_wins = result_data.get('player1_wins') or 0
                    match.result.player2_wins = result_data.get('player2_wins') or 0
                    match.result.draws = result_data.get('draws') or 0
                    match.result.p1_place = result_data.get('p1_place')
                    match.result.p2_place = result_data.get('p2_place')
                    match.result.p3_place = result_data.get('p3_place')
                    match.result.p4_place = result_data.get('p4_place')
                    match.result.is_draw = bool(result_data.get('is_draw'))
                counts['matches'] += 1
        db.session.flush()

        for item in payload.get('league_cubes', []):
            league = league_map.get(item.get('league_id'))
            title = (item.get('title') or '').strip()
            url = (item.get('cube_cobra_url') or '').strip()
            if not league or not title or not url:
                continue
            cube = db.session.query(LeagueCube).filter_by(league_id=league.id, cube_cobra_url=url).first()
            is_new = cube is None
            if is_new:
                cube = LeagueCube(league=league, cube_cobra_url=url, title=title)
                db.session.add(cube)
            if overwrite or is_new:
                cube.title = title
                cube.image_url = item.get('image_url')
                cube.created_at = parse_iso_datetime(item.get('created_at')) or cube.created_at
                counts['league_cubes'] += 1
            cube_map[item.get('id')] = cube
        db.session.flush()

        for item in payload.get('league_play_dates', []):
            league = league_map.get(item.get('league_id'))
            date_value = parse_iso_date(item.get('play_date'))
            if not league or not date_value:
                continue
            play_date = db.session.query(LeaguePlayDate).filter_by(league_id=league.id, play_date=date_value).first()
            is_new = play_date is None
            if is_new:
                play_date = LeaguePlayDate(league=league, play_date=date_value)
                db.session.add(play_date)
            if overwrite or is_new:
                play_date.is_active = bool(item.get('is_active'))
                play_date.created_at = parse_iso_datetime(item.get('created_at')) or play_date.created_at
                counts['league_play_dates'] += 1
            play_date_map[item.get('id')] = play_date
        db.session.flush()

        for item in payload.get('league_play_date_cubes', []):
            play_date = play_date_map.get(item.get('play_date_id'))
            cube = cube_map.get(item.get('cube_id'))
            if not play_date or not cube:
                continue
            link = db.session.query(LeaguePlayDateCube).filter_by(play_date_id=play_date.id, cube_id=cube.id).first()
            if not link:
                db.session.add(LeaguePlayDateCube(play_date=play_date, cube=cube))
                counts['league_play_date_cubes'] += 1
        db.session.flush()

        for item in payload.get('league_cube_votes', []):
            league = league_map.get(item.get('league_id'))
            play_date = play_date_map.get(item.get('play_date_id'))
            cube = cube_map.get(item.get('cube_id'))
            user = user_map.get(item.get('user_id'))
            if not league or not play_date or not cube or not user:
                continue
            vote = db.session.query(LeagueCubeVote).filter_by(play_date_id=play_date.id, cube_id=cube.id, user_id=user.id).first()
            is_new = vote is None
            if is_new:
                vote = LeagueCubeVote(league=league, play_date=play_date, cube=cube, user=user)
                db.session.add(vote)
            if overwrite or is_new:
                vote.votes = item.get('votes') or 0
                vote.updated_at = parse_iso_datetime(item.get('updated_at')) or vote.updated_at
                counts['league_cube_votes'] += 1
        db.session.flush()

        for item in payload.get('league_results', []):
            league = league_map.get(item.get('league_id'))
            tournament = tournament_map.get(item.get('tournament_id'))
            user = user_map.get(item.get('user_id'))
            if not league or not tournament or not user:
                continue
            lr = db.session.query(LeagueResult).filter_by(league_id=league.id, tournament_id=tournament.id, user_id=user.id).first()
            is_new = lr is None
            if is_new:
                lr = LeagueResult(league=league, tournament=tournament, user=user)
                db.session.add(lr)
            if overwrite or is_new:
                lr.points = item.get('points') or 0
                lr.wins = item.get('wins') or 0
                lr.draws = item.get('draws') or 0
                lr.losses = item.get('losses') or 0
                lr.deck_archetype = item.get('deck_archetype')
                lr.imported_at = parse_iso_datetime(item.get('imported_at')) or lr.imported_at
                counts['league_results'] += 1

        db.session.commit()
        return counts

    def resolve_structure_and_pairing(form):
        """Determine structure and pairing from the submitted form data."""
        selection = (form.get('structure') or 'swiss').lower()
        pairing_choice = (form.get('pairing_type') or '').lower()
        if selection == 'single_elim':
            return 'single_elim', 'swiss'
        if selection == 'round_robin':
            return 'swiss', 'round_robin'
        # Fall back to legacy behaviour where structure and pairing were separate fields
        structure = 'single_elim' if selection == 'single_elim' else 'swiss'
        if structure != 'single_elim' and pairing_choice == 'round_robin':
            return structure, 'round_robin'
        return structure, 'swiss'

    @app.route('/admin/tournaments/new', methods=['GET','POST'])
    def new_tournament():
        require_permission('tournaments.manage')
        leagues = db.session.query(League).order_by(League.name).all()
        venues = db.session.query(Venue).order_by(Venue.name).all()
        template_context = {
            'leagues': leagues,
            'venues': venues,
            'formats': TOURNAMENT_FORMATS,
            'suggested_start_table_number': 1,
            'table_reservations': table_reservations(),
        }
        if request.method == 'POST':
            provided_name = request.form['name'].strip()
            fmt = request.form['format']
            if fmt not in TOURNAMENT_FORMATS:
                flash('Select a supported tournament format.', 'error')
                return render_template('admin/new_tournament.html', **template_context)
            structure, pairing_type = resolve_structure_and_pairing(request.form)
            cut = request.form.get('cut', 'none') if structure == 'swiss' and pairing_type != 'round_robin' else 'none'
            if fmt == 'Commander' and cut not in ('none','top4','top16','top32','top64'):
                flash('Commander supports cuts to Top 4, 16, 32, or 64.', 'error')
                return render_template('admin/new_tournament.html', **template_context)
            commander_points = request.form.get('commander_points', '3,2,1,0,1')
            round_length = int(request.form.get('round_length', 50))
            draft_time = request.form.get('draft_time')
            deck_build_time = request.form.get('deck_build_time')
            start_time_str = request.form.get('start_time')
            start_time = parse_datetime_local(start_time_str)
            if start_time_str and start_time is None:
                flash('Invalid start time format.', 'error')
                return render_template('admin/new_tournament.html', **template_context)
            rel = request.form.get('rules_enforcement_level', 'None') or 'None'
            is_cube = request.form.get('is_cube') == '1'
            if fmt != 'Draft':
                is_cube = False
            join_requires_approval = request.form.get('join_requires_approval') == '1'
            player_cap_raw = (request.form.get('player_cap') or '').strip()
            if not player_cap_raw:
                player_cap_raw = '8'
            try:
                player_cap = int(player_cap_raw)
            except ValueError:
                flash('Player cap is required and must be a whole number.', 'error')
                return render_template('admin/new_tournament.html', **template_context)
            if player_cap < 1:
                flash('Player cap must be at least 1.', 'error')
                return render_template('admin/new_tournament.html', **template_context)
            start_table_raw = (request.form.get('start_table_number') or '').strip()
            if start_table_raw:
                try:
                    start_table_number = int(start_table_raw)
                except ValueError:
                    flash('Starting table number must be a whole number.', 'error')
                    return render_template('admin/new_tournament.html', **template_context)
            else:
                start_table_number = None
            name = format_tournament_name(fmt, start_time, provided_name)
            t = Tournament(name=name, format=fmt, cut=cut, structure=structure,
                           pairing_type=pairing_type,
                           commander_points=commander_points,
                           round_length=round_length,
                           draft_time=int(draft_time) if draft_time else None,
                           deck_build_time=int(deck_build_time) if deck_build_time else None,
                           start_time=start_time,
                            rules_enforcement_level=rel,
                           is_cube=is_cube,
                           join_requires_approval=join_requires_approval,
                           player_cap=player_cap,
                           start_table_number=start_table_number)
            league_id = request.form.get('league_id')
            if league_id:
                t.league_id = int(league_id)
            venue_id = request.form.get('venue_id')
            if venue_id:
                t.venue_id = int(venue_id)
            if start_table_number is None:
                start_table_number = find_available_table_start(t)
                t.start_table_number = start_table_number
            errors, _, _, _, _ = validate_table_assignment(t, start_number=start_table_number)
            if errors:
                for message in errors:
                    flash(message, 'error')
                return render_template('admin/new_tournament.html', **template_context)
            try:
                db.session.add(t)
                # warn on overlapping schedule
                if start_time:
                    new_end = estimate_end_time(t)
                    others = db.session.query(Tournament).filter(Tournament.start_time.isnot(None)).all()
                    for other in others:
                        if other.id == t.id:
                            continue
                        other_end = estimate_end_time(other)
                        if other.start_time and other_end and not (new_end <= other.start_time or start_time >= other_end):
                            flash('Warning: overlaps with existing tournament "' + other.name + '"', 'warning')
                            break
                db.session.commit()
                log_site('tournament_create', 'success')
                log_tournament(t.id, 'create', 'success')
                flash("Tournament created.", "success")
                return redirect(url_for('view_tournament', tid=t.id))
            except Exception as e:
                db.session.rollback()
                log_site('tournament_create', 'failure', str(e))
                flash('Error creating tournament.', 'error')
        return render_template('admin/new_tournament.html', **template_context)

    @app.route('/admin/tournaments/<int:tid>/edit', methods=['GET','POST'])
    def edit_tournament(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        venues = db.session.query(Venue).order_by(Venue.name).all()
        suggested_start_table_number = find_available_table_start(t)
        template_context = {
            't': t,
            'venues': venues,
            'formats': TOURNAMENT_FORMATS,
            'provided_name': extract_provided_tournament_name(t.name),
            'suggested_start_table_number': suggested_start_table_number,
            'table_reservations': table_reservations(t.id),
        }
        if request.method == 'POST':
            provided_name = request.form['name'].strip()
            new_format = request.form['format']
            if new_format not in TOURNAMENT_FORMATS:
                flash('Select a supported tournament format.', 'error')
                return render_template('admin/edit_tournament.html', **template_context)
            new_structure, new_pairing_type = resolve_structure_and_pairing(request.form)
            new_cut = request.form.get('cut', 'none') if new_structure == 'swiss' and new_pairing_type != 'round_robin' else 'none'
            commander_points = request.form.get('commander_points', '3,2,1,0,1')
            round_length = int(request.form.get('round_length', 50))
            draft_time = request.form.get('draft_time')
            deck_build_time = request.form.get('deck_build_time')
            start_time_str = request.form.get('start_time')
            start_time = parse_datetime_local(start_time_str)
            if start_time_str and start_time is None:
                flash('Invalid start time format.', 'error')
                return render_template('admin/edit_tournament.html', **template_context)
            rel = request.form.get('rules_enforcement_level', 'None') or 'None'
            is_cube = request.form.get('is_cube') == '1'
            join_requires_approval = request.form.get('join_requires_approval') == '1'
            player_cap_raw = (request.form.get('player_cap') or '').strip()
            if not player_cap_raw:
                player_cap_raw = str(len(t.players) or 8)
            try:
                player_cap = int(player_cap_raw)
            except ValueError:
                flash('Player cap is required and must be a whole number.', 'error')
                return render_template('admin/edit_tournament.html', **template_context)
            if player_cap < len(t.players):
                flash('Player cap cannot be below the current player count.', 'error')
                return render_template('admin/edit_tournament.html', **template_context)
            start_table_raw = (request.form.get('start_table_number') or '').strip()
            if start_table_raw:
                try:
                    start_table_number = int(start_table_raw)
                except ValueError:
                    flash('Starting table number must be a whole number.', 'error')
                    return render_template('admin/edit_tournament.html', **template_context)
            else:
                start_table_number = None

            class _Preview:
                pass

            preview = _Preview()
            preview.id = t.id
            preview.format = new_format
            preview.start_table_number = start_table_number or t.start_table_number or 1
            preview.players = t.players
            preview.player_cap = player_cap
            preview.name = provided_name or t.name
            if start_table_number is None:
                start_table_number = find_available_table_start(preview)
                preview.start_table_number = start_table_number
            errors, _, _, _, _ = validate_table_assignment(preview, start_number=start_table_number)
            if errors:
                for message in errors:
                    flash(message, 'error')
                return render_template('admin/edit_tournament.html', **template_context)

            t.name = format_tournament_name(new_format, start_time, provided_name)
            t.format = new_format
            t.structure = new_structure
            t.pairing_type = new_pairing_type
            if new_pairing_type != 'round_robin':
                t.pairing_options = None
            t.cut = new_cut
            t.commander_points = commander_points
            t.round_length = round_length
            t.start_time = start_time
            t.draft_time = int(draft_time) if draft_time else None
            t.deck_build_time = int(deck_build_time) if deck_build_time else None
            t.rules_enforcement_level = rel
            t.is_cube = is_cube if t.format == 'Draft' else False
            t.join_requires_approval = join_requires_approval
            t.player_cap = player_cap
            t.start_table_number = start_table_number
            venue_id = request.form.get('venue_id')
            t.venue_id = int(venue_id) if venue_id else None
            db.session.commit()
            flash('Tournament updated.', 'success')
            log_site('edit_tournament', 'success', t.name)
            log_tournament(tid, 'edit', 'success')
            return redirect(url_for('view_tournament', tid=tid))
        return render_template('admin/edit_tournament.html', **template_context)

    @app.route('/admin/venues', methods=['GET', 'POST'])
    @login_required
    def venue_management():
        if request.method == 'POST':
            require_permission('venues.manage')
            name = request.form.get('name', '').strip()
            if not name:
                flash('Venue name is required.', 'error')
            else:
                venue = Venue(
                    name=name,
                    address=request.form.get('address', '').strip() or None,
                    website=request.form.get('website', '').strip() or None,
                    notes=request.form.get('notes', '').strip() or None,
                )
                db.session.add(venue)
                db.session.commit()
                log_site('venue_create', 'success', f'venue_id={venue.id}')
                flash('Venue created.', 'success')
                return redirect(url_for('venue_management'))
        venue_query = db.session.query(Venue).order_by(Venue.name)
        if not current_user.has_permission('venues.manage'):
            visible_ids = venue_ids_for_user(current_user)
            venue_query = venue_query.filter(Venue.id.in_(visible_ids)) if visible_ids else venue_query.filter(False)
        venues = venue_query.all()
        return render_template(
            'admin/venues.html',
            venues=venues,
            can_manage_venues=current_user.has_permission('venues.manage'),
        )

    @app.route('/admin/venues/<int:venue_id>/update', methods=['POST'])
    @login_required
    def update_venue(venue_id):
        require_permission('venues.manage')
        venue = db.session.get(Venue, venue_id)
        if not venue:
            abort(404)
        name = request.form.get('name', '').strip()
        if not name:
            flash('Venue name is required.', 'error')
        else:
            venue.name = name
            venue.address = request.form.get('address', '').strip() or None
            venue.website = request.form.get('website', '').strip() or None
            venue.notes = request.form.get('notes', '').strip() or None
            db.session.commit()
            log_site('venue_update', 'success', f'venue_id={venue.id}')
            flash('Venue updated.', 'success')
        return redirect(url_for('venue_management'))

    def _get_visible_venue_or_404(venue_id):
        venue = db.session.get(Venue, venue_id)
        if not venue:
            abort(404)
        if current_user.has_permission('venues.manage'):
            return venue
        if venue.id not in venue_ids_for_user(current_user):
            abort(403)
        return venue

    @app.route('/admin/venues/<int:venue_id>')
    @login_required
    def venue_detail(venue_id):
        venue = _get_visible_venue_or_404(venue_id)
        current_tournaments = (
            db.session.query(Tournament)
            .filter(Tournament.venue_id == venue.id)
            .order_by(Tournament.start_time.desc().nullslast(), Tournament.created_at.desc())
            .all()
        )
        available_tournaments = (
            db.session.query(Tournament)
            .filter(or_(Tournament.venue_id.is_(None), Tournament.venue_id != venue.id))
            .order_by(Tournament.start_time.desc().nullslast(), Tournament.created_at.desc())
            .all()
        )
        unassigned_tournaments = (
            db.session.query(Tournament)
            .filter(Tournament.venue_id.is_(None))
            .order_by(Tournament.start_time.desc().nullslast(), Tournament.created_at.desc())
            .all()
        )
        return render_template(
            'admin/venue_detail.html',
            venue=venue,
            current_tournaments=current_tournaments,
            available_tournaments=available_tournaments,
            unassigned_tournaments=unassigned_tournaments,
            can_bulk_add_tournaments=(
                current_user.has_permission('venues.manage')
                and (
                    current_user.has_permission('tournaments.bulk_manage')
                    or current_user.has_permission('tournaments.manage')
                )
            ),
        )

    @app.route('/admin/venues/<int:venue_id>/tournaments/bulk-add', methods=['POST'])
    @login_required
    def bulk_add_tournaments_to_venue(venue_id):
        require_permission('venues.manage')
        user_id = current_user.id if current_user.is_authenticated else None
        if not (
            current_user.has_permission('tournaments.bulk_manage')
            or current_user.has_permission('tournaments.manage')
        ):
            app.logger.warning(
                'Venue bulk add denied: user_id=%s venue_id=%s required=%s',
                user_id,
                venue_id,
                'venues.manage+(tournaments.bulk_manage|tournaments.manage)',
            )
            log_site('unauthorized_access', 'failure', 'venues.manage+tournaments.bulk_manage')
            abort(403)
        venue = db.session.get(Venue, venue_id)
        if not venue:
            app.logger.warning('Venue bulk add aborted: venue_id=%s was not found; user_id=%s', venue_id, user_id)
            abort(404)
        raw_ids = request.form.getlist('tournament_ids')
        tournament_ids = []
        seen_tournament_ids = set()
        invalid_tournament_ids = []
        duplicate_tournament_ids = []
        for raw_id in raw_ids:
            try:
                tournament_id = int(raw_id)
            except (TypeError, ValueError):
                invalid_tournament_ids.append(raw_id)
                continue
            if tournament_id in seen_tournament_ids:
                duplicate_tournament_ids.append(tournament_id)
                continue
            seen_tournament_ids.add(tournament_id)
            tournament_ids.append(tournament_id)
        app.logger.info(
            'Venue bulk add requested: user_id=%s venue_id=%s raw_ids=%r parsed_ids=%s duplicates=%s invalid=%r',
            user_id,
            venue.id,
            raw_ids,
            tournament_ids,
            duplicate_tournament_ids,
            invalid_tournament_ids,
        )
        if not tournament_ids:
            app.logger.info('Venue bulk add rejected: no valid tournament ids for venue_id=%s user_id=%s', venue.id, user_id)
            flash('Select at least one tournament to add to this venue.', 'error')
            return redirect(url_for('venue_detail', venue_id=venue.id))
        tournaments = db.session.query(Tournament).filter(Tournament.id.in_(tournament_ids)).all()
        tournament_by_id = {t.id: t for t in tournaments}
        ordered_tournaments = [tournament_by_id[tid] for tid in tournament_ids if tid in tournament_by_id]
        missing_tournament_ids = [tid for tid in tournament_ids if tid not in tournament_by_id]
        skipped_tournament_ids = []
        moved_tournament_ids = []
        for tournament in ordered_tournaments:
            if tournament.venue_id == venue.id:
                skipped_tournament_ids.append(tournament.id)
                continue
            previous_venue_id = tournament.venue_id
            tournament.venue_id = venue.id
            moved_tournament_ids.append(tournament.id)
            app.logger.info(
                'Venue bulk add staged: user_id=%s tournament_id=%s previous_venue_id=%s new_venue_id=%s',
                user_id,
                tournament.id,
                previous_venue_id,
                venue.id,
            )
        try:
            db.session.commit()
        except Exception as exc:
            db.session.rollback()
            app.logger.exception(
                'Venue bulk add commit failed: user_id=%s venue_id=%s parsed_ids=%s moved_ids=%s missing_ids=%s skipped_ids=%s error=%s',
                user_id,
                venue.id,
                tournament_ids,
                moved_tournament_ids,
                missing_tournament_ids,
                skipped_tournament_ids,
                exc,
            )
            flash('Bulk add failed. Please try again or review the selected tournaments.', 'error')
            return redirect(url_for('venue_detail', venue_id=venue.id))

        app.logger.info(
            'Venue bulk add committed: user_id=%s venue_id=%s moved_ids=%s missing_ids=%s skipped_ids=%s duplicates=%s invalid=%r',
            user_id,
            venue.id,
            moved_tournament_ids,
            missing_tournament_ids,
            skipped_tournament_ids,
            duplicate_tournament_ids,
            invalid_tournament_ids,
        )

        if moved_tournament_ids:
            try:
                for tournament_id in moved_tournament_ids:
                    db.session.add(TournamentLog(
                        tournament_id=tournament_id,
                        action='bulk_add_to_venue',
                        result='success',
                        error=f'venue_id={venue.id}',
                        user_id=user_id,
                    ))
                    db.session.add(SiteLog(
                        action='venue_bulk_add_tournaments',
                        result='success',
                        error=f'venue_id={venue.id}; tournament_id={tournament_id}',
                        user_id=user_id,
                    ))
                db.session.commit()
            except Exception as exc:
                db.session.rollback()
                app.logger.exception(
                    'Venue bulk add audit logging failed after assignment commit: user_id=%s venue_id=%s moved_ids=%s error=%s',
                    user_id,
                    venue.id,
                    moved_tournament_ids,
                    exc,
                )

        if missing_tournament_ids:
            flash(f'Some selected tournaments no longer exist: {missing_tournament_ids}.', 'warning')
        count = len(moved_tournament_ids)
        flash(f'Added {count} tournament' + ('s' if count != 1 else '') + f' to {venue.name}.', 'success')
        return redirect(url_for('venue_detail', venue_id=venue.id))

    def booth_number_conflict(venue_id, booth_number, *, vendor_id=None, artist_id=None):
        booth = (booth_number or '').strip()
        if not venue_id or not booth:
            return None
        vendor_query = db.session.query(Vendor).filter(
            Vendor.venue_id == venue_id,
            db.func.lower(Vendor.booth_number) == booth.lower(),
        )
        if vendor_id is not None:
            vendor_query = vendor_query.filter(Vendor.id != vendor_id)
        vendor = vendor_query.first()
        if vendor:
            return f'Booth {booth} is already assigned to vendor {vendor.name}.'
        artist_query = db.session.query(ArtistProfile).filter(
            ArtistProfile.venue_id == venue_id,
            db.func.lower(ArtistProfile.booth_number) == booth.lower(),
        )
        if artist_id is not None:
            artist_query = artist_query.filter(ArtistProfile.id != artist_id)
        artist = artist_query.first()
        if artist:
            return f'Booth {booth} is already assigned to artist {artist.name}.'
        return None

    @app.route('/admin/venues/vendors', methods=['GET', 'POST'])
    @login_required
    def vendor_management():
        venue_query = db.session.query(Venue).order_by(Venue.name)
        if not current_user.has_permission('venues.manage'):
            visible_ids = venue_ids_for_user(current_user)
            venue_query = venue_query.filter(Venue.id.in_(visible_ids)) if visible_ids else venue_query.filter(False)
        venues = venue_query.all()
        if request.method == 'POST':
            require_permission('venues.manage')
            name = request.form.get('name', '').strip()
            if not name:
                flash('Vendor name is required.', 'error')
            else:
                venue_id = int(request.form['venue_id']) if request.form.get('venue_id') else None
                booth_number = request.form.get('booth_number', '').strip() or None
                conflict = booth_number_conflict(venue_id, booth_number)
                if conflict:
                    flash(conflict, 'error')
                else:
                    vendor = Vendor(
                        name=name,
                        venue_id=venue_id,
                        website=request.form.get('website', '').strip() or None,
                        booth_number=booth_number,
                        services_provided=request.form.get('services_provided', '').strip() or None,
                    )
                    db.session.add(vendor)
                    db.session.commit()
                    log_site('vendor_create', 'success', f'vendor_id={vendor.id}')
                    flash('Vendor created.', 'success')
                    return redirect(url_for('vendor_management'))
        vendors = restrict_to_visible_venues(db.session.query(Vendor), Vendor).order_by(Vendor.name).all()
        return render_template('admin/vendors.html', vendors=vendors, venues=venues, can_manage_venues=current_user.has_permission('venues.manage'))

    @app.route('/admin/venues/vendors/<int:vendor_id>/update', methods=['POST'])
    @login_required
    def update_vendor(vendor_id):
        require_permission('venues.manage')
        vendor = db.session.get(Vendor, vendor_id)
        if not vendor:
            abort(404)
        name = request.form.get('name', '').strip()
        if not name:
            flash('Vendor name is required.', 'error')
        else:
            venue_id = int(request.form['venue_id']) if request.form.get('venue_id') else None
            booth_number = request.form.get('booth_number', '').strip() or None
            conflict = booth_number_conflict(venue_id, booth_number, vendor_id=vendor.id)
            if conflict:
                flash(conflict, 'error')
            else:
                vendor.name = name
                vendor.venue_id = venue_id
                vendor.website = request.form.get('website', '').strip() or None
                vendor.booth_number = booth_number
                vendor.services_provided = request.form.get('services_provided', '').strip() or None
                db.session.commit()
                log_site('vendor_update', 'success', f'vendor_id={vendor.id}')
                flash('Vendor updated.', 'success')
        return redirect(url_for('vendor_management'))

    @app.route('/admin/venues/artists', methods=['GET', 'POST'])
    @login_required
    def artist_management():
        venue_query = db.session.query(Venue).order_by(Venue.name)
        if not current_user.has_permission('venues.manage'):
            visible_ids = venue_ids_for_user(current_user)
            venue_query = venue_query.filter(Venue.id.in_(visible_ids)) if visible_ids else venue_query.filter(False)
        venues = venue_query.all()
        if request.method == 'POST':
            require_permission('venues.manage')
            name = request.form.get('name', '').strip()
            if not name:
                flash('Artist name is required.', 'error')
            else:
                venue_id = int(request.form['venue_id']) if request.form.get('venue_id') else None
                booth_number = request.form.get('booth_number', '').strip() or None
                conflict = booth_number_conflict(venue_id, booth_number)
                if conflict:
                    flash(conflict, 'error')
                else:
                    artist = ArtistProfile(
                        name=name,
                        venue_id=venue_id,
                        website=request.form.get('website', '').strip() or None,
                        booth_number=booth_number,
                        services_provided=request.form.get('services_provided', '').strip() or None,
                    )
                    db.session.add(artist)
                    db.session.commit()
                    log_site('artist_create', 'success', f'artist_id={artist.id}')
                    flash('Artist profile created.', 'success')
                    return redirect(url_for('artist_management'))
        artists = restrict_to_visible_venues(db.session.query(ArtistProfile), ArtistProfile).order_by(ArtistProfile.name).all()
        return render_template('admin/artists.html', artists=artists, venues=venues, can_manage_venues=current_user.has_permission('venues.manage'))

    @app.route('/admin/venues/artists/<int:artist_id>/update', methods=['POST'])
    @login_required
    def update_artist(artist_id):
        require_permission('venues.manage')
        artist = db.session.get(ArtistProfile, artist_id)
        if not artist:
            abort(404)
        name = request.form.get('name', '').strip()
        if not name:
            flash('Artist name is required.', 'error')
        else:
            venue_id = int(request.form['venue_id']) if request.form.get('venue_id') else None
            booth_number = request.form.get('booth_number', '').strip() or None
            conflict = booth_number_conflict(venue_id, booth_number, artist_id=artist.id)
            if conflict:
                flash(conflict, 'error')
            else:
                artist.name = name
                artist.venue_id = venue_id
                artist.website = request.form.get('website', '').strip() or None
                artist.booth_number = booth_number
                artist.services_provided = request.form.get('services_provided', '').strip() or None
                db.session.commit()
                log_site('artist_update', 'success', f'artist_id={artist.id}')
                flash('Artist profile updated.', 'success')
        return redirect(url_for('artist_management'))

    @app.route('/admin/tournaments/<int:tid>/judges', methods=['GET','POST'])
    def assign_judges(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        head_judges = (
            db.session.query(User)
            .join(Role)
            .filter(Role.name == 'event head judge')
            .order_by(User.name)
            .all()
        )
        floor_judges = (
            db.session.query(User)
            .join(Role)
            .filter(Role.name == 'floor judge')
            .order_by(User.name)
            .all()
        )
        if request.method == 'POST':
            head_id = request.form.get('head_judge')
            floor_ids = request.form.getlist('floor_judges')
            t.head_judge_id = int(head_id) if head_id else None
            t.floor_judges = json.dumps([int(fid) for fid in floor_ids])
            db.session.commit()
            flash('Judges updated.', 'success')
            log_tournament(tid, 'assign_judges', 'success')
            return redirect(url_for('view_tournament', tid=tid))
        floor_set = set(t.floor_judge_ids())
        return render_template(
            'admin/judges.html',
            t=t,
            head_judges=head_judges,
            floor_judges=floor_judges,
            floor_set=floor_set,
        )

    @app.route('/admin/staff')
    def staff_management():
        require_permission('tournaments.manage')
        tournaments = db.session.query(Tournament).order_by(Tournament.start_time).all()
        data = []
        for t in tournaments:
            floor = []
            ids = t.floor_judge_ids()
            if ids:
                floor = db.session.query(User).filter(User.id.in_(ids)).all()
            data.append(
                {
                    't': t,
                    'head': t.head_judge,
                    'floor': floor,
                    'start': t.start_time,
                    'end': estimate_end_time(t),
                }
            )
        return render_template(
            'admin/staff.html',
            data=data,
            server_now=datetime.utcnow(),
        )

    @app.route('/admin/judges/<int:uid>/break', methods=['POST'])
    def judge_break(uid):
        require_permission('tournaments.manage')
        u = db.session.get(User, uid)
        minutes = request.form.get('minutes')
        if minutes:
            try:
                mins = int(minutes)
                u.break_end = datetime.utcnow() + timedelta(minutes=mins)
                flash(f'{u.name} on break for {mins} minutes.', 'success')
            except Exception:
                flash('Invalid break duration.', 'error')
        else:
            u.break_end = None
            flash(f'{u.name} break cleared.', 'success')
        db.session.commit()
        return redirect(url_for('staff_management'))

    def parse_date_input(value):
        value = (value or '').strip()
        if not value:
            return None
        try:
            return datetime.strptime(value, '%Y-%m-%d').date()
        except ValueError:
            return None

    def league_player_record(tournament, user_id):
        wins = draws = losses = 0
        entry = (
            db.session.query(TournamentPlayer)
            .filter_by(tournament_id=tournament.id, user_id=user_id)
            .first()
        )
        if not entry:
            return wins, draws, losses
        matches = (
            db.session.query(Match)
            .join(Round)
            .filter(Round.tournament_id == tournament.id)
            .filter(
                (Match.player1_id == entry.id) |
                (Match.player2_id == entry.id) |
                (Match.player3_id == entry.id) |
                (Match.player4_id == entry.id)
            )
            .all()
        )
        is_commander = (tournament.format or '').lower() == 'commander'
        for match in matches:
            if not match.completed or not match.result:
                continue
            result = match.result
            if match.player2_id is None:
                wins += 1
                continue
            if is_commander:
                if result.is_draw:
                    draws += 1
                    continue
                place = None
                if match.player1_id == entry.id:
                    place = result.p1_place
                elif match.player2_id == entry.id:
                    place = result.p2_place
                elif match.player3_id == entry.id:
                    place = result.p3_place
                elif match.player4_id == entry.id:
                    place = result.p4_place
                if place == 1:
                    wins += 1
                elif place:
                    losses += 1
                continue
            if result.player1_wins == result.player2_wins:
                draws += 1
            elif (result.player1_wins > result.player2_wins and match.player1_id == entry.id) or (
                result.player2_wins > result.player1_wins and match.player2_id == entry.id
            ):
                wins += 1
            else:
                losses += 1
        return wins, draws, losses

    def import_tournament_to_league(league, tournament):
        if tournament.league_id != league.id:
            tournament.league_id = league.id
        standings = compute_standings(tournament, db.session)
        imported = 0
        for row in standings:
            tp = row['tp']
            if not db.session.query(LeaguePlayer).filter_by(league_id=league.id, user_id=tp.user_id).first():
                db.session.add(LeaguePlayer(league_id=league.id, user_id=tp.user_id))
            result = (
                db.session.query(LeagueResult)
                .filter_by(league_id=league.id, tournament_id=tournament.id, user_id=tp.user_id)
                .first()
            )
            if not result:
                result = LeagueResult(league_id=league.id, tournament_id=tournament.id, user_id=tp.user_id)
            result.wins, result.draws, result.losses = league_player_record(tournament, tp.user_id)
            result.points = (result.wins * 3) + result.draws
            db.session.add(result)
            imported += 1
        db.session.commit()
        return imported

    def build_league_context(league):
        league_players = db.session.query(LeaguePlayer).filter_by(league_id=league.id).all()
        results = db.session.query(LeagueResult).filter_by(league_id=league.id).all()
        player_rows = []
        results_by_player = {}
        for result in results:
            results_by_player.setdefault(result.user_id, []).append(result)
        for lp in league_players:
            player_results = sorted(
                results_by_player.get(lp.user_id, []),
                key=lambda r: (r.points or 0, r.wins or 0, -(r.losses or 0)),
                reverse=True,
            )
            played = len(player_results)
            counted_count = math.ceil(played * 0.75) if played else 0
            counted = player_results[:counted_count]
            player_rows.append({
                'player': lp.user,
                'played': played,
                'counted_count': counted_count,
                'league_points': sum(r.points or 0 for r in counted),
                'raw_points': sum(r.points or 0 for r in player_results),
                'wins': sum(r.wins or 0 for r in counted),
                'draws': sum(r.draws or 0 for r in counted),
                'losses': sum(r.losses or 0 for r in counted),
            })
        player_rows.sort(key=lambda r: (-r['league_points'], -r['wins'], r['losses'], r['player'].name.lower()))
        league_tournament_ids = [t.id for t in league.tournaments]
        available_tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        users = db.session.query(User).order_by(User.name).all()
        return player_rows, results, available_tournaments, users, league_tournament_ids

    def league_vote_context(league):
        play_dates = db.session.query(LeaguePlayDate).filter_by(league_id=league.id).order_by(LeaguePlayDate.play_date).all()
        cubes = db.session.query(LeagueCube).filter_by(league_id=league.id).order_by(LeagueCube.title).all()
        totals = {
            (play_date_id, cube_id): total or 0
            for play_date_id, cube_id, total in (
                db.session.query(
                    LeagueCubeVote.play_date_id,
                    LeagueCubeVote.cube_id,
                    db.func.coalesce(db.func.sum(LeagueCubeVote.votes), 0),
                )
                .filter(LeagueCubeVote.league_id == league.id)
                .group_by(LeagueCubeVote.play_date_id, LeagueCubeVote.cube_id)
                .all()
            )
        }
        user_votes = {}
        if current_user.is_authenticated:
            user_votes = {
                (vote.play_date_id, vote.cube_id): vote.votes or 0
                for vote in db.session.query(LeagueCubeVote)
                .filter_by(league_id=league.id, user_id=current_user.id)
                .all()
            }
        available_by_date = {
            play_date.id: [link.cube_id for link in play_date.available_cubes]
            for play_date in play_dates
        }
        return play_dates, cubes, totals, user_votes, available_by_date

    def require_league_member_or_manager(league):
        if current_user.has_permission('tournaments.manage'):
            return True
        return db.session.query(LeaguePlayer).filter_by(league_id=league.id, user_id=current_user.id).first() is not None

    @app.route('/admin/leagues', methods=['GET', 'POST'])
    def leagues():
        require_permission('tournaments.manage')
        users = db.session.query(User).order_by(User.name).all()
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        if request.method == 'POST':
            name = request.form.get('name', '').strip()
            start_date = parse_date_input(request.form.get('start_date'))
            end_date = parse_date_input(request.form.get('end_date'))
            if not name:
                flash('League name is required.', 'error')
                return redirect(url_for('leagues'))
            league = League(name=name, start_date=start_date, end_date=end_date, is_cube_league=bool(request.form.get('is_cube_league')))
            db.session.add(league)
            db.session.flush()
            tournament_id = request.form.get('tournament_id')
            if tournament_id:
                tournament = db.session.get(Tournament, int(tournament_id))
                if tournament:
                    import_tournament_to_league(league, tournament)
                else:
                    db.session.commit()
            else:
                db.session.commit()
            flash('League created.', 'success')
            return redirect(url_for('league_detail', league_id=league.id))
        league_list = db.session.query(League).order_by(League.created_at.desc()).all()
        return render_template('admin/leagues.html', leagues=league_list, users=users, tournaments=tournaments)

    @app.route('/admin/leagues/<int:league_id>', methods=['GET', 'POST'])
    def league_detail(league_id):
        require_permission('tournaments.manage')
        league = db.session.get(League, league_id)
        if not league:
            abort(404)
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'add_players':
                added = 0
                for user_id in request.form.getlist('player_ids'):
                    if not db.session.query(LeaguePlayer).filter_by(league_id=league.id, user_id=int(user_id)).first():
                        db.session.add(LeaguePlayer(league_id=league.id, user_id=int(user_id)))
                        added += 1
                db.session.commit()
                flash(f'Added {added} players to the league.', 'success')
            elif action == 'import_tournament':
                tournament = db.session.get(Tournament, int(request.form.get('tournament_id') or 0))
                if tournament:
                    imported = import_tournament_to_league(league, tournament)
                    flash(f'Imported {imported} player results from {tournament.name}.', 'success')
                else:
                    flash('Select a tournament to import.', 'error')
            elif action == 'update_archetypes':
                for result in db.session.query(LeagueResult).filter_by(league_id=league.id).all():
                    result.deck_archetype = (request.form.get(f'archetype_{result.id}') or '').strip()
                db.session.commit()
                flash('Deck archetypes updated.', 'success')
            elif action == 'update_settings':
                league.is_cube_league = bool(request.form.get('is_cube_league'))
                db.session.commit()
                log_site('league_update', 'success', f'league_id={league.id}; cube={league.is_cube_league}')
                flash('League settings updated.', 'success')
            elif action == 'add_cube':
                if not league.is_cube_league:
                    flash('Enable cube league mode before adding Cube Cobra links.', 'error')
                else:
                    try:
                        url, title, image_url = fetch_cube_cobra_metadata(request.form.get('cube_url'))
                    except ValueError as exc:
                        flash(str(exc), 'error')
                    else:
                        db.session.add(LeagueCube(league_id=league.id, cube_cobra_url=url, title=title, image_url=image_url))
                        db.session.commit()
                        log_site('league_cube_add', 'success', f'league_id={league.id}; url={url}')
                        flash('Cube added.', 'success')
            elif action == 'add_play_date':
                if not league.is_cube_league:
                    flash('Enable cube league mode before adding League Events.', 'error')
                else:
                    play_date_value = parse_date_input(request.form.get('play_date'))
                    if not play_date_value:
                        flash('Choose a League Event date.', 'error')
                    elif db.session.query(LeaguePlayDate).filter_by(league_id=league.id, play_date=play_date_value).first():
                        flash('That League Event already exists.', 'error')
                    else:
                        play_date = LeaguePlayDate(league_id=league.id, play_date=play_date_value, is_active=bool(request.form.get('is_active', '1')))
                        db.session.add(play_date)
                        db.session.flush()
                        cube_ids = {int(cid) for cid in request.form.getlist('cube_ids') if cid.isdigit()}
                        for cube in db.session.query(LeagueCube).filter(LeagueCube.league_id == league.id, LeagueCube.id.in_(cube_ids)).all():
                            db.session.add(LeaguePlayDateCube(play_date_id=play_date.id, cube_id=cube.id))
                        db.session.commit()
                        log_site('league_play_date_add', 'success', f'league_id={league.id}; date={play_date_value}')
                        flash('League Event added.', 'success')
            elif action == 'update_play_date':
                play_date = db.session.get(LeaguePlayDate, int(request.form.get('play_date_id') or 0))
                if not play_date or play_date.league_id != league.id:
                    flash('League Event not found.', 'error')
                else:
                    play_date.is_active = bool(request.form.get('is_active'))
                    db.session.query(LeaguePlayDateCube).filter_by(play_date_id=play_date.id).delete()
                    cube_ids = {int(cid) for cid in request.form.getlist('cube_ids') if cid.isdigit()}
                    for cube in db.session.query(LeagueCube).filter(LeagueCube.league_id == league.id, LeagueCube.id.in_(cube_ids)).all():
                        db.session.add(LeaguePlayDateCube(play_date_id=play_date.id, cube_id=cube.id))
                    db.session.commit()
                    log_site('league_play_date_update', 'success', f'league_id={league.id}; play_date_id={play_date.id}')
                    flash('League Event updated.', 'success')
            elif action == 'delete_play_date':
                play_date = db.session.get(LeaguePlayDate, int(request.form.get('play_date_id') or 0))
                if not play_date or play_date.league_id != league.id:
                    flash('League Event not found.', 'error')
                else:
                    play_date_id = play_date.id
                    db.session.query(LeagueCubeVote).filter_by(play_date_id=play_date.id).delete()
                    db.session.query(LeaguePlayDateCube).filter_by(play_date_id=play_date.id).delete()
                    db.session.delete(play_date)
                    db.session.commit()
                    log_site('league_play_date_delete', 'success', f'league_id={league.id}; play_date_id={play_date_id}')
                    flash('League Event removed.', 'success')
            return redirect(url_for('league_detail', league_id=league.id))
        leaderboard, results, available_tournaments, users, league_tournament_ids = build_league_context(league)
        play_dates, cubes, cube_vote_totals, cube_user_votes, available_cube_ids = league_vote_context(league)
        return render_template(
            'admin/league_detail.html',
            league=league,
            leaderboard=leaderboard,
            results=results,
            available_tournaments=available_tournaments,
            users=users,
            league_tournament_ids=league_tournament_ids,
            play_dates=play_dates,
            cubes=cubes,
            cube_vote_totals=cube_vote_totals,
            cube_user_votes=cube_user_votes,
            available_cube_ids=available_cube_ids,
        )

    @app.route('/admin/leagues/<int:league_id>/delete', methods=['POST'])
    def delete_league(league_id):
        require_permission('tournaments.delete_leagues')
        league = db.session.get(League, league_id)
        if not league:
            abort(404)
        name = league.name
        tournament_count = db.session.query(Tournament).filter_by(league_id=league.id).update({'league_id': None})
        db.session.delete(league)
        db.session.commit()
        log_site('league_delete', 'success', f'league_id={league_id}; name={name}; tournaments_unlinked={tournament_count}')
        flash(f'Deleted league {name}.', 'success')
        return redirect(url_for('leagues'))

    @app.route('/my-leagues')
    @login_required
    def my_leagues():
        memberships = (
            db.session.query(LeaguePlayer)
            .join(League)
            .filter(LeaguePlayer.user_id == current_user.id)
            .order_by(League.created_at.desc())
            .all()
        )
        return render_template('my_leagues.html', memberships=memberships)

    @app.route('/leagues/<int:league_id>')
    @login_required
    def view_league(league_id):
        league = db.session.get(League, league_id)
        if not league:
            abort(404)
        if not require_league_member_or_manager(league):
            abort(403)
        leaderboard, results, _available_tournaments, _users, league_tournament_ids = build_league_context(league)
        play_dates, cubes, cube_vote_totals, _cube_user_votes, available_cube_ids = league_vote_context(league)
        return render_template(
            'league_view.html',
            league=league,
            leaderboard=leaderboard,
            results=results,
            league_tournament_ids=league_tournament_ids,
            play_dates=play_dates,
            cubes=cubes,
            cube_vote_totals=cube_vote_totals,
            available_cube_ids=available_cube_ids,
        )

    @app.route('/leagues/<int:league_id>/cubes', methods=['GET', 'POST'])
    @login_required
    def league_cube_voting(league_id):
        league = db.session.get(League, league_id)
        if not league or not league.is_cube_league:
            abort(404)
        if not require_league_member_or_manager(league):
            abort(403)
        if request.method == 'POST':
            for play_date in db.session.query(LeaguePlayDate).filter_by(league_id=league.id, is_active=True).all():
                available_ids = {link.cube_id for link in play_date.available_cubes}
                requested = {}
                total = 0
                for cube_id in available_ids:
                    raw = request.form.get(f'votes_{play_date.id}_{cube_id}', '0')
                    try:
                        count = max(0, min(3, int(raw)))
                    except ValueError:
                        count = 0
                    requested[cube_id] = count
                    total += count
                if total > 3:
                    flash(f'{play_date.play_date}: use no more than 3 total votes.', 'error')
                    return redirect(url_for('league_cube_voting', league_id=league.id))
                for cube_id, count in requested.items():
                    vote = db.session.query(LeagueCubeVote).filter_by(play_date_id=play_date.id, cube_id=cube_id, user_id=current_user.id).first()
                    if count:
                        if not vote:
                            vote = LeagueCubeVote(league_id=league.id, play_date_id=play_date.id, cube_id=cube_id, user_id=current_user.id)
                            db.session.add(vote)
                        vote.votes = count
                    elif vote:
                        db.session.delete(vote)
            db.session.commit()
            log_site('league_cube_vote', 'success', f'league_id={league.id}; user_id={current_user.id}')
            flash('Cube votes saved.', 'success')
            return redirect(url_for('league_cube_voting', league_id=league.id))
        play_dates, cubes, cube_vote_totals, cube_user_votes, available_cube_ids = league_vote_context(league)
        return render_template(
            'league_cubes.html',
            league=league,
            play_dates=play_dates,
            cubes=cubes,
            cube_vote_totals=cube_vote_totals,
            cube_user_votes=cube_user_votes,
            available_cube_ids=available_cube_ids,
        )

    @app.route('/admin/schedule')
    def schedule():
        require_permission('tournaments.manage')
        tournaments = db.session.query(Tournament).order_by(Tournament.start_time).all()
        entries = []
        for t in tournaments:
            entries.append({'t': t, 'start': t.start_time, 'end': estimate_end_time(t)})
        return render_template('admin/schedule.html', entries=entries)

    @app.route('/admin/schedule/export.csv')
    @login_required
    def export_schedule_csv():
        require_permission('tournaments.manage')
        tournaments = db.session.query(Tournament).order_by(Tournament.start_time).all()
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Tournament', 'Format', 'Rules Enforcement Level', 'Start Time', 'Estimated End'])
        for t in tournaments:
            est_end = estimate_end_time(t)
            writer.writerow([
                t.name,
                'Draft (Cube)' if t.format == 'Draft' and t.is_cube else t.format,
                t.rules_enforcement_level,
                t.start_time.isoformat() if t.start_time else '',
                est_end.isoformat() if est_end else '',
            ])
        output.seek(0)
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=schedule.csv'},
        )

    @app.route('/admin/register-player', methods=['GET', 'POST'])
    def admin_register_player():
        require_permission('tournaments.manage')
        from .models import User, Tournament, TournamentPlayer, Role
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            name = request.form.get('name', '').strip() or ' '.join(part for part in [first_name, last_name] if part).strip()
            password = request.form['password']
            password_confirm = request.form.get('password_confirm', '')
            if password != password_confirm:
                flash('Passwords do not match', 'error')
                log_site('admin_register_player', 'failure', 'password mismatch')
            elif db.session.query(User).filter_by(email=email).first():
                flash("Email already registered", "error")
                log_site('admin_register_player', 'failure', 'email exists')
            else:
                role_user = db.session.query(Role).filter_by(name='user').first()
                u = User(email=email, name=name, role=role_user)
                _set_user_name_parts(u, request.form.get('first_name'), request.form.get('last_name'), name)
                u.set_password(password)
                db.session.add(u)
                db.session.commit()
                tournament_id = request.form.get('tournament_id')
                if tournament_id:
                    tp = TournamentPlayer(tournament_id=int(tournament_id), user_id=u.id)
                    db.session.add(tp)
                    db.session.commit()
                    log_tournament(int(tournament_id), 'add_player', 'success')
                log_site('admin_register_player', 'success')
                flash("Player registered.", "success")
                return redirect(url_for('admin_register_player'))
        return render_template('admin/register_player.html', tournaments=tournaments)

    @app.route('/admin/bulk-register', methods=['GET', 'POST'])
    def admin_bulk_register():
        require_permission('tournaments.manage')
        from .models import User, Tournament, TournamentPlayer, Role
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        existing_users = db.session.query(User).order_by(User.name).all()
        if request.method == 'POST':
            tournament_id = request.form.get('tournament_id')
            selected_user_ids = request.form.getlist('existing_user_ids')
            names_raw = request.form.get('names', '')
            count = 0
            added_existing = 0
            existing_tournament_user_ids = set()
            if tournament_id:
                existing_tournament_user_ids = {
                    row.user_id
                    for row in db.session.query(TournamentPlayer).filter_by(tournament_id=int(tournament_id)).all()
                }
            for user_id_raw in selected_user_ids:
                if not tournament_id:
                    continue
                try:
                    user_id = int(user_id_raw)
                except ValueError:
                    continue
                if user_id in existing_tournament_user_ids:
                    continue
                if not db.session.get(User, user_id):
                    continue
                db.session.add(TournamentPlayer(tournament_id=int(tournament_id), user_id=user_id))
                existing_tournament_user_ids.add(user_id)
                added_existing += 1
            for line in names_raw.splitlines():
                name = line.strip()
                if not name:
                    continue
                role_user = db.session.query(Role).filter_by(name='user').first()
                u = User(name=name, role=role_user)
                _set_user_name_parts(u, fallback_name=name)
                db.session.add(u)
                db.session.flush()
                if tournament_id:
                    tp = TournamentPlayer(tournament_id=int(tournament_id), user_id=u.id)
                    db.session.add(tp)
                count += 1
            db.session.commit()
            if tournament_id:
                log_tournament(int(tournament_id), 'add_player', 'bulk', f'new={count}; existing={added_existing}')
            log_site('bulk_register', 'success', f'new={count}; existing={added_existing}')
            flash(f"Registered {count} new players and added {added_existing} existing players.", "success")
            return redirect(url_for('admin_bulk_register'))
        return render_template('admin/bulk_register_players.html', tournaments=tournaments, existing_users=existing_users)

    @app.route('/admin/site-settings', methods=['GET', 'POST'])
    @login_required
    def site_settings():
        require_permission('admin.site_settings')
        if request.method == 'POST':
            action = request.form.get('action')
            if action == 'settings':
                mode = request.form.get('registration_mode', 'open')
                if mode not in {'open', 'invite_only', 'closed'}:
                    mode = 'open'
                theme = request.form.get('site_theme')
                if theme is not None:
                    if theme not in {'light', 'dark'}:
                        theme = 'light'
                    set_site_setting('site_theme', theme)
                    current_user.color_mode = theme
                set_site_setting('registration_mode', mode)
                db.session.commit()
                details = f'registration_mode={mode}' + (f'; site_theme={theme}' if theme is not None else '')
                log_site('site_settings_update', 'success', details)
                flash('Site settings saved.', 'success')
            return redirect(url_for('site_settings'))
        return render_template(
            'admin/site_settings.html',
            registration_mode=registration_mode(),
        )

    @app.route('/admin/registration-invites', methods=['GET', 'POST'])
    @login_required
    def admin_registration_invites():
        require_permission('admin.site_settings')
        if request.method == 'POST':
            email = request.form.get('email', '').strip().lower()
            if not email:
                flash('Invite email is required.', 'error')
            elif db.session.query(User).filter_by(email=email).first():
                flash('That email already belongs to a user.', 'error')
            else:
                token = secrets.token_urlsafe(32)
                invite = RegistrationInvite(
                    email=email,
                    token_hash=_hash_registration_token(token),
                    created_by_id=current_user.id,
                    expires_at=datetime.utcnow() + timedelta(days=app.config.get('REGISTRATION_INVITE_TTL_DAYS', 14)),
                )
                db.session.add(invite)
                try:
                    _send_registration_invite(invite, token)
                except Exception as exc:
                    db.session.rollback()
                    log_site('registration_invite', 'failure', str(exc))
                    flash('Invite email could not be sent. Check mail settings.', 'error')
                    return redirect(url_for('admin_registration_invites'))
                db.session.commit()
                log_site('registration_invite', 'sent', f'invite_id={invite.id}; email={email}')
                flash('Registration invite sent.', 'success')
            return redirect(url_for('admin_registration_invites'))
        invites = db.session.query(RegistrationInvite).order_by(RegistrationInvite.created_at.desc()).all()
        return render_template('admin/registration_invites.html', invites=invites)

    @app.route('/admin/registration-invites/<int:invite_id>/revoke', methods=['POST'])
    @login_required
    def revoke_registration_invite(invite_id):
        require_permission('admin.site_settings')
        invite = db.session.get(RegistrationInvite, invite_id)
        if not invite:
            abort(404)
        if invite.used_at or invite.status == 'used':
            flash('Used invites cannot be revoked.', 'error')
        else:
            invite.status = 'revoked'
            db.session.commit()
            log_site('registration_invite_revoke', 'success', f'invite_id={invite.id}; email={invite.email}')
            flash('Registration invite revoked.', 'success')
        return redirect(url_for('admin_registration_invites'))

    @app.route('/admin/panel', methods=['GET', 'POST'])
    def admin_panel():
        require_admin()
        log_site('view_admin_panel', 'success')
        process = psutil.Process(os.getpid())
        db_path = db.engine.url.database
        db_size = os.path.getsize(db_path) if db_path and os.path.exists(db_path) else 0
        cpu_usage = psutil.cpu_percent(interval=0.1)
        mem_usage = process.memory_info().rss
        connections = len([c for c in psutil.net_connections() if c.status == psutil.CONN_ESTABLISHED])
        uptime_seconds = int((datetime.utcnow() - datetime.fromtimestamp(psutil.boot_time())).total_seconds())

        def fmt_bytes(num):
            for unit in ['B', 'KB', 'MB', 'GB', 'TB']:
                if num < 1024.0:
                    return f"{num:.2f} {unit}"
                num /= 1024.0
            return f"{num:.2f} PB"

        return render_template(
            'admin/panel.html',
            encryption_type='Werkzeug password hashing',
            db_size=fmt_bytes(db_size),
            ram_usage=fmt_bytes(mem_usage),
            cpu_usage=cpu_usage,
            connections=connections,
            uptime=uptime_seconds,
        )

    @app.route('/admin/backup', methods=['GET', 'POST'])
    def admin_backup():
        require_admin()
        if request.method == 'POST':
            upload = request.files.get('backup_file')
            overwrite = request.form.get('overwrite') == 'yes'
            backup_password = request.form.get('backup_password', '')
            if not upload or not upload.filename:
                flash('Choose a WaLTER backup JSON file to import.', 'error')
                return redirect(url_for('admin_backup'))
            try:
                payload = decode_backup_file(json.load(upload.stream), backup_password)
                counts = apply_backup_payload(payload, overwrite=overwrite)
            except Exception as exc:
                db.session.rollback()
                app.logger.warning('Backup import failed: %s', exc)
                log_site('backup_import', 'failure', str(exc))
                flash('Backup import failed. Please verify the file and password, then try again.', 'error')
                return redirect(url_for('admin_backup'))
            summary = ', '.join(f'{value} {key.replace("_", " ")}' for key, value in counts.items() if value)
            flash(f'Backup imported successfully. Updated {summary or "no records"}.', 'success')
            log_site('backup_import', 'success', summary or 'no records')
            return redirect(url_for('admin_backup'))

        roles_count = db.session.query(Role).count()
        users_count = db.session.query(User).count()
        tournaments_count = db.session.query(Tournament).count()
        return render_template(
            'admin/backup.html',
            roles_count=roles_count,
            users_count=users_count,
            tournaments_count=tournaments_count,
        )

    @app.route('/admin/backup/export', methods=['GET', 'POST'])
    def admin_backup_export():
        require_admin()
        password = request.form.get('export_password', '') if request.method == 'POST' else ''
        password_confirm = request.form.get('export_password_confirm', '') if request.method == 'POST' else ''
        if password or password_confirm:
            if password != password_confirm:
                flash('Backup encryption passwords do not match.', 'error')
                return redirect(url_for('admin_backup'))
            if len(password) < 8:
                flash('Backup encryption password must be at least 8 characters.', 'error')
                return redirect(url_for('admin_backup'))
        payload = export_backup_payload()
        encrypted = bool(password)
        if encrypted:
            payload = encrypt_backup_payload(payload, password)
        buffer = io.BytesIO(json.dumps(payload, indent=2, sort_keys=True).encode('utf-8'))
        suffix = 'encrypted-' if encrypted else ''
        filename = f"walter-backup-{suffix}{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}.json"
        log_site('backup_export', 'success', f'{filename}:encrypted={encrypted}')
        return send_file(
            buffer,
            mimetype='application/json',
            as_attachment=True,
            download_name=filename,
        )

    @app.route('/admin/permissions', methods=['GET', 'POST'])
    def permissions():
        require_permission('admin.permissions')
        log_site('view_permissions', 'success')
        if request.method == 'POST':
            name = request.form['name'].strip()
            level_raw = (request.form.get('level') or '').strip()
            try:
                level = int(level_raw)
            except ValueError:
                level = 500
            perms = {}
            for cat, items in PERMISSION_GROUPS.items():
                for perm in items:
                    key = f"{cat}.{perm}"
                    perms[key] = bool(request.form.get(key))
            role = Role(name=name, permissions=json.dumps(perms), level=level)
            db.session.add(role)
            db.session.commit()
            flash('Role created.', 'success')
            log_site('role_create', 'success', name)
            return redirect(url_for('permissions'))
        roles = db.session.query(Role).order_by(Role.level, Role.name).all()
        return render_template('admin/permissions.html', roles=roles, permission_groups=PERMISSION_GROUPS)

    @app.route('/admin/api-logs')
    def admin_api_logs():
        require_admin()
        log_site('view_api_logs', 'success')
        logs = db.session.query(ApiLog).order_by(ApiLog.timestamp.desc()).limit(500).all()
        user_ids = {log.api_user_id for log in logs if log.api_user_id}
        users = {u.id: u for u in db.session.query(User).filter(User.id.in_(user_ids)).all()} if user_ids else {}
        return render_template('admin/api_logs.html', logs=logs, users=users)

    @app.route('/admin/logs')
    def site_logs():
        require_admin()
        log_site('view_site_logs', 'success')
        logs = db.session.query(SiteLog).order_by(SiteLog.timestamp.desc()).all()
        for l in logs:
            l.user = db.session.get(User, l.user_id) if l.user_id else None
        return render_template('admin/site_logs.html', logs=logs)

    @app.route('/admin/security/bad-logins')
    def admin_bad_logins():
        require_permission('admin.login_audit')
        log_site('view_bad_login_audit', 'success')
        attempts = db.session.query(BadLoginAttempt).order_by(BadLoginAttempt.created_at.desc()).all()
        return render_template('admin/bad_logins.html', attempts=attempts)

    @app.route('/admin/security/ip-blacklist')
    def admin_ip_blacklist():
        require_permission('admin.ip_blacklist')
        log_site('view_ip_blacklist', 'success')
        ips = db.session.query(BlacklistedIP).order_by(BlacklistedIP.created_at.desc()).all()
        return render_template('admin/ip_blacklist.html', ips=ips)

    @app.route('/admin/security/ip-blacklist/<int:ip_id>/toggle', methods=['POST'])
    def admin_toggle_ip_blacklist(ip_id):
        require_permission('admin.ip_blacklist')
        item = db.session.get(BlacklistedIP, ip_id)
        if not item:
            abort(404)
        item.is_active = not item.is_active
        db.session.commit()
        log_site('ip_blacklist_toggle', 'success', f'ip={item.ip_address}; active={item.is_active}')
        flash('IP blacklist entry updated.', 'success')
        return redirect(url_for('admin_ip_blacklist'))

    @app.route('/admin/security/ip-blacklist/export')
    def admin_export_ip_blacklist():
        require_permission('admin.ip_blacklist')
        log_site('export_ip_blacklist', 'success')
        ips = db.session.query(BlacklistedIP).filter_by(is_active=True).order_by(BlacklistedIP.ip_address).all()
        lines = [f'iptables -A INPUT -s {item.ip_address} -j DROP' for item in ips]
        output = '\n'.join(lines) + ('\n' if lines else '')
        return Response(
            output,
            mimetype='text/plain',
            headers={'Content-Disposition': 'attachment; filename=walter_bad_ips_iptables.sh'},
        )

    @app.route('/admin/current-connections')
    def admin_current_connections():
        require_admin()
        cutoff = datetime.utcnow() - timedelta(minutes=30)
        connections = [
            item for item in CURRENT_CONNECTIONS.values()
            if item.get('last_seen') and item['last_seen'] >= cutoff
        ]
        connections.sort(key=lambda item: item['last_seen'], reverse=True)
        log_site('view_current_connections', 'success')
        return render_template('admin/current_connections.html', connections=connections)

    @app.route('/admin/current-connections/blacklist', methods=['POST'])
    def admin_blacklist_connection():
        require_permission('admin.ip_blacklist')
        ip_address = (request.form.get('ip_address') or '').strip()
        if not ip_address:
            flash('Missing IP address.', 'error')
            return redirect(url_for('admin_current_connections'))
        item = db.session.query(BlacklistedIP).filter_by(ip_address=ip_address).first()
        if not item:
            item = BlacklistedIP(ip_address=ip_address, created_by_id=current_user.id)
            db.session.add(item)
        item.is_active = True
        item.reason = request.form.get('reason') or 'Blacklisted from current connections'
        if not item.created_by_id:
            item.created_by_id = current_user.id
        db.session.commit()
        log_site('ip_blacklist_connection', 'success', f'ip={ip_address}')
        flash(f'{ip_address} has been blacklisted.', 'success')
        return redirect(url_for('admin_current_connections'))

    @app.route('/admin/tournaments/bulk', methods=['POST'])
    @login_required
    def bulk_edit_tournaments():
        if not (
            current_user.has_permission('tournaments.bulk_manage')
            or current_user.has_permission('tournaments.manage')
        ):
            log_site('unauthorized_access', 'failure', 'tournaments.bulk_manage')
            abort(403)
        raw_ids = request.form.getlist('tournament_ids')
        tournament_ids = []
        seen_tournament_ids = set()
        for raw_id in raw_ids:
            try:
                tournament_id = int(raw_id)
            except (TypeError, ValueError):
                continue
            if tournament_id in seen_tournament_ids:
                continue
            seen_tournament_ids.add(tournament_id)
            tournament_ids.append(tournament_id)
        action = (request.form.get('bulk_action') or '').strip()
        if not tournament_ids:
            flash('Select at least one tournament.', 'error')
            return redirect(url_for('index'))
        tournaments = db.session.query(Tournament).filter(Tournament.id.in_(tournament_ids)).all()
        tournament_by_id = {t.id: t for t in tournaments}
        ordered_tournaments = [tournament_by_id[tid] for tid in tournament_ids if tid in tournament_by_id]
        count = 0
        now = datetime.utcnow()
        user_id = current_user.id if current_user.is_authenticated else None
        audit_entries = []
        if action == 'start':
            for tournament in ordered_tournaments:
                tournament.started_at = now
                if not tournament.start_time:
                    tournament.start_time = now
                    tournament.name = format_tournament_name(
                        tournament.format,
                        tournament.start_time,
                        extract_provided_tournament_name(tournament.name),
                    )
                tournament.ended_at = None
                audit_entries.append({
                    'tournament_id': tournament.id,
                    'tournament_action': 'bulk_start',
                    'site_action': 'bulk_start_tournament',
                    'site_error': f'tournament_id={tournament.id}',
                })
                count += 1
        elif action == 'end':
            for tournament in ordered_tournaments:
                tournament.ended_at = now
                tournament.round_timer_end = None
                tournament.draft_timer_end = None
                tournament.deck_timer_end = None
                audit_entries.append({
                    'tournament_id': tournament.id,
                    'tournament_action': 'bulk_end',
                    'site_action': 'bulk_end_tournament',
                    'site_error': f'tournament_id={tournament.id}',
                })
                count += 1
        elif action == 'delete':
            for tournament in ordered_tournaments:
                tid = tournament.id
                name = tournament.name
                audit_entries.append({
                    'tournament_id': tid,
                    'tournament_action': 'bulk_delete',
                    'site_action': 'bulk_delete_tournament',
                    'site_error': f'tournament_id={tid}; name={name}',
                })
                db.session.delete(tournament)
                count += 1
        else:
            flash('Choose a bulk action.', 'error')
            return redirect(url_for('index'))
        try:
            db.session.commit()
        except SQLAlchemyError as exc:
            db.session.rollback()
            app.logger.exception('Bulk tournament action failed: %s', exc)
            flash('Bulk action failed. Please try again or review the selected tournaments.', 'error')
            return redirect(url_for('index'))

        if audit_entries:
            try:
                for entry in audit_entries:
                    db.session.add(TournamentLog(
                        tournament_id=entry['tournament_id'],
                        action=entry['tournament_action'],
                        result='success',
                        user_id=user_id,
                    ))
                    db.session.add(SiteLog(
                        action=entry['site_action'],
                        result='success',
                        error=entry['site_error'],
                        user_id=user_id,
                    ))
                db.session.commit()
            except Exception as exc:
                db.session.rollback()
                app.logger.exception(
                    'Bulk tournament audit logging failed after action commit: user_id=%s action=%s tournament_ids=%s error=%s',
                    user_id,
                    action,
                    [entry['tournament_id'] for entry in audit_entries],
                    exc,
                )

        flash(f'Bulk action applied to {count} tournament' + ('s' if count != 1 else '') + '.', 'success')
        return redirect(url_for('index'))

    @app.route('/admin/tournaments/<int:tid>/complete', methods=['POST'])
    def complete_tournament(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        now = datetime.utcnow()
        t.manually_completed = True
        t.ended_at = t.ended_at or now
        t.round_timer_end = None
        t.draft_timer_end = None
        t.deck_timer_end = None
        db.session.commit()
        flash('Tournament marked complete.', 'success')
        log_site('complete_tournament', 'success', f'tournament_id={tid}')
        log_tournament(tid, 'complete', 'success')
        return redirect(request.referrer or url_for('index'))

    @app.route('/admin/tournaments/<int:tid>/reopen', methods=['POST'])
    def reopen_tournament(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        t.manually_completed = False
        t.ended_at = None
        db.session.commit()
        flash('Tournament reopened.', 'success')
        log_site('reopen_tournament', 'success', f'tournament_id={tid}')
        log_tournament(tid, 'reopen', 'success')
        return redirect(request.referrer or url_for('view_tournament', tid=tid))

    @app.route('/admin/tournaments/<int:tid>/delete', methods=['POST'])
    def delete_tournament(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        db.session.delete(t)
        db.session.commit()
        flash("Tournament deleted.", "success")
        log_site('delete_tournament', 'success', t.name)
        log_tournament(tid, 'delete', 'success')
        return redirect(url_for('index'))

    # ---------- Tournament ----------

    @app.route('/my-tournaments')
    @login_required
    def my_tournaments():
        entries = (
            db.session.query(TournamentPlayer)
            .join(Tournament)
            .filter(TournamentPlayer.user_id == current_user.id)
            .order_by(Tournament.start_time.desc().nullslast(), Tournament.created_at.desc())
            .all()
        )
        active_entries = [entry for entry in entries if not tournament_is_complete(entry.tournament)]
        player_counts = {entry.tournament_id: len(entry.tournament.players) for entry in active_entries}
        return render_template(
            'tournament/my_tournaments.html',
            entries=active_entries,
            player_counts=player_counts,
            server_now=datetime.utcnow(),
        )

    @app.route('/t/<int:tid>')
    def view_tournament(tid):
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        players = db.session.query(TournamentPlayer).filter_by(tournament_id=tid).all()
        rounds = db.session.query(Round).filter_by(tournament_id=tid).order_by(Round.number).all()
        standings = compute_standings(t, db.session)
        rec_rounds = recommended_rounds(len(players))
        floor_judges = []
        floor_judge_ids = t.floor_judge_ids() or []
        if floor_judge_ids:
            floor_judges = db.session.query(User).filter(User.id.in_(floor_judge_ids)).all()
        assigned_judge_ids = set(floor_judge_ids)
        if t.head_judge_id:
            assigned_judge_ids.add(t.head_judge_id)
        is_player = False
        show_passcode = False
        pending_join_requests = []
        user_join_request = None
        player_deck = None
        can_view_player_decks = False
        available_users = []
        if current_user.is_authenticated:
            is_player = any(p.user_id == current_user.id for p in players)
            show_passcode = current_user.has_permission('tournaments.manage') or is_player
            if t.join_requires_approval:
                user_join_request = (
                    db.session.query(TournamentJoinRequest)
                    .filter_by(tournament_id=tid, user_id=current_user.id)
                    .order_by(TournamentJoinRequest.created_at.desc())
                    .first()
                )
            if current_user.has_permission('tournaments.approve_join'):
                pending_join_requests = (
                    db.session.query(TournamentJoinRequest)
                    .filter_by(tournament_id=tid, status='pending')
                    .order_by(TournamentJoinRequest.created_at.asc())
                    .all()
                )
            if is_player:
                for player in players:
                    if player.user_id == current_user.id:
                        player_deck = player.deck
                        break
            can_view_player_decks = user_can_view_player_decks(
                current_user,
                t,
                assigned_judge_ids=assigned_judge_ids,
            )
        timer_end = None
        timer_type = None
        timer_remaining = None
        if t.round_timer_end:
            timer_end = t.round_timer_end
            timer_type = 'round'
        elif t.draft_timer_end:
            timer_end = t.draft_timer_end
            timer_type = 'draft'
        elif t.deck_timer_end:
            timer_end = t.deck_timer_end
            timer_type = 'deck'
        elif t.round_timer_remaining:
            timer_type = 'round'
            timer_remaining = t.round_timer_remaining
        elif t.draft_timer_remaining:
            timer_type = 'draft'
            timer_remaining = t.draft_timer_remaining
        elif t.deck_timer_remaining:
            timer_type = 'deck'
            timer_remaining = t.deck_timer_remaining
        deck_locked = any(r.number == 1 for r in rounds)
        deck_state = {
            'main': player_deck.mainboard_cards() if player_deck else [],
            'side': player_deck.sideboard_cards() if player_deck else [],
            'submitted': bool(player_deck and player_deck.is_submitted),
        }
        if current_user.is_authenticated and current_user.has_permission('tournaments.manage'):
            player_user_ids = {player.user_id for player in players}
            user_query = db.session.query(User)
            if player_user_ids:
                user_query = user_query.filter(~User.id.in_(player_user_ids))
            available_users = user_query.order_by(User.name).all()
        table_start, table_end, table_count, _ = compute_table_allocation(t)
        return render_template('tournament/view.html', t=t, players=players, rounds=rounds,
                               standings=standings, rec_rounds=rec_rounds,
                               table_range=_format_table_range(table_start, table_end, table_count),
                               timer_end=timer_end, timer_type=timer_type,
                               timer_remaining=timer_remaining,
                               is_player=is_player, show_passcode=show_passcode,
                               floor_judges=floor_judges,
                               pending_join_requests=pending_join_requests,
                               user_join_request=user_join_request,
                               player_deck=player_deck,
                               deck_state=deck_state,
                               deck_locked=deck_locked,
                               deck_search_url=url_for('deck_card_search', tid=t.id) if is_player and not deck_locked else None,
                               can_view_player_decks=can_view_player_decks,
                               available_users=available_users,
                               server_now=datetime.utcnow())

    @app.route('/t/<int:tid>/decklists')
    @login_required
    def tournament_decklists(tid):
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        if not user_can_view_player_decks(current_user, t):
            abort(403)
        players = db.session.query(TournamentPlayer).filter_by(tournament_id=tid).order_by(TournamentPlayer.id).all()
        deck_rows = []
        for player in players:
            deck = player.deck
            main_cards = deck.mainboard_cards() if deck else []
            side_cards = deck.sideboard_cards() if deck else []
            max_len = max(len(main_cards), len(side_cards), 1)
            rows = []
            for index in range(max_len):
                rows.append({
                    'main': main_cards[index] if index < len(main_cards) else None,
                    'side': side_cards[index] if index < len(side_cards) else None,
                })
            deck_rows.append({'player': player, 'deck': deck, 'rows': rows})
        return render_template('tournament/decklists.html', t=t, deck_rows=deck_rows)

    @app.route('/t/<int:tid>/players/<int:player_id>/deck')
    @login_required
    def view_player_deck(tid, player_id):
        from .models import TournamentPlayer

        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        player = db.session.get(TournamentPlayer, player_id)
        if not player or player.tournament_id != tid:
            abort(404)
        if not (
            user_can_view_player_decks(current_user, t)
            or current_user.id == player.user_id
        ):
            abort(403)
        sort_mode = request.args.get('sort', 'name')
        deck = player.deck
        main_cards = deck.mainboard_cards() if deck else []
        side_cards = deck.sideboard_cards() if deck else []
        metadata = {}
        if deck:
            try:
                db_path = ensure_card_database_ready()
            except Exception:
                db_path = None
            if db_path:
                names = [card.get('name') for card in main_cards + side_cards if card.get('name')]
                if names:
                    metadata = card_db.get_card_metadata(db_path, names)

        def _sort_key(card):
            name = card.get('name', '')
            if sort_mode == 'type':
                info = metadata.get(name, {})
                primary = info.get('primary_type') or ''
                order = TYPE_SORT_INDEX.get(primary, len(TYPE_SORT_ORDER))
                return (order, primary.lower(), name.lower())
            return (name.lower(),)

        if sort_mode in ('name', 'type'):
            main_cards = sorted(main_cards, key=_sort_key)
            side_cards = sorted(side_cards, key=_sort_key)
        return render_template(
            'tournament/player_deck.html',
            t=t,
            player=player,
            deck=deck,
            main_cards=main_cards,
            side_cards=side_cards,
            sort_mode=sort_mode,
            card_metadata=metadata,
        )

    @app.route('/t/<int:tid>/deck/search')
    @login_required
    def deck_card_search(tid):
        from .models import Tournament

        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        tp = get_player_entry(tid, current_user.id)
        if not tp and not current_user.has_permission('tournaments.manage'):
            abort(403)
        query = (request.args.get('q') or '').strip()
        if len(query) < 2:
            return jsonify(results=[])
        try:
            path = ensure_card_database_ready()
        except Exception as exc:
            app.logger.warning('Card database unavailable during deck search: %s', exc)
            return jsonify(error='Card database unavailable.', results=[]), 503
        results = card_db.search_cards(path, query, limit=20)
        return jsonify(results=results)

    @app.route('/t/<int:tid>/deck/manual', methods=['POST'])
    @login_required
    def upload_manual_deck(tid):
        from .models import Tournament

        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        tp = get_player_entry(tid, current_user.id)
        if not tp:
            abort(403)
        if deck_modifications_locked(t):
            flash('Deck changes are locked after round one pairings.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        action = (request.form.get('action') or 'save').lower()
        submission_requested = action == 'submit'
        deck_json_raw = request.form.get('deck_json')
        deck_text = (request.form.get('deck_text') or '').strip()
        parse_errors = []
        if deck_json_raw:
            try:
                deck_payload = json.loads(deck_json_raw)
            except ValueError:
                flash('Unable to read deck data.', 'error')
                return redirect(url_for('view_tournament', tid=tid))
            main_entries, side_entries, json_errors = parse_deck_json(deck_payload)
            parse_errors.extend(json_errors)
            raw_text = None
        else:
            if not deck_text:
                flash('Deck list cannot be empty.', 'error')
                return redirect(url_for('view_tournament', tid=tid))
            main_entries, side_entries, text_errors = parse_counted_sections(deck_text)
            parse_errors.extend(text_errors)
            raw_text = deck_text
        if parse_errors:
            for message in parse_errors:
                flash(message, 'error')
        try:
            db_path = ensure_card_database_ready()
        except Exception as exc:
            app.logger.warning('Card database unavailable during manual deck upload: %s', exc)
            flash('Card database unavailable. Please try again later.', 'error')
            log_tournament(tid, 'deck_manual', 'failure', str(exc))
            return redirect(url_for('view_tournament', tid=tid))
        canonical_main, missing_main = canonicalize_card_group(main_entries, db_path=db_path)
        canonical_side, missing_side = canonicalize_card_group(side_entries, db_path=db_path)
        missing = missing_main + missing_side
        missing_set = sorted({name for name in missing}) if missing else []
        if missing_set:
            flash('Unknown card(s) ignored: ' + ', '.join(missing_set), 'error')
        validation_errors = []
        submission_success = False
        if submission_requested:
            validation_errors = validate_deck_lists(canonical_main, canonical_side, db_path)
            for message in validation_errors:
                flash(message, 'error')
            if parse_errors or missing_set or validation_errors:
                flash('Deck saved but submission requirements not met.', 'error')
            else:
                submission_success = True
        save_player_deck(
            tp,
            'manual',
            canonical_main,
            canonical_side,
            raw_text=raw_text,
            submitted=submission_success,
        )
        if submission_success:
            flash('Deck submitted.', 'success')
        else:
            flash('Deck list saved.', 'success')
        log_detail = 'submitted' if submission_success else 'saved'
        if parse_errors:
            log_detail += '; parse_errors'
        if missing_set:
            log_detail += '; missing=' + ', '.join(missing_set)
        if validation_errors:
            log_detail += '; validation=' + ' | '.join(validation_errors)
        log_tournament(tid, 'deck_manual', 'success', log_detail)
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/deck/mtgo', methods=['POST'])
    @login_required
    def upload_mtgo_deck(tid):
        from .models import Tournament

        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        tp = get_player_entry(tid, current_user.id)
        if not tp:
            abort(403)
        if deck_modifications_locked(t):
            flash('Deck changes are locked after round one pairings.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        upload = request.files.get('mtgo_file')
        if not upload or not upload.filename:
            flash('Choose an MTGO deck file to upload.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        file_bytes = upload.read()
        if not file_bytes:
            flash('The uploaded deck file is empty.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        try:
            text = file_bytes.decode('utf-8')
        except UnicodeDecodeError:
            text = file_bytes.decode('latin-1', errors='ignore')
        main_entries, side_entries, parse_errors = parse_mtgo_deck_text(text)
        if parse_errors:
            for message in parse_errors:
                flash(message, 'error')
        if not main_entries and not side_entries:
            flash('The uploaded deck file does not contain any cards.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        try:
            db_path = ensure_card_database_ready()
        except Exception as exc:
            app.logger.warning('Card database unavailable during MTGO deck upload: %s', exc)
            flash('Card database unavailable. Please try again later.', 'error')
            log_tournament(tid, 'deck_mtgo', 'failure', str(exc))
            return redirect(url_for('view_tournament', tid=tid))
        canonical_main, missing_main = canonicalize_card_group(main_entries, db_path=db_path)
        canonical_side, missing_side = canonicalize_card_group(side_entries, db_path=db_path)
        missing = missing_main + missing_side
        missing_set = sorted({name for name in missing}) if missing else []
        if missing_set:
            flash('Cards not found in local database: ' + ', '.join(missing_set), 'error')
        save_player_deck(tp, 'mtgo', canonical_main, canonical_side, raw_text=text, submitted=False)
        flash('MTGO deck file imported.', 'success')
        log_detail = 'imported'
        if parse_errors:
            log_detail += '; parse_errors'
        if missing_set:
            log_detail += '; missing=' + ', '.join(missing_set)
        log_tournament(tid, 'deck_mtgo', 'success', log_detail)
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/deck/image', methods=['POST'])
    @login_required
    def upload_deck_image(tid):
        from .models import Tournament

        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        if (t.format or '').lower() != 'draft':
            flash('Deck images are only available for draft events.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        tp = get_player_entry(tid, current_user.id)
        if not tp:
            abort(403)
        upload = request.files.get('deck_image')
        if not upload or not upload.filename:
            flash('Select an image to upload.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        filename = sanitize_image_upload(upload, prefix=f'deck{tid}')
        if not filename:
            flash('Unable to process the image upload.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        update_deck_image(tp, filename)
        flash('Deck image uploaded.', 'success')
        log_tournament(tid, 'deck_image', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/deck/image/delete', methods=['POST'])
    @login_required
    def delete_deck_image(tid):
        from .models import Tournament

        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        if (t.format or '').lower() != 'draft':
            flash('Deck images are only available for draft events.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        tp = get_player_entry(tid, current_user.id)
        if not tp:
            abort(403)
        deck = tp.deck
        if not deck or not deck.image_path:
            flash('No deck image to delete.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        update_deck_image(tp, None)
        flash('Deck image deleted.', 'success')
        log_tournament(tid, 'deck_image', 'deleted')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/join', methods=['POST'])
    @login_required
    def join_tournament(tid):
        require_permission('tournaments.join')
        if current_user.is_admin or (current_user.role and current_user.role.name != 'user'):
            abort(403)
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        tp = db.session.query(TournamentPlayer).filter_by(tournament_id=tid, user_id=current_user.id).first()
        if tp:
            flash("Already joined", "info")
            log_tournament(tid, 'join', 'already joined')
            log_site('join_tournament', 'already joined')
        else:
            code = request.form.get('passcode', '')
            if t.passcode and code != t.passcode:
                flash("Invalid passcode", "error")
                log_tournament(tid, 'join', 'failure', 'invalid passcode')
                log_site('join_tournament', 'failure', 'invalid passcode')
                return redirect(url_for('view_tournament', tid=tid))
            if not tournament_has_capacity(t):
                flash('Tournament is at its player cap.', 'error')
                log_tournament(tid, 'join', 'failure', 'player cap reached')
                return redirect(url_for('view_tournament', tid=tid))
            if t.join_requires_approval:
                existing_request = (
                    db.session.query(TournamentJoinRequest)
                    .filter_by(tournament_id=tid, user_id=current_user.id, status='pending')
                    .first()
                )
                if existing_request:
                    flash('Your join request is pending approval.', 'info')
                else:
                    join_request = TournamentJoinRequest(
                        tournament_id=tid,
                        user_id=current_user.id,
                    )
                    db.session.add(join_request)
                    db.session.commit()
                    flash('Join request submitted for approval.', 'success')
                    log_tournament(tid, 'join_request', 'submitted')
                    log_site('join_request', 'submitted')
                return redirect(url_for('view_tournament', tid=tid))
            tp = TournamentPlayer(tournament_id=tid, user_id=current_user.id)
            db.session.add(tp)
            pending_requests = (
                db.session.query(TournamentJoinRequest)
                .filter_by(tournament_id=tid, user_id=current_user.id, status='pending')
                .all()
            )
            for req in pending_requests:
                req.status = 'approved'
                req.note = 'Auto-approved when approval disabled.'
            db.session.commit()
            flash("Joined tournament", "success")
            log_tournament(tid, 'join', 'success')
            log_site('join_tournament', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/join-requests/<int:req_id>/approve', methods=['POST'])
    @login_required
    def approve_join_request(tid, req_id):
        require_permission('tournaments.approve_join')
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        join_request = db.session.get(TournamentJoinRequest, req_id)
        if not join_request or join_request.tournament_id != tid:
            abort(404)
        if join_request.status != 'pending':
            flash('Request already processed.', 'info')
            return redirect(url_for('view_tournament', tid=tid))
        existing = (
            db.session.query(TournamentPlayer)
            .filter_by(tournament_id=tid, user_id=join_request.user_id)
            .first()
        )
        if not existing:
            if not tournament_has_capacity(t):
                flash('Tournament is at its player cap.', 'error')
                return redirect(url_for('view_tournament', tid=tid))
            tp = TournamentPlayer(tournament_id=tid, user_id=join_request.user_id)
            db.session.add(tp)
        note = (request.form.get('note') or '').strip()
        join_request.status = 'approved'
        join_request.approved_by_id = current_user.id
        join_request.note = note or None
        db.session.commit()
        flash('Join request approved.', 'success')
        log_tournament(tid, 'join_request', 'approved', f'user_id={join_request.user_id}')
        log_site('join_request_approve', 'success', f'id={req_id}')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/join-requests/<int:req_id>/reject', methods=['POST'])
    @login_required
    def reject_join_request(tid, req_id):
        require_permission('tournaments.approve_join')
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        join_request = db.session.get(TournamentJoinRequest, req_id)
        if not join_request or join_request.tournament_id != tid:
            abort(404)
        if join_request.status != 'pending':
            flash('Request already processed.', 'info')
            return redirect(url_for('view_tournament', tid=tid))
        note = (request.form.get('note') or '').strip()
        join_request.status = 'rejected'
        join_request.approved_by_id = current_user.id
        join_request.note = note or None
        db.session.commit()
        flash('Join request rejected.', 'info')
        log_tournament(tid, 'join_request', 'rejected', f'user_id={join_request.user_id}')
        log_site('join_request_reject', 'success', f'id={req_id}')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/players/add', methods=['POST'])
    @login_required
    def add_player_to_tournament(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        selected_user_ids = request.form.getlist('user_ids')
        user_id_raw = (request.form.get('user_id') or '').strip()
        if user_id_raw and user_id_raw not in selected_user_ids:
            selected_user_ids.append(user_id_raw)
        new_name = (request.form.get('new_player_name') or '').strip()
        new_email = (request.form.get('new_player_email') or '').strip().lower()
        created_user = False
        added_existing = 0
        skipped_existing = 0
        if selected_user_ids:
            existing_user_ids = {p.user_id for p in t.players}
            for raw_id in selected_user_ids:
                try:
                    user_id = int(raw_id)
                except (TypeError, ValueError):
                    skipped_existing += 1
                    continue
                if user_id in existing_user_ids:
                    skipped_existing += 1
                    continue
                player = db.session.get(User, user_id)
                if not player:
                    skipped_existing += 1
                    continue
                if not tournament_has_capacity(t, slots=added_existing + 1):
                    skipped_existing += 1
                    continue
                db.session.add(TournamentPlayer(tournament_id=tid, user_id=player.id))
                existing_user_ids.add(player.id)
                added_existing += 1
            if added_existing:
                db.session.commit()
                log_tournament(tid, 'add_player_inline', 'success', f'existing_count={added_existing}')
                message = f'Added {added_existing} existing player' + ('s' if added_existing != 1 else '') + ' to tournament.'
                if skipped_existing:
                    message += f' Skipped {skipped_existing} invalid or duplicate selection' + ('s' if skipped_existing != 1 else '') + '.'
                flash(message, 'success')
                return redirect(url_for('view_tournament', tid=tid))
            flash('No new existing players were selected.', 'warning')
            return redirect(url_for('view_tournament', tid=tid))
        if new_name:
            email_value = new_email or None
            if email_value and db.session.query(User).filter_by(email=email_value).first():
                flash('Email already registered.', 'error')
                return redirect(url_for('view_tournament', tid=tid))
            role_user = db.session.query(Role).filter_by(name='user').first()
            player = User(name=new_name, email=email_value, role=role_user)
            _set_user_name_parts(player, fallback_name=new_name)
            db.session.add(player)
            db.session.flush()
            created_user = True
        else:
            flash('Select existing users or enter a name to add a new player.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        existing = (
            db.session.query(TournamentPlayer)
            .filter_by(tournament_id=tid, user_id=player.id)
            .first()
        )
        if existing:
            if created_user:
                db.session.rollback()
            flash('Player is already registered for this tournament.', 'warning')
            return redirect(url_for('view_tournament', tid=tid))
        if not tournament_has_capacity(t):
            if created_user:
                db.session.rollback()
            flash('Tournament is at its player cap.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        tp = TournamentPlayer(tournament_id=tid, user_id=player.id)
        db.session.add(tp)
        db.session.commit()
        log_tournament(tid, 'add_player_inline', 'success', f'user_id={player.id}')
        flash('Player added to tournament.', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/players/<int:player_id>/replace', methods=['POST'])
    @login_required
    def replace_tournament_player(tid, player_id):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        entry = db.session.get(TournamentPlayer, player_id)
        if not entry or entry.tournament_id != tid:
            abort(404)
        try:
            replacement_user_id = int(request.form.get('replacement_user_id') or 0)
        except (TypeError, ValueError):
            replacement_user_id = 0
        replacement = db.session.get(User, replacement_user_id)
        if not replacement:
            flash('Choose a replacement player.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        existing = db.session.query(TournamentPlayer).filter_by(tournament_id=tid, user_id=replacement.id).first()
        if existing and existing.id != entry.id:
            flash('Replacement player is already in this tournament.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        old_user_id = entry.user_id
        entry.user_id = replacement.id
        db.session.commit()
        log_tournament(tid, 'replace_player', 'success', f'old_user_id={old_user_id}; new_user_id={replacement.id}; ended={bool(t.ended_at)}')
        flash('Tournament player replaced.', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/logs')
    def tournament_logs(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        log_tournament(tid, 'view_logs', 'success')
        logs = db.session.query(TournamentLog).filter_by(tournament_id=tid).order_by(TournamentLog.timestamp.desc()).all()
        for l in logs:
            l.user = db.session.get(User, l.user_id) if l.user_id else None
        return render_template('tournament/logs.html', t=t, logs=logs)

    @app.route('/t/<int:tid>/start-timer/<string:timer>', methods=['POST'])
    def start_timer(tid, timer):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        now = datetime.utcnow()
        if timer == 'round':
            if t.round_timer_remaining:
                t.round_timer_end = now + timedelta(seconds=t.round_timer_remaining)
                t.round_timer_remaining = None
            elif t.round_length:
                t.round_timer_end = now + timedelta(minutes=t.round_length)
                t.round_timer_remaining = None
            else:
                abort(400)
        elif timer == 'draft':
            if t.draft_timer_remaining:
                t.draft_timer_end = now + timedelta(seconds=t.draft_timer_remaining)
                t.draft_timer_remaining = None
            elif t.draft_time:
                t.draft_timer_end = now + timedelta(minutes=t.draft_time)
                t.draft_timer_remaining = None
            else:
                abort(400)
        elif timer == 'deck':
            if t.deck_timer_remaining:
                t.deck_timer_end = now + timedelta(seconds=t.deck_timer_remaining)
                t.deck_timer_remaining = None
            elif t.deck_build_time:
                t.deck_timer_end = now + timedelta(minutes=t.deck_build_time)
                t.deck_timer_remaining = None
            else:
                abort(400)
        else:
            abort(400)
        db.session.commit()
        log_tournament(tid, f'start_timer_{timer}', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/pause-timer/<string:timer>', methods=['POST'])
    def pause_timer(tid, timer):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        now = datetime.utcnow()
        if timer == 'round' and t.round_timer_end:
            t.round_timer_remaining = int((t.round_timer_end - now).total_seconds())
            t.round_timer_end = None
        elif timer == 'draft' and t.draft_timer_end:
            t.draft_timer_remaining = int((t.draft_timer_end - now).total_seconds())
            t.draft_timer_end = None
        elif timer == 'deck' and t.deck_timer_end:
            t.deck_timer_remaining = int((t.deck_timer_end - now).total_seconds())
            t.deck_timer_end = None
        else:
            abort(400)
        db.session.commit()
        log_tournament(tid, f'pause_timer_{timer}', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/stop-timer/<string:timer>', methods=['POST'])
    def stop_timer(tid, timer):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        if timer == 'round':
            t.round_timer_end = None
            t.round_timer_remaining = None
        elif timer == 'draft':
            t.draft_timer_end = None
            t.draft_timer_remaining = None
        elif timer == 'deck':
            t.deck_timer_end = None
            t.deck_timer_remaining = None
        else:
            abort(400)
        db.session.commit()
        log_tournament(tid, f'stop_timer_{timer}', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/restart-timer/<string:timer>', methods=['POST'])
    def restart_timer(tid, timer):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        now = datetime.utcnow()
        if timer == 'round' and t.round_length:
            t.round_timer_end = now + timedelta(minutes=t.round_length)
            t.round_timer_remaining = None
        elif timer == 'draft' and t.draft_time:
            t.draft_timer_end = now + timedelta(minutes=t.draft_time)
            t.draft_timer_remaining = None
        elif timer == 'deck' and t.deck_build_time:
            t.deck_timer_end = now + timedelta(minutes=t.deck_build_time)
            t.deck_timer_remaining = None
        else:
            abort(400)
        db.session.commit()
        log_tournament(tid, f'restart_timer_{timer}', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/draft-seating')
    def draft_seating(tid):
        t = db.session.get(Tournament, tid)
        if not t or t.format != 'Draft':
            abort(404)
        tables = draft_seating_tables(t, db.session)
        db.session.commit()
        timer_end = None
        timer_type = None
        timer_remaining = None
        if t.round_timer_end:
            timer_end = t.round_timer_end
            timer_type = 'round'
        elif t.draft_timer_end:
            timer_end = t.draft_timer_end
            timer_type = 'draft'
        elif t.deck_timer_end:
            timer_end = t.deck_timer_end
            timer_type = 'deck'
        elif t.round_timer_remaining:
            timer_type = 'round'
            timer_remaining = t.round_timer_remaining
        elif t.draft_timer_remaining:
            timer_type = 'draft'
            timer_remaining = t.draft_timer_remaining
        elif t.deck_timer_remaining:
            timer_type = 'deck'
            timer_remaining = t.deck_timer_remaining
        return render_template('tournament/draft_seating.html', t=t, tables=tables,
                               timer_end=timer_end, timer_type=timer_type,
                               timer_remaining=timer_remaining, server_now=datetime.utcnow())

    @app.route('/t/<int:tid>/set-rounds', methods=['POST'])
    def set_rounds(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        rounds = int(request.form['rounds'])
        t.rounds_override = rounds
        db.session.commit()
        flash("Round count set.", "success")
        log_tournament(tid, 'set_rounds', 'success', str(rounds))
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/pair-next-round', methods=['POST'])
    def pair_next_round(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        prev_round = db.session.query(Round).filter_by(tournament_id=tid).order_by(Round.number.desc()).first()
        if prev_round and any((not m.completed) or (not m.result) for m in prev_round.matches):
            flash('Previous round not completed.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        current_rounds = prev_round.number if prev_round else 0
        active_players = (
            db.session.query(TournamentPlayer)
            .filter_by(tournament_id=tid, dropped=False)
            .all()
        )
        player_count = len(active_players)
        if player_count == 0:
            flash('No players registered.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        pairing_type = (t.pairing_type or 'swiss').lower()
        round_limit = t.rounds_override
        if pairing_type == 'round_robin':
            if round_limit is None:
                if player_count <= 1:
                    round_limit = 1
                else:
                    round_limit = player_count if player_count % 2 else max(player_count - 1, 1)
        else:
            round_limit = round_limit or recommended_rounds(player_count)
        if t.structure == 'single_elim':
            round_limit = 0
        next_round_num = current_rounds + 1
        if (
            next_round_num == 1
            and player_count <= 7
            and pairing_type != 'round_robin'
        ):
            flash(
                'Tip: With seven or fewer players, the Round Robin pairing type ensures '
                'everyone plays each other. Consider selecting it before pairing.',
                'info',
            )
        if current_rounds < round_limit:
            if (
                next_round_num == 1
                and t.rules_enforcement_level in ('Competitive', 'Professional')
            ):
                missing = [p for p in active_players if not (p.deck and p.deck.is_submitted)]
                if missing:
                    names = ', '.join(p.user.name for p in missing if getattr(p, 'user', None))
                    message = (
                        'All players must submit a deck list before pairing round one '
                        'at Competitive or Professional REL.'
                    )
                    if names:
                        message += f' Missing deck lists: {names}.'
                    flash(message, 'error')
                    return redirect(url_for('view_tournament', tid=tid))
            r = Round(tournament_id=tid, number=next_round_num)
            db.session.add(r)
            db.session.commit()
            pair_round(t, r, db.session)
            flash(f"Paired round {next_round_num}.", "success")
            log_tournament(tid, 'pair_round', 'success', f'round={next_round_num}')
            return redirect(url_for('view_tournament', tid=tid))
        # Elimination rounds
        next_round_num = current_rounds + 1
        if t.structure == 'single_elim':
            if current_rounds == 0:
                players = list(active_players)
                random.shuffle(players)
                r = Round(tournament_id=tid, number=next_round_num)
                db.session.add(r)
                db.session.commit()
                table = t.start_table_number or 1
                for i in range(0, len(players), 2):
                    p1 = players[i]
                    p2 = players[i+1] if i+1 < len(players) else None
                    m = Match(round_id=r.id, player1_id=p1.id, player2_id=p2.id if p2 else None, table_number=table)
                    if p2 is None:
                        m.completed = True
                        m.result = MatchResult(player1_wins=2, player2_wins=0, draws=0)
                    db.session.add(m)
                    table += 1
                db.session.commit()
                flash(f"Paired round {next_round_num}.", "success")
                log_tournament(tid, 'pair_round', 'success', f'round={next_round_num}')
                return redirect(url_for('view_tournament', tid=tid))
            winners = []
            for m in sorted(prev_round.matches, key=lambda m: m.table_number):
                if m.result.player1_wins > m.result.player2_wins:
                    winners.append(m.player1)
                    if m.player2_id:
                        m.player2.dropped = True
                else:
                    winners.append(m.player2)
                    m.player1.dropped = True
            db.session.commit()
            if len(winners) <= 1:
                flash('Tournament complete.', 'success')
                return redirect(url_for('view_tournament', tid=tid))
            r = Round(tournament_id=tid, number=next_round_num)
            db.session.add(r)
            db.session.commit()
            table = t.start_table_number or 1
            for i in range(0, len(winners), 2):
                p1 = winners[i]
                p2 = winners[i+1]
                m = Match(round_id=r.id, player1_id=p1.id, player2_id=p2.id, table_number=table)
                db.session.add(m)
                table += 1
            db.session.commit()
            flash(f"Paired round {next_round_num}.", "success")
            log_tournament(tid, 'pair_round', 'success', f'round={next_round_num}')
            return redirect(url_for('view_tournament', tid=tid))
        else:
            if not t.cut.startswith('top'):
                flash('Cut not configured.', 'error')
                return redirect(url_for('view_tournament', tid=tid))
            if current_rounds == round_limit:
                top_n = int(t.cut[3:])
                standings = [row for row in compute_standings(t, db.session) if not row['tp'].dropped]
                if len(standings) < top_n:
                    flash('Not enough players for cut.', 'error')
                    return redirect(url_for('view_tournament', tid=tid))
                seeds = [row['tp'] for row in standings[:top_n]]
                r = Round(tournament_id=tid, number=next_round_num)
                db.session.add(r)
                db.session.commit()
                table = t.start_table_number or 1
                if t.format.lower() == 'commander':
                    group_size = 4
                    i = 0
                    while i < top_n:
                        pod = seeds[i:i+group_size]
                        m = Match(round_id=r.id, table_number=table,
                                  player1_id=pod[0].id,
                                  player2_id=pod[1].id if len(pod) > 1 else None,
                                  player3_id=pod[2].id if len(pod) > 2 else None,
                                  player4_id=pod[3].id if len(pod) > 3 else None)
                        db.session.add(m)
                        table += 1
                        i += group_size
                else:
                    for p1, p2 in seeded_cut_pairs(seeds):
                        m = Match(round_id=r.id, player1_id=p1.id, player2_id=p2.id, table_number=table)
                        db.session.add(m)
                        table += 1
                db.session.commit()
                flash(f"Paired round {next_round_num}.", "success")
                log_tournament(tid, 'pair_round', 'success', f'round={next_round_num}')
                return redirect(url_for('view_tournament', tid=tid))
            winners = []
            for m in sorted(prev_round.matches, key=lambda m: m.table_number):
                if t.format.lower() == 'commander':
                    rres = m.result
                    placements = [
                        (m.player1, rres.p1_place),
                        (m.player2, rres.p2_place),
                        (m.player3, rres.p3_place),
                        (m.player4, rres.p4_place),
                    ]
                    for pl, place in placements:
                        if not pl:
                            continue
                        if place == 1:
                            winners.append(pl)
                        else:
                            pl.dropped = True
                else:
                    if m.result.player1_wins > m.result.player2_wins:
                        winners.append(m.player1)
                        if m.player2_id:
                            m.player2.dropped = True
                    else:
                        winners.append(m.player2)
                        m.player1.dropped = True
            db.session.commit()
            if len(winners) <= 1:
                flash('Tournament complete.', 'success')
                return redirect(url_for('view_tournament', tid=tid))
            r = Round(tournament_id=tid, number=next_round_num)
            db.session.add(r)
            db.session.commit()
            table = t.start_table_number or 1
            if t.format.lower() == 'commander':
                group_size = 4
                i = 0
                while i < len(winners):
                    pod = winners[i:i+group_size]
                    m = Match(round_id=r.id, table_number=table,
                              player1_id=pod[0].id,
                              player2_id=pod[1].id if len(pod) > 1 else None,
                              player3_id=pod[2].id if len(pod) > 2 else None,
                              player4_id=pod[3].id if len(pod) > 3 else None)
                    db.session.add(m)
                    table += 1
                    i += group_size
            else:
                for i in range(0, len(winners), 2):
                    m = Match(round_id=r.id, player1_id=winners[i].id, player2_id=winners[i+1].id, table_number=table)
                    db.session.add(m)
                    table += 1
            db.session.commit()
            flash(f"Paired round {next_round_num}.", "success")
            log_tournament(tid, 'pair_round', 'success', f'round={next_round_num}')
            return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/round/<int:rid>/repair', methods=['POST'])
    def repair_round(tid, rid):
        require_permission('tournaments.manage')
        r = db.session.get(Round, rid)
        if not r or r.tournament_id != tid:
            abort(404)
        if any(m.completed for m in r.matches):
            flash('Cannot re-pair, results already entered.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        for m in r.matches:
            db.session.delete(m)
        db.session.commit()
        t = db.session.get(Tournament, tid)
        player_count = db.session.query(TournamentPlayer).filter_by(tournament_id=tid, dropped=False).count()
        if player_count == 0:
            flash('No players registered.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        pair_round(t, r, db.session)
        flash('Round re-paired.', 'success')
        log_tournament(tid, 'repair_round', 'success', f'round={r.number}')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/round/<int:rid>/delete', methods=['POST'])
    def delete_round(tid, rid):
        require_permission('tournaments.manage')
        r = db.session.get(Round, rid)
        if not r or r.tournament_id != tid:
            abort(404)
        if any(m.completed for m in r.matches):
            flash('Cannot delete, results already entered.', 'error')
            return redirect(url_for('view_round', tid=tid, rid=rid))
        for m in r.matches:
            db.session.delete(m)
        db.session.delete(r)
        db.session.commit()
        flash('Round deleted.', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/round/<int:rid>')
    def view_round(tid, rid):
        r = db.session.get(Round, rid)
        if not r or r.tournament_id != tid:
            abort(404)
        has_results = any(m.completed for m in r.matches)
        next_round = db.session.query(Round).filter(Round.tournament_id==tid, Round.number>r.number).first()
        locked = bool(next_round)
        t = r.tournament
        timer_end = None
        timer_type = None
        timer_remaining = None
        if t.round_timer_end:
            timer_end = t.round_timer_end
            timer_type = 'round'
        elif t.draft_timer_end:
            timer_end = t.draft_timer_end
            timer_type = 'draft'
        elif t.deck_timer_end:
            timer_end = t.deck_timer_end
            timer_type = 'deck'
        elif t.round_timer_remaining:
            timer_type = 'round'
            timer_remaining = t.round_timer_remaining
        elif t.draft_timer_remaining:
            timer_type = 'draft'
            timer_remaining = t.draft_timer_remaining
        elif t.deck_timer_remaining:
            timer_type = 'deck'
            timer_remaining = t.deck_timer_remaining
        return render_template('tournament/round.html', t=t, r=r, has_results=has_results,
                               locked=locked, timer_end=timer_end, timer_type=timer_type,
                               timer_remaining=timer_remaining, server_now=datetime.utcnow())

    @app.route('/match/<int:mid>', methods=['GET','POST'])
    @login_required
    def report_match(mid):
        m = db.session.get(Match, mid)
        if not m: abort(404)
        from .models import TournamentPlayer, MatchResult
        # Only participants or tournament managers can report
        t = m.round.tournament
        if not current_user.has_permission('tournaments.manage') and current_user.id not in (
            m.player1.user_id,
            m.player2.user_id if m.player2_id else None,
            m.player3.user_id if m.player3_id else None,
            m.player4.user_id if m.player4_id else None,
        ):
            abort(403)
        next_round = db.session.query(Round).filter(Round.tournament_id==t.id, Round.number>m.round.number).first()
        if next_round:
            flash('Cannot modify result after next round has been paired.', 'error')
            return redirect(url_for('view_round', tid=t.id, rid=m.round_id))
        if request.method == 'POST':
            dropped_ids = []
            can_drop_any_player = current_user.has_permission('tournaments.manage')

            def player_drop_requested(field_name, tournament_player):
                if not request.form.get(field_name):
                    return False
                if can_drop_any_player or (tournament_player and tournament_player.user_id == current_user.id):
                    return True
                flash('Players may only drop themselves from a tournament.', 'error')
                log_tournament(t.id, 'drop', 'failure', f'user_id={current_user.id}; attempted={tournament_player.user_id if tournament_player else ""}')
                return False

            if t.format.lower() == 'commander':
                drop_p1 = player_drop_requested('drop_p1', m.player1)
                drop_p2 = player_drop_requested('drop_p2', m.player2) if m.player2_id else False
                drop_p3 = player_drop_requested('drop_p3', m.player3) if m.player3_id else False
                drop_p4 = player_drop_requested('drop_p4', m.player4) if m.player4_id else False
                if request.form.get('is_draw') and not any([drop_p1, drop_p2, drop_p3, drop_p4]):
                    m.result = MatchResult(is_draw=True)
                else:
                    p1_place = int(request.form.get('p1_place', 0) or 0)
                    p2_place = int(request.form.get('p2_place', 0) or 0)
                    p3_place = int(request.form.get('p3_place', 0) or 0)
                    p4_place = int(request.form.get('p4_place', 0) or 0)
                    if drop_p1: p1_place = 4
                    if drop_p2: p2_place = 4
                    if drop_p3: p3_place = 4
                    if drop_p4: p4_place = 4
                    m.result = MatchResult(p1_place=p1_place, p2_place=p2_place,
                                           p3_place=p3_place, p4_place=p4_place)
                m.completed = True
                if drop_p1:
                    m.player1.dropped = True
                    dropped_ids.append(m.player1.user_id)
                if m.player2_id and drop_p2:
                    m.player2.dropped = True
                    dropped_ids.append(m.player2.user_id)
                if m.player3_id and drop_p3:
                    m.player3.dropped = True
                    dropped_ids.append(m.player3.user_id)
                if m.player4_id and drop_p4:
                    m.player4.dropped = True
                    dropped_ids.append(m.player4.user_id)
            else:
                p1_wins = int(request.form.get('p1_wins', 2 if m.player2_id is None else 0))
                p2_wins = int(request.form.get('p2_wins', 0))
                draws   = int(request.form.get('draws', 0))
                m.result = MatchResult(player1_wins=p1_wins, player2_wins=p2_wins, draws=draws)
                m.completed = True
                if player_drop_requested('drop_p1', m.player1):
                    m.player1.dropped = True
                    dropped_ids.append(m.player1.user_id)
                if m.player2_id and player_drop_requested('drop_p2', m.player2):
                    m.player2.dropped = True
                    dropped_ids.append(m.player2.user_id)
                # Auto-drop losers in elimination rounds
                active = db.session.query(TournamentPlayer).filter_by(
                    tournament_id=t.id, dropped=False
                ).count()
                round_limit = t.rounds_override or recommended_rounds(active)
                if t.structure == 'single_elim':
                    round_limit = 0
                if m.round.number > round_limit and m.player2_id:
                    if p1_wins > p2_wins:
                        m.player2.dropped = True
                        dropped_ids.append(m.player2.user_id)
                    elif p2_wins > p1_wins:
                        m.player1.dropped = True
                        dropped_ids.append(m.player1.user_id)
            db.session.commit()
            flash("Result submitted.", "success")
            log_tournament(t.id, 'report', 'success')
            for uid in dropped_ids:
                log_tournament(t.id, 'drop', 'success', f'user_id={uid}')
            return redirect(url_for('view_round', tid=m.round.tournament_id, rid=m.round_id))
        return render_template('match/report.html', m=m, t=t)

    @app.route('/t/<int:tid>/standings')
    def standings(tid):
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        standings = compute_standings(t, db.session)
        timer_end = None
        timer_type = None
        timer_remaining = None
        if t.round_timer_end:
            timer_end = t.round_timer_end
            timer_type = 'round'
        elif t.draft_timer_end:
            timer_end = t.draft_timer_end
            timer_type = 'draft'
        elif t.deck_timer_end:
            timer_end = t.deck_timer_end
            timer_type = 'deck'
        elif t.round_timer_remaining:
            timer_type = 'round'
            timer_remaining = t.round_timer_remaining
        elif t.draft_timer_remaining:
            timer_type = 'draft'
            timer_remaining = t.draft_timer_remaining
        elif t.deck_timer_remaining:
            timer_type = 'deck'
            timer_remaining = t.deck_timer_remaining
        return render_template('tournament/standings.html', t=t, standings=standings,
                               timer_end=timer_end, timer_type=timer_type,
                               timer_remaining=timer_remaining, server_now=datetime.utcnow())

    @app.route('/t/<int:tid>/bracket')
    def bracket(tid):
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        rounds = db.session.query(Round).filter_by(tournament_id=tid).order_by(Round.number).all()
        players = db.session.query(TournamentPlayer).filter_by(tournament_id=tid).all()
        round_limit = t.rounds_override or recommended_rounds(len(players))
        if t.structure == 'single_elim':
            round_limit = 0
        elim_rounds = [r for r in rounds if r.number > round_limit]
        points = {tp.id: player_points(tp, db.session) for tp in players}
        champion = None
        if elim_rounds:
            final_round = elim_rounds[-1]
            if all(m.completed and m.result for m in final_round.matches):
                fm = final_round.matches[0]
                if t.format == 'Commander':
                    placements = {
                        fm.result.p1_place: fm.player1,
                        fm.result.p2_place: fm.player2,
                        fm.result.p3_place: fm.player3,
                        fm.result.p4_place: fm.player4,
                    }
                    champion = placements.get(1)
                else:
                    if fm.result.player1_wins >= fm.result.player2_wins:
                        champion = fm.player1
                    else:
                        champion = fm.player2
        timer_end = None
        timer_type = None
        timer_remaining = None
        if t.round_timer_end:
            timer_end = t.round_timer_end
            timer_type = 'round'
        elif t.draft_timer_end:
            timer_end = t.draft_timer_end
            timer_type = 'draft'
        elif t.deck_timer_end:
            timer_end = t.deck_timer_end
            timer_type = 'deck'
        elif t.round_timer_remaining:
            timer_type = 'round'
            timer_remaining = t.round_timer_remaining
        elif t.draft_timer_remaining:
            timer_type = 'draft'
            timer_remaining = t.draft_timer_remaining
        elif t.deck_timer_remaining:
            timer_type = 'deck'
            timer_remaining = t.deck_timer_remaining
        return render_template('tournament/bracket.html', t=t, rounds=elim_rounds, points=points,
                               champion=champion, timer_end=timer_end,
                               timer_type=timer_type, timer_remaining=timer_remaining,
                               server_now=datetime.utcnow())

    @app.route('/admin/users')
    def admin_users():
        require_permission('users.manage')
        from .models import User

        q = request.args.get('q', '').strip()
        query = db.session.query(User)
        if not current_user.has_permission('users.manage_admins'):
            query = query.filter(User.is_admin == False)
        if q:
            pattern = f"%{q}%"
            query = query.filter(or_(User.name.ilike(pattern), User.email.ilike(pattern)))
        users = query.order_by(User.name).all()
        return render_template(
            'admin/users.html',
            users=users,
            search_query=q,
        )

    POST_LOGIN_REDIRECT_ENDPOINTS = {'tournament_join_link'}

    def allowed_post_login_redirect(candidate):
        if not candidate:
            return None
        candidate = candidate.strip()
        if not candidate or '\\' in candidate:
            return None
        parsed = urlparse(candidate)
        if (
            parsed.scheme
            or parsed.netloc
            or not parsed.path.startswith('/')
            or parsed.path.startswith('//')
        ):
            return None
        try:
            endpoint, values = app.url_map.bind('').match(parsed.path, method='GET')
        except (MethodNotAllowed, NotFound, RequestRedirect, ValueError):
            return None
        if endpoint not in POST_LOGIN_REDIRECT_ENDPOINTS:
            return None
        return url_for(endpoint, **values)

    @app.route('/admin/users/<int:uid>')
    def admin_user_detail(uid):
        require_permission('users.manage')
        from .models import User, Tournament, Role

        target = db.session.get(User, uid)
        if not target:
            abort(404)
        if target.is_admin and not current_user.has_permission('users.manage_admins'):
            abort(403)

        q = request.args.get('q', '').strip()
        back_url = url_for('admin_users', q=q) if q else url_for('admin_users')

        tournaments = db.session.query(Tournament).order_by(Tournament.name).all()
        roles = db.session.query(Role).order_by(Role.name).all()
        if not current_user.has_permission('users.manage_admins'):
            roles = [r for r in roles if r.name != 'admin']
        can_manage_overrides = current_user.has_permission('admin.permissions')

        return render_template(
            'admin/user_detail.html',
            user=target,
            tournaments=tournaments,
            roles=roles,
            search_query=q,
            back_url=back_url,
            can_manage_overrides=can_manage_overrides,
            permission_groups=PERMISSION_GROUPS,
        )

    @app.route('/admin/users/<int:uid>/add', methods=['POST'])
    def admin_add_user_to_tournament(uid):
        require_permission('users.manage')
        from .models import TournamentPlayer, User
        target = db.session.get(User, uid)
        if target.is_admin and not current_user.has_permission('users.manage_admins'):
            abort(403)
        search_query = request.form.get('search_query', '').strip()
        tid = int(request.form['tournament_id'])
        if not db.session.query(TournamentPlayer).filter_by(user_id=uid, tournament_id=tid).first():
            tp = TournamentPlayer(user_id=uid, tournament_id=tid)
            db.session.add(tp)
            db.session.commit()
        flash('User added to tournament.', 'success')
        if search_query:
            return redirect(url_for('admin_user_detail', uid=uid, q=search_query))
        return redirect(url_for('admin_user_detail', uid=uid))

    @app.route('/admin/users/<int:uid>/remove/<int:tid>', methods=['POST'])
    def admin_remove_user_from_tournament(uid, tid):
        require_permission('users.manage')
        from .models import TournamentPlayer, User
        target = db.session.get(User, uid)
        if target.is_admin and not current_user.has_permission('users.manage_admins'):
            abort(403)
        search_query = request.form.get('search_query', '').strip()
        tp = db.session.query(TournamentPlayer).filter_by(user_id=uid, tournament_id=tid).first()
        if tp:
            db.session.delete(tp)
            db.session.commit()
        flash('User removed from tournament.', 'success')
        if search_query:
            return redirect(url_for('admin_user_detail', uid=uid, q=search_query))
        return redirect(url_for('admin_user_detail', uid=uid))

    @app.route('/admin/users/<int:uid>/update', methods=['POST'])
    def admin_update_user(uid):
        require_permission('users.manage')
        from .models import User, Role
        u = db.session.get(User, uid)
        if not u:
            abort(404)
        if u.is_admin and not current_user.has_permission('users.manage_admins'):
            abort(403)
        search_query = request.form.get('search_query', '').strip()
        if search_query:
            redirect_target = url_for('admin_user_detail', uid=uid, q=search_query)
        else:
            redirect_target = url_for('admin_user_detail', uid=uid)
        email = request.form.get('email', '').strip().lower() or None
        if email and db.session.query(User).filter(User.email == email, User.id != uid).first():
            flash('Email already registered.', 'error')
            log_site('user_update', 'failure', 'email exists')
        else:
            password = request.form.get('password', '')
            password_confirm = request.form.get('password_confirm', '')
            if password or password_confirm:
                if password != password_confirm:
                    flash('Passwords do not match.', 'error')
                    log_site('user_update', 'failure', 'password mismatch')
                    return redirect(redirect_target)
                u.set_password(password, unlock=False)
                u.generate_keys(password)

            log_events = []
            if password or password_confirm:
                log_events.append(('admin_password_reset', 'success', f'user_id={u.id}'))

            lock_action = request.form.get('account_lock_action')
            if u.id == current_user.id and lock_action == 'lock':
                flash('Cannot lock your own account.', 'error')
                log_events.append(('admin_account_lock', 'failure', f'user_id={u.id}; self_lock'))
            elif lock_action == 'lock':
                u.locked_at = datetime.now(timezone.utc).replace(tzinfo=None)
                u.lock_reason = request.form.get('lock_reason', '').strip() or 'Manually locked by administrator'
                log_events.append(('admin_account_lock', 'success', f'user_id={u.id}; reason={u.lock_reason}'))
            elif lock_action == 'unlock' or request.form.get('unlock_account') == 'yes':
                u.failed_login_count = 0
                u.locked_at = None
                u.lock_reason = None
                log_events.append(('admin_account_unlock', 'success', f'user_id={u.id}'))
            first_name = request.form.get('first_name', '').strip()
            last_name = request.form.get('last_name', '').strip()
            if 'first_name' not in request.form and 'last_name' not in request.form:
                first_name = u.first_name or _split_name(u.name)[0]
                last_name = u.last_name or _split_name(u.name)[1]
            if not first_name and not last_name:
                flash('First or last name is required.', 'error')
                return redirect(redirect_target)
            u.email = email
            _set_user_name_parts(u, first_name, last_name, request.form.get('name'))
            u.notes = request.form.get('notes', '').strip() or None
            role_id = request.form.get('role_id')
            if role_id:
                role = db.session.get(Role, int(role_id))
                if uid == current_user.id and role and role.name != 'admin':
                    flash('Cannot change your own admin role.', 'error')
                elif role and (role.name != 'admin' or current_user.has_permission('users.manage_admins')):
                    u.role = role
                    u.is_admin = (role.name == 'admin')
            if current_user.has_permission('admin.permissions'):
                overrides = {}
                for key in all_permission_keys():
                    field = f'perm_override_{key}'
                    val = request.form.get(field)
                    if val in ('allow', 'deny'):
                        overrides[key] = val
                u.permission_overrides = json.dumps(overrides) if overrides else None
            db.session.commit()
            for action, result, error in log_events:
                try:
                    log_site(action, result, error)
                except SQLAlchemyError as exc:
                    db.session.rollback()
                    app.logger.warning('Unable to write site log entry %s: %s', action, exc)
            try:
                log_site('user_update', 'success')
            except SQLAlchemyError as exc:
                db.session.rollback()
                app.logger.warning('Unable to write site log entry user_update: %s', exc)
            flash('User updated.', 'success')
        return redirect(redirect_target)

    @app.route('/admin/users/<int:uid>/delete', methods=['POST'])
    def admin_delete_user(uid):
        require_permission('users.manage')
        from .models import User
        u = db.session.get(User, uid)
        if not u:
            abort(404)
        if u.is_admin and not current_user.has_permission('users.manage_admins'):
            abort(403)
        search_query = request.form.get('search_query', '').strip()
        for tp in list(u.tournament_entries):
            db.session.delete(tp)
        db.session.delete(u)
        db.session.commit()
        flash('User deleted.', 'success')
        if search_query:
            return redirect(url_for('admin_users', q=search_query))
        return redirect(url_for('admin_users'))


    @app.route('/admin/users/bulk-delete', methods=['POST'])
    def admin_bulk_delete_users():
        require_permission('users.manage')
        user_ids = []
        for raw_id in request.form.getlist('user_ids'):
            try:
                user_ids.append(int(raw_id))
            except ValueError:
                continue
        if not user_ids:
            flash('Select at least one user to delete.', 'error')
            return redirect(url_for('admin_users', q=request.form.get('search_query', '').strip()))
        deleted = 0
        skipped = 0
        for user in db.session.query(User).filter(User.id.in_(user_ids)).all():
            if user.id == current_user.id:
                skipped += 1
                continue
            if user.is_admin and not current_user.has_permission('users.manage_admins'):
                skipped += 1
                continue
            for tp in list(user.tournament_entries):
                db.session.delete(tp)
            db.session.delete(user)
            deleted += 1
        db.session.commit()
        message = f'Deleted {deleted} user' + ('s' if deleted != 1 else '') + '.'
        if skipped:
            message += f' Skipped {skipped} protected user' + ('s' if skipped != 1 else '') + '.'
        flash(message, 'success' if deleted else 'warning')
        log_site('users_bulk_delete', 'success', f'deleted={deleted}; skipped={skipped}')
        search_query = request.form.get('search_query', '').strip()
        if search_query:
            return redirect(url_for('admin_users', q=search_query))
        return redirect(url_for('admin_users'))

    return app

app = create_app()
