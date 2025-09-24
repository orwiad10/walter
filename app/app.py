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
from datetime import datetime, timedelta
import os
import random
import click
import hashlib
import psutil
import json
import base64
import io
import glob
import secrets
import csv
from collections import OrderedDict
from urllib.parse import urlparse

import requests
from sqlalchemy import inspect, text, or_
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from werkzeug.utils import secure_filename
from PIL import Image, ImageOps

from . import card_db


db = SQLAlchemy()
login_manager = LoginManager()
PASSWORD_KEY = None
PASSWORD_SEED = None


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
        timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
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
    app.config['MOXFIELD_API_TEMPLATE'] = os.environ.get(
        'MOXFIELD_API_TEMPLATE',
        'https://api.moxfield.com/v2/decks/all/{code}',
    )
    app.config['MOXFIELD_PRIMARY_USER_AGENT'] = os.environ.get(
        'MOXFIELD_PRIMARY_USER_AGENT',
        'WalterDeckImporter/1.0',
    )
    app.config['MOXFIELD_FALLBACK_USER_AGENT'] = os.environ.get(
        'MOXFIELD_FALLBACK_USER_AGENT',
        'Mozilla/5.0',
    )
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret-change-me')

    seed_env = os.environ.get('PASSWORD_SEED')
    if seed_env is None:
        seed_bytes = os.urandom(32)
        seed_display = seed_bytes.hex()
    else:
        seed_bytes = seed_env.encode()
        seed_display = seed_env
    global PASSWORD_KEY, PASSWORD_SEED
    PASSWORD_KEY = hashlib.sha256(seed_bytes).digest()
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
        if 'user' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('user')]
            if 'break_end' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN break_end DATETIME'))
                db.session.commit()
            if 'permission_overrides' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN permission_overrides TEXT'))
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
        from .models import Report, TournamentJoinRequest  # lazy import to avoid circular reference

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
        from .models import LostFoundItem, TournamentPlayerDeck

        media_engine = db.get_engine(app, bind='media')
        LostFoundItem.__table__.create(bind=media_engine, checkfirst=True)
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
        TournamentLog,
        Message,
        Report,
        TournamentJoinRequest,
        LostFoundItem,
        all_permission_keys,
    )
    from .pairing import swiss_pair_round, recommended_rounds, compute_standings, player_points

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
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        player_counts = {t.id: len(t.players) for t in tournaments}
        return render_template('index.html', tournaments=tournaments, player_counts=player_counts,
                               server_now=datetime.utcnow())

    @app.route('/register', methods=['GET','POST'])
    def register():
        from .models import User, Tournament, TournamentPlayer, Role
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            name = request.form['name'].strip()
            password = request.form['password']
            confirm = request.form.get('password_confirm', '')
            if password != confirm:
                flash("Passwords do not match", "error")
                log_site('register', 'failure', 'password mismatch')
                return redirect(url_for('register'))
            if db.session.query(User).filter_by(email=email).first():
                flash("Email already registered", "error")
                log_site('register', 'failure', 'email exists')
                return redirect(url_for('register'))
            role_user = db.session.query(Role).filter_by(name='user').first()
            u = User(email=email, name=name, role=role_user)
            u.set_password(password)
            u.generate_keys(password)
            db.session.add(u)
            db.session.commit()
            log_site('register', 'success')
            tournament_id = request.form.get('tournament_id')
            if tournament_id:
                t = db.session.get(Tournament, int(tournament_id))
                code = request.form.get('passcode', '')
                if not t or code != t.passcode:
                    flash("Invalid tournament passcode", "error")
                    return redirect(url_for('register'))
                tp = TournamentPlayer(tournament_id=int(tournament_id), user_id=u.id)
                db.session.add(tp)
                db.session.commit()
            flash("Registered. Please login.", "success")
            return redirect(url_for('login'))
        return render_template('register.html', tournaments=tournaments)

    @app.route('/login', methods=['GET','POST'])
    def login():
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            password = request.form['password']
            from .models import User
            u = db.session.query(User).filter_by(email=email).first()
            if u and u.check_password(password):
                login_user(u)
                try:
                    priv_pem = u.decrypt_private_key(password)
                    if priv_pem:
                        session['private_key'] = base64.b64encode(priv_pem).decode()
                except Exception:
                    session['private_key'] = None
                log_site('login', 'success')
                return redirect(url_for('index'))
            flash("Invalid credentials", "error")
            log_site('login', 'failure', 'invalid credentials')
        return render_template('login.html')

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
    @login_required
    def lost_and_found():
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
                return redirect(url_for('lost_and_found'))
            image_filename = None
            upload = request.files.get('photo')
            if upload and upload.filename:
                image_filename = sanitize_image_upload(upload)
                if not image_filename:
                    flash('Image could not be processed. Please upload a different picture.', 'error')
                    return redirect(url_for('lost_and_found'))
            item = LostFoundItem(
                title=title,
                description=description,
                location=location,
                reporter_name=reporter_name,
                reporter_contact=reporter_contact,
                status=status,
            )
            if image_filename:
                item.image_path = image_filename
            db.session.add(item)
            db.session.commit()
            log_site('lost_found_create', 'success', title)
            flash('Lost & Found entry created.', 'success')
            return redirect(url_for('lost_and_found'))
        items = (
            db.session.query(LostFoundItem)
            .order_by(LostFoundItem.created_at.desc())
            .all()
        )
        return render_template(
            'lost_found/index.html',
            items=items,
            manage_access=manage_access,
            status_options=status_options,
        )

    @app.route('/lost-and-found/<int:item_id>/update', methods=['POST'])
    @login_required
    def update_lost_and_found(item_id):
        if not can_manage_lost_found():
            abort(403)
        item = db.session.get(LostFoundItem, item_id)
        if not item:
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
        return redirect(url_for('lost_and_found'))

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

    def log_site(action, result, error=None):
        log = SiteLog(action=action, result=result, error=error,
                      user_id=current_user.id if current_user.is_authenticated else None)
        db.session.add(log)
        db.session.commit()

    def log_tournament(tid, action, result, error=None):
        log = TournamentLog(tournament_id=tid, action=action, result=result, error=error,
                             user_id=current_user.id if current_user.is_authenticated else None)
        db.session.add(log)
        db.session.commit()

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
        safe_prefix = ''.join(ch for ch in prefix if ch.isalnum()) or 'deck'
        filename = f"{safe_prefix}_{datetime.utcnow().strftime('%Y%m%d%H%M%S')}_{secrets.token_hex(4)}.png"
        os.makedirs(storage_dir, exist_ok=True)
        path = os.path.join(storage_dir, filename)
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

    def extract_moxfield_deck_id(raw_value):
        value = (raw_value or '').strip()
        if not value:
            return None

        def sanitize(segment):
            if not segment:
                return None
            cleaned = segment.split('?')[0].split('#')[0].strip()
            return cleaned or None

        known_sections = {
            'all',
            'alchemy',
            'artisan',
            'brawl',
            'cedh',
            'commander',
            'constructed',
            'duel-commander',
            'duelcommander',
            'explorer',
            'featured',
            'gladiator',
            'historic',
            'historic-brawl',
            'historicbrawl',
            'legacy',
            'modern',
            'oathbreaker',
            'oldschool',
            'pauper',
            'pauper-commander',
            'paupercommander',
            'penny',
            'pioneer',
            'premodern',
            'predh',
            'private',
            'public',
            'standard',
            'tinyleaders',
            'vintage',
        }

        if value.startswith('http://') or value.startswith('https://'):
            parsed = urlparse(value)
            segments = [segment for segment in parsed.path.split('/') if segment]
            deck_id = None
            try:
                decks_index = next(
                    idx for idx, segment in enumerate(segments) if segment.lower() == 'decks'
                )
            except StopIteration:
                return None
            candidates = [sanitize(segment) for segment in segments[decks_index + 1 :]]
            candidates = [segment for segment in candidates if segment]
            if not candidates:
                return None
            for candidate in candidates:
                if candidate.lower() in known_sections:
                    continue
                deck_id = candidate
                break
            if deck_id is None:
                return None
        else:
            parts = [sanitize(segment) for segment in value.split('/') if segment]
            parts = [segment for segment in parts if segment]
            if not parts:
                return None
            deck_id = parts[-1]
        return deck_id or None

    def parse_moxfield_section(section):
        entries = []
        if isinstance(section, dict):
            for item in section.values():
                if not isinstance(item, dict):
                    continue
                quantity = item.get('quantity', item.get('count'))
                if quantity in (None, ''):
                    continue
                try:
                    count = int(quantity)
                except (TypeError, ValueError):
                    continue
                card_name = None
                card_info = item.get('card')
                if isinstance(card_info, dict):
                    card_name = card_info.get('name')
                if not card_name:
                    card_name = item.get('name')
                if not card_name:
                    continue
                entries.append({'name': card_name, 'count': count})
        return entries

    def parse_moxfield_payload(payload):
        if not isinstance(payload, dict):
            raise ValueError('Unexpected response from Moxfield.')
        main_entries = []
        for key in ('mainboard', 'commanders', 'companions', 'signatureSpells'):
            section = payload.get(key)
            main_entries.extend(parse_moxfield_section(section))
        side_entries = parse_moxfield_section(payload.get('sideboard'))
        return combine_card_entries(main_entries), combine_card_entries(side_entries)

    def save_player_deck(tp, source, main_cards, side_cards, raw_text=None, moxfield_url=None, submitted=False):
        from .models import TournamentPlayerDeck  # lazy import

        deck = tp.deck
        if not deck:
            deck = TournamentPlayerDeck(tournament_player=tp, source=source)
        deck.source = source
        deck.mainboard = json.dumps(main_cards, ensure_ascii=False)
        deck.sideboard = json.dumps(side_cards, ensure_ascii=False)
        deck.raw_text = raw_text
        deck.moxfield_url = moxfield_url
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

    @app.route('/admin/tournaments/new', methods=['GET','POST'])
    def new_tournament():
        require_permission('tournaments.manage')
        if request.method == 'POST':
            name = request.form['name'].strip()
            fmt = request.form['format']
            structure = request.form.get('structure', 'swiss')
            cut = request.form.get('cut', 'none') if structure == 'swiss' else 'none'
            if fmt == 'Commander' and cut not in ('none','top4','top16','top32','top64'):
                flash('Commander supports cuts to Top 4, 16, 32, or 64.', 'error')
                return render_template('admin/new_tournament.html')
            commander_points = request.form.get('commander_points', '3,2,1,0,1')
            round_length = int(request.form.get('round_length', 50))
            draft_time = request.form.get('draft_time')
            deck_build_time = request.form.get('deck_build_time')
            start_time_str = request.form.get('start_time')
            start_time = parse_datetime_local(start_time_str)
            if start_time_str and start_time is None:
                flash('Invalid start time format.', 'error')
                return render_template('admin/new_tournament.html')
            rel = request.form.get('rules_enforcement_level', 'None') or 'None'
            is_cube = request.form.get('is_cube') == '1'
            if fmt != 'Draft':
                is_cube = False
            join_requires_approval = request.form.get('join_requires_approval') == '1'
            t = Tournament(name=name, format=fmt, cut=cut, structure=structure,
                           commander_points=commander_points,
                           round_length=round_length,
                           draft_time=int(draft_time) if draft_time else None,
                           deck_build_time=int(deck_build_time) if deck_build_time else None,
                           start_time=start_time,
                            rules_enforcement_level=rel,
                           is_cube=is_cube,
                           join_requires_approval=join_requires_approval)
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
        return render_template('admin/new_tournament.html')

    @app.route('/admin/tournaments/<int:tid>/edit', methods=['GET','POST'])
    def edit_tournament(tid):
        require_permission('tournaments.manage')
        t = db.session.get(Tournament, tid)
        if request.method == 'POST':
            t.name = request.form['name'].strip()
            t.format = request.form['format']
            t.structure = request.form.get('structure', 'swiss')
            t.cut = request.form.get('cut', 'none') if t.structure == 'swiss' else 'none'
            t.commander_points = request.form.get('commander_points', '3,2,1,0,1')
            t.round_length = int(request.form.get('round_length', 50))
            draft_time = request.form.get('draft_time')
            deck_build_time = request.form.get('deck_build_time')
            start_time_str = request.form.get('start_time')
            t.start_time = parse_datetime_local(start_time_str)
            if start_time_str and t.start_time is None:
                flash('Invalid start time format.', 'error')
                return render_template('admin/edit_tournament.html', t=t)
            t.draft_time = int(draft_time) if draft_time else None
            t.deck_build_time = int(deck_build_time) if deck_build_time else None
            rel = request.form.get('rules_enforcement_level', 'None') or 'None'
            is_cube = request.form.get('is_cube') == '1'
            t.rules_enforcement_level = rel
            t.is_cube = is_cube if t.format == 'Draft' else False
            t.join_requires_approval = request.form.get('join_requires_approval') == '1'
            db.session.commit()
            flash('Tournament updated.', 'success')
            log_site('edit_tournament', 'success', t.name)
            log_tournament(tid, 'edit', 'success')
            return redirect(url_for('view_tournament', tid=tid))
        return render_template('admin/edit_tournament.html', t=t)

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
            name = request.form['name'].strip()
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
        if request.method == 'POST':
            tournament_id = request.form.get('tournament_id')
            names_raw = request.form['names']
            count = 0
            for line in names_raw.splitlines():
                name = line.strip()
                if not name:
                    continue
                role_user = db.session.query(Role).filter_by(name='user').first()
                u = User(name=name, role=role_user)
                db.session.add(u)
                db.session.flush()
                if tournament_id:
                    tp = TournamentPlayer(tournament_id=int(tournament_id), user_id=u.id)
                    db.session.add(tp)
                count += 1
            db.session.commit()
            if tournament_id:
                log_tournament(int(tournament_id), 'add_player', 'bulk', f'count={count}')
            log_site('bulk_register', 'success', f'count={count}')
            flash(f"Registered {count} players.", "success")
            return redirect(url_for('admin_bulk_register'))
        return render_template('admin/bulk_register_players.html', tournaments=tournaments)

    @app.route('/admin/panel', methods=['GET', 'POST'])
    def admin_panel():
        require_admin()
        log_site('view_admin_panel', 'success')
        password_seed = None
        if request.method == 'POST':
            if current_user.check_password(request.form.get('password', '')):
                password_seed = PASSWORD_SEED
                log_site('reveal_password_seed', 'success')
            else:
                log_site('reveal_password_seed', 'failure')
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
            encryption_type='SHA256+salt',
            db_size=fmt_bytes(db_size),
            ram_usage=fmt_bytes(mem_usage),
            cpu_usage=cpu_usage,
            connections=connections,
            uptime=uptime_seconds,
            password_seed=password_seed,
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

    @app.route('/admin/logs')
    def site_logs():
        require_admin()
        log_site('view_site_logs', 'success')
        logs = db.session.query(SiteLog).order_by(SiteLog.timestamp.desc()).all()
        for l in logs:
            l.user = db.session.get(User, l.user_id) if l.user_id else None
        return render_template('admin/site_logs.html', logs=logs)

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
    @app.route('/t/<int:tid>')
    def view_tournament(tid):
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        players = db.session.query(TournamentPlayer).filter_by(tournament_id=tid).all()
        rounds = db.session.query(Round).filter_by(tournament_id=tid).order_by(Round.number).all()
        standings = compute_standings(t, db.session)
        rec_rounds = recommended_rounds(len(players))
        floor_judges = []
        ids = t.floor_judge_ids()
        if ids:
            floor_judges = db.session.query(User).filter(User.id.in_(ids)).all()
        is_player = False
        show_passcode = False
        pending_join_requests = []
        user_join_request = None
        player_deck = None
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
        return render_template('tournament/view.html', t=t, players=players, rounds=rounds,
                               standings=standings, rec_rounds=rec_rounds,
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
                               server_now=datetime.utcnow())

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
            return jsonify(error=str(exc), results=[]), 503
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
            flash(f'Card database unavailable: {exc}', 'error')
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

    @app.route('/t/<int:tid>/deck/moxfield', methods=['POST'])
    @login_required
    def import_moxfield_deck(tid):
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
        deck_input = (request.form.get('moxfield_url') or '').strip()
        deck_id = extract_moxfield_deck_id(deck_input)
        if not deck_id:
            flash('Enter a valid Moxfield deck link or ID.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        template = app.config.get('MOXFIELD_API_TEMPLATE', 'https://api.moxfield.com/v2/decks/all/{code}')
        api_url = template.format(code=deck_id)
        header_candidates = []
        seen_user_agents = set()
        for user_agent in (
            app.config.get('MOXFIELD_PRIMARY_USER_AGENT'),
            app.config.get('MOXFIELD_FALLBACK_USER_AGENT'),
        ):
            if not user_agent or user_agent in seen_user_agents:
                continue
            seen_user_agents.add(user_agent)
            header_candidates.append(
                {'Accept': 'application/json', 'User-Agent': user_agent}
            )
        if not header_candidates:
            header_candidates.append({'Accept': 'application/json'})
        response = None
        for headers in header_candidates:
            try:
                candidate = requests.get(
                    api_url,
                    timeout=15,
                    headers=headers,
                )
            except requests.RequestException as exc:
                flash(f'Failed to contact Moxfield: {exc}', 'error')
                log_tournament(tid, 'deck_moxfield', 'failure', str(exc))
                return redirect(url_for('view_tournament', tid=tid))
            response = candidate
            if response.status_code != 403:
                break
        if response is None:
            flash('Failed to contact Moxfield.', 'error')
            log_tournament(tid, 'deck_moxfield', 'failure', 'no response')
            return redirect(url_for('view_tournament', tid=tid))
        if response.status_code != 200:
            error_message = None
            try:
                error_payload = response.json()
                if isinstance(error_payload, dict):
                    error_message = error_payload.get('error') or error_payload.get('message')
            except ValueError:
                error_message = None
            msg = f"Moxfield returned an error.{(' ' + error_message) if error_message else ''}"
            flash(msg.strip(), 'error')
            detail = f'status {response.status_code}'
            if error_message:
                detail += f' message={error_message}'
            log_tournament(tid, 'deck_moxfield', 'failure', detail)
            return redirect(url_for('view_tournament', tid=tid))
        try:
            payload = response.json()
        except ValueError:
            flash('Invalid response from Moxfield.', 'error')
            log_tournament(tid, 'deck_moxfield', 'failure', 'invalid json')
            return redirect(url_for('view_tournament', tid=tid))
        try:
            main_entries, side_entries = parse_moxfield_payload(payload)
        except ValueError as exc:
            flash(str(exc), 'error')
            log_tournament(tid, 'deck_moxfield', 'failure', str(exc))
            return redirect(url_for('view_tournament', tid=tid))
        if not main_entries and not side_entries:
            flash('Moxfield deck appears to be empty.', 'error')
            log_tournament(tid, 'deck_moxfield', 'failure', 'empty deck')
            return redirect(url_for('view_tournament', tid=tid))
        try:
            db_path = ensure_card_database_ready()
        except Exception as exc:
            flash(f'Card database unavailable: {exc}', 'error')
            log_tournament(tid, 'deck_moxfield', 'failure', str(exc))
            return redirect(url_for('view_tournament', tid=tid))
        canonical_main, missing_main = canonicalize_card_group(main_entries, db_path=db_path)
        canonical_side, missing_side = canonicalize_card_group(side_entries, db_path=db_path)
        missing = missing_main + missing_side
        missing_set = sorted({name for name in missing}) if missing else []
        if missing_set:
            flash('Cards not found in local database: ' + ', '.join(missing_set), 'error')
        save_player_deck(
            tp,
            'moxfield',
            canonical_main,
            canonical_side,
            raw_text=None,
            moxfield_url=deck_input,
            submitted=False,
        )
        flash('Deck imported from Moxfield.', 'success')
        log_detail = f'id={deck_id}'
        if missing_set:
            log_detail += '; missing=' + ', '.join(missing_set)
        log_tournament(tid, 'deck_moxfield', 'success', log_detail)
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
            flash(f'Card database unavailable: {exc}', 'error')
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
        user_id_raw = (request.form.get('user_id') or '').strip()
        new_name = (request.form.get('new_player_name') or '').strip()
        new_email = (request.form.get('new_player_email') or '').strip().lower()
        player = None
        created_user = False
        if user_id_raw:
            try:
                player = db.session.get(User, int(user_id_raw))
            except (TypeError, ValueError):
                player = None
            if not player:
                flash('Selected user could not be found.', 'error')
                return redirect(url_for('view_tournament', tid=tid))
        elif new_name:
            email_value = new_email or None
            if email_value and db.session.query(User).filter_by(email=email_value).first():
                flash('Email already registered.', 'error')
                return redirect(url_for('view_tournament', tid=tid))
            role_user = db.session.query(Role).filter_by(name='user').first()
            player = User(name=new_name, email=email_value, role=role_user)
            db.session.add(player)
            db.session.flush()
            created_user = True
        else:
            flash('Select an existing user or enter a name to add a new player.', 'error')
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
        tp = TournamentPlayer(tournament_id=tid, user_id=player.id)
        db.session.add(tp)
        db.session.commit()
        log_tournament(tid, 'add_player_inline', 'success', f'user_id={player.id}')
        flash('Player added to tournament.', 'success')
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
        players = db.session.query(TournamentPlayer).filter_by(tournament_id=tid).all()
        random.shuffle(players)
        tables = [players[i:i+8] for i in range(0, len(players), 8)]
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
        player_count = db.session.query(TournamentPlayer).filter_by(tournament_id=tid, dropped=False).count()
        if player_count == 0:
            flash('No players registered.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        round_limit = t.rounds_override or recommended_rounds(player_count)
        if t.structure == 'single_elim':
            round_limit = 0
        if current_rounds < round_limit:
            next_round_num = current_rounds + 1
            r = Round(tournament_id=tid, number=next_round_num)
            db.session.add(r)
            db.session.commit()
            swiss_pair_round(t, r, db.session)
            flash(f"Paired round {next_round_num}.", "success")
            log_tournament(tid, 'pair_round', 'success', f'round={next_round_num}')
            return redirect(url_for('view_tournament', tid=tid))
        # Elimination rounds
        next_round_num = current_rounds + 1
        if t.structure == 'single_elim':
            if current_rounds == 0:
                players = db.session.query(TournamentPlayer).filter_by(tournament_id=tid, dropped=False).all()
                random.shuffle(players)
                r = Round(tournament_id=tid, number=next_round_num)
                db.session.add(r)
                db.session.commit()
                table = 1
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
            table = 1
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
                table = 1
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
                    for i in range(top_n // 2):
                        p1 = seeds[i]
                        p2 = seeds[top_n - 1 - i]
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
            table = 1
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
        swiss_pair_round(t, r, db.session)
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
            if t.format.lower() == 'commander':
                drop_p1 = bool(request.form.get('drop_p1'))
                drop_p2 = bool(request.form.get('drop_p2'))
                drop_p3 = bool(request.form.get('drop_p3'))
                drop_p4 = bool(request.form.get('drop_p4'))
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
                if request.form.get('drop_p1'):
                    m.player1.dropped = True
                    dropped_ids.append(m.player1.user_id)
                if m.player2_id and request.form.get('drop_p2'):
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
        from .models import User, Tournament, TournamentPlayer, Role
        q = request.args.get('q', '').strip()
        query = db.session.query(User)
        if not current_user.has_permission('users.manage_admins'):
            query = query.filter(User.is_admin == False)
        if q:
            pattern = f"%{q}%"
            query = query.filter(or_(User.name.ilike(pattern), User.email.ilike(pattern)))
        users = query.order_by(User.name).all()
        tournaments = db.session.query(Tournament).order_by(Tournament.name).all()
        roles = db.session.query(Role).order_by(Role.name).all()
        if not current_user.has_permission('users.manage_admins'):
            roles = [r for r in roles if r.name != 'admin']
        can_manage_overrides = current_user.has_permission('admin.permissions')
        return render_template(
            'admin/users.html',
            users=users,
            tournaments=tournaments,
            roles=roles,
            search_query=q,
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
        redirect_url = url_for('admin_users', q=search_query) if search_query else url_for('admin_users')
        return redirect(redirect_url)

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
        redirect_url = url_for('admin_users', q=search_query) if search_query else url_for('admin_users')
        return redirect(redirect_url)

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
                    redirect_target = url_for('admin_users', q=search_query) if search_query else url_for('admin_users')
                    return redirect(redirect_target)
                u.set_password(password)
                u.generate_keys(password)
            u.email = email
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
            log_site('user_update', 'success')
            flash('User updated.', 'success')
        redirect_target = url_for('admin_users', q=search_query) if search_query else url_for('admin_users')
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
        redirect_target = url_for('admin_users', q=search_query) if search_query else url_for('admin_users')
        return redirect(redirect_target)

    return app

app = create_app()
