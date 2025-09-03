from flask import Flask, render_template, redirect, url_for, request, flash, abort
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
from sqlalchemy import inspect, text


db = SQLAlchemy()
login_manager = LoginManager()
PASSWORD_KEY = None
PASSWORD_SEED = None


def create_app():
    app = Flask(__name__)
    db_file = os.environ.get('MTG_DB_PATH', 'mtg_tournament.db')
    log_db_file = os.environ.get('MTG_LOG_DB_PATH', db_file.replace('.db', '_logs.db'))
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_file}'
    app.config['SQLALCHEMY_BINDS'] = {'logs': f'sqlite:///{log_db_file}'}
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
        if 'user' in inspector.get_table_names():
            columns = [c['name'] for c in inspector.get_columns('user')]
            if 'break_end' not in columns:
                db.session.execute(text('ALTER TABLE user ADD COLUMN break_end DATETIME'))
                db.session.commit()

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
        SiteLog,
        TournamentLog,
    )
    from .pairing import swiss_pair_round, recommended_rounds, compute_standings, player_points

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ---------- CLI ----------
    @app.cli.command('db-init')
    def db_init():
        db.create_all()
        # Ensure default roles
        for name, perms in DEFAULT_ROLE_PERMISSIONS.items():
            if not db.session.query(Role).filter_by(name=name).first():
                r = Role(name=name, permissions=json.dumps(perms))
                db.session.add(r)
        db.session.commit()
        # Ensure a default admin account exists for first-time login
        if not db.session.query(User).filter_by(
            email="admin@example.com"
        ).first():
            admin_role = db.session.query(Role).filter_by(name='admin').first()
            u = User(email="admin@example.com", name="Admin", role=admin_role, is_admin=True)
            u.set_password("admin123")
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
            if db.session.query(User).filter_by(email=email).first():
                flash("Email already registered", "error")
                log_site('register', 'failure', 'email exists')
                return redirect(url_for('register'))
            role_user = db.session.query(Role).filter_by(name='user').first()
            u = User(email=email, name=name, role=role_user)
            u.set_password(password)
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
                log_site('login', 'success')
                return redirect(url_for('index'))
            flash("Invalid credentials", "error")
            log_site('login', 'failure', 'invalid credentials')
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        log_site('logout', 'success')
        return redirect(url_for('index'))

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
            start_time = datetime.fromisoformat(start_time_str) if start_time_str else None
            t = Tournament(name=name, format=fmt, cut=cut, structure=structure,
                           commander_points=commander_points,
                           round_length=round_length,
                           draft_time=int(draft_time) if draft_time else None,
                           deck_build_time=int(deck_build_time) if deck_build_time else None,
                           start_time=start_time)
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
            t.start_time = datetime.fromisoformat(start_time_str) if start_time_str else None
            t.draft_time = int(draft_time) if draft_time else None
            t.deck_build_time = int(deck_build_time) if deck_build_time else None
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

    @app.route('/admin/register-player', methods=['GET', 'POST'])
    def admin_register_player():
        require_permission('tournaments.manage')
        from .models import User, Tournament, TournamentPlayer, Role
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            name = request.form['name'].strip()
            password = request.form['password']
            if db.session.query(User).filter_by(email=email).first():
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
            perms = {}
            for cat, items in PERMISSION_GROUPS.items():
                for perm in items:
                    key = f"{cat}.{perm}"
                    perms[key] = bool(request.form.get(key))
            role = Role(name=name, permissions=json.dumps(perms))
            db.session.add(role)
            db.session.commit()
            flash('Role created.', 'success')
            log_site('role_create', 'success', name)
            return redirect(url_for('permissions'))
        roles = db.session.query(Role).order_by(Role.name).all()
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
        if current_user.is_authenticated:
            is_player = any(p.user_id == current_user.id for p in players)
            show_passcode = current_user.has_permission('tournaments.manage') or is_player
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
        return render_template('tournament/view.html', t=t, players=players, rounds=rounds,
                               standings=standings, rec_rounds=rec_rounds,
                               timer_end=timer_end, timer_type=timer_type,
                               timer_remaining=timer_remaining,
                               is_player=is_player, show_passcode=show_passcode,
                               floor_judges=floor_judges,
                               server_now=datetime.utcnow())

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
            tp = TournamentPlayer(tournament_id=tid, user_id=current_user.id)
            db.session.add(tp)
            db.session.commit()
            flash("Joined tournament", "success")
            log_tournament(tid, 'join', 'success')
            log_site('join_tournament', 'success')
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
        if current_user.has_permission('users.manage_admins'):
            users = db.session.query(User).order_by(User.name).all()
        else:
            users = db.session.query(User).filter(User.is_admin == False).order_by(User.name).all()
        tournaments = db.session.query(Tournament).order_by(Tournament.name).all()
        roles = db.session.query(Role).order_by(Role.name).all()
        if not current_user.has_permission('users.manage_admins'):
            roles = [r for r in roles if r.name != 'admin']
        return render_template('admin/users.html', users=users, tournaments=tournaments, roles=roles)

    @app.route('/admin/users/<int:uid>/add', methods=['POST'])
    def admin_add_user_to_tournament(uid):
        require_permission('users.manage')
        from .models import TournamentPlayer, User
        target = db.session.get(User, uid)
        if target.is_admin and not current_user.has_permission('users.manage_admins'):
            abort(403)
        tid = int(request.form['tournament_id'])
        if not db.session.query(TournamentPlayer).filter_by(user_id=uid, tournament_id=tid).first():
            tp = TournamentPlayer(user_id=uid, tournament_id=tid)
            db.session.add(tp)
            db.session.commit()
        flash('User added to tournament.', 'success')
        return redirect(url_for('admin_users'))

    @app.route('/admin/users/<int:uid>/remove/<int:tid>', methods=['POST'])
    def admin_remove_user_from_tournament(uid, tid):
        require_permission('users.manage')
        from .models import TournamentPlayer, User
        target = db.session.get(User, uid)
        if target.is_admin and not current_user.has_permission('users.manage_admins'):
            abort(403)
        tp = db.session.query(TournamentPlayer).filter_by(user_id=uid, tournament_id=tid).first()
        if tp:
            db.session.delete(tp)
            db.session.commit()
        flash('User removed from tournament.', 'success')
        return redirect(url_for('admin_users'))

    @app.route('/admin/users/<int:uid>/update', methods=['POST'])
    def admin_update_user(uid):
        require_permission('users.manage')
        from .models import User, Role
        u = db.session.get(User, uid)
        if not u:
            abort(404)
        if u.is_admin and not current_user.has_permission('users.manage_admins'):
            abort(403)
        email = request.form.get('email', '').strip().lower() or None
        if email and db.session.query(User).filter(User.email == email, User.id != uid).first():
            flash('Email already registered.', 'error')
        else:
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
            db.session.commit()
            log_site('user_update', 'success')
            flash('User updated.', 'success')
        return redirect(url_for('admin_users'))

    @app.route('/admin/users/<int:uid>/delete', methods=['POST'])
    def admin_delete_user(uid):
        require_permission('users.manage')
        from .models import User
        u = db.session.get(User, uid)
        if not u:
            abort(404)
        if u.is_admin and not current_user.has_permission('users.manage_admins'):
            abort(403)
        for tp in list(u.tournament_entries):
            db.session.delete(tp)
        db.session.delete(u)
        db.session.commit()
        flash('User deleted.', 'success')
        return redirect(url_for('admin_users'))

    return app

app = create_app()
