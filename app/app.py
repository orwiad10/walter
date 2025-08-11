from flask import Flask, render_template, redirect, url_for, request, flash, abort
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, login_required, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
import click

db = SQLAlchemy()
login_manager = LoginManager()

def create_app():
    app = Flask(__name__)
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///mtg_tournament.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['SECRET_KEY'] = os.environ.get('FLASK_SECRET', 'dev-secret-change-me')

    db.init_app(app)
    login_manager.init_app(app)
    login_manager.login_view = 'login'

    from .models import User, Tournament, TournamentPlayer, Round, Match, MatchResult
    from .pairing import swiss_pair_round, recommended_rounds, compute_standings

    @login_manager.user_loader
    def load_user(user_id):
        return db.session.get(User, int(user_id))

    # ---------- CLI ----------
    @app.cli.command('db-init')
    def db_init():
        db.create_all()
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
        u = User(email=email, name="Admin", is_admin=True)
        u.set_password(password)
        db.session.add(u)
        db.session.commit()
        print("Admin created.")

    # ---------- Routes ----------
    @app.route('/')
    def index():
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        return render_template('index.html', tournaments=tournaments)

    @app.route('/register', methods=['GET','POST'])
    def register():
        from .models import User, Tournament, TournamentPlayer
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            name = request.form['name'].strip()
            password = request.form['password']
            if db.session.query(User).filter_by(email=email).first():
                flash("Email already registered", "error")
                return redirect(url_for('register'))
            u = User(email=email, name=name)
            u.set_password(password)
            db.session.add(u)
            db.session.commit()
            tournament_id = request.form.get('tournament_id')
            if tournament_id:
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
                return redirect(url_for('index'))
            flash("Invalid credentials", "error")
        return render_template('login.html')

    @app.route('/logout')
    @login_required
    def logout():
        logout_user()
        return redirect(url_for('index'))

    # ---------- Admin ----------
    def require_admin():
        if not current_user.is_authenticated or not current_user.is_admin:
            abort(403)

    @app.route('/admin/tournaments/new', methods=['GET','POST'])
    def new_tournament():
        require_admin()
        if request.method == 'POST':
            name = request.form['name'].strip()
            fmt = request.form['format']
            cut = request.form.get('cut', 'none')
            t = Tournament(name=name, format=fmt, cut=cut)
            db.session.add(t)
            db.session.commit()
            flash("Tournament created.", "success")
            return redirect(url_for('view_tournament', tid=t.id))
        return render_template('admin/new_tournament.html')

    @app.route('/admin/register-player', methods=['GET', 'POST'])
    def admin_register_player():
        require_admin()
        from .models import User, Tournament, TournamentPlayer
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        if request.method == 'POST':
            email = request.form['email'].strip().lower()
            name = request.form['name'].strip()
            password = request.form['password']
            if db.session.query(User).filter_by(email=email).first():
                flash("Email already registered", "error")
            else:
                u = User(email=email, name=name)
                u.set_password(password)
                db.session.add(u)
                db.session.commit()
                tournament_id = request.form.get('tournament_id')
                if tournament_id:
                    tp = TournamentPlayer(tournament_id=int(tournament_id), user_id=u.id)
                    db.session.add(tp)
                    db.session.commit()
                flash("Player registered.", "success")
                return redirect(url_for('admin_register_player'))
        return render_template('admin/register_player.html', tournaments=tournaments)

    @app.route('/admin/bulk-register', methods=['GET', 'POST'])
    def admin_bulk_register():
        require_admin()
        from .models import User, Tournament, TournamentPlayer
        tournaments = db.session.query(Tournament).order_by(Tournament.created_at.desc()).all()
        if request.method == 'POST':
            tournament_id = int(request.form.get('tournament_id'))
            names_raw = request.form['names']
            count = 0
            for line in names_raw.splitlines():
                name = line.strip()
                if not name:
                    continue
                u = User(name=name)
                db.session.add(u)
                db.session.flush()
                tp = TournamentPlayer(tournament_id=tournament_id, user_id=u.id)
                db.session.add(tp)
                count += 1
            db.session.commit()
            flash(f"Registered {count} players.", "success")
            return redirect(url_for('admin_bulk_register'))
        return render_template('admin/bulk_register_players.html', tournaments=tournaments)

    @app.route('/admin/tournaments/<int:tid>/delete', methods=['POST'])
    def delete_tournament(tid):
        require_admin()
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        db.session.delete(t)
        db.session.commit()
        flash("Tournament deleted.", "success")
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
        return render_template('tournament/view.html', t=t, players=players, rounds=rounds, standings=standings, rec_rounds=rec_rounds)

    @app.route('/t/<int:tid>/join', methods=['POST'])
    @login_required
    def join_tournament(tid):
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        tp = db.session.query(TournamentPlayer).filter_by(tournament_id=tid, user_id=current_user.id).first()
        if tp:
            flash("Already joined", "info")
        else:
            tp = TournamentPlayer(tournament_id=tid, user_id=current_user.id)
            db.session.add(tp)
            db.session.commit()
            flash("Joined tournament", "success")
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/set-rounds', methods=['POST'])
    def set_rounds(tid):
        require_admin()
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        t.rounds_override = int(request.form['rounds'])
        db.session.commit()
        flash("Round count set.", "success")
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/pair-next-round', methods=['POST'])
    def pair_next_round(tid):
        require_admin()
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        current_rounds = db.session.query(Round).filter_by(tournament_id=tid).count()
        player_count = db.session.query(TournamentPlayer).filter_by(tournament_id=tid).count()
        round_limit = t.rounds_override or recommended_rounds(player_count)
        if current_rounds >= round_limit:
            flash("Round limit reached.", "error")
            return redirect(url_for('view_tournament', tid=tid))
        next_round_num = current_rounds + 1
        r = Round(tournament_id=tid, number=next_round_num)
        db.session.add(r)
        db.session.commit()
        swiss_pair_round(t, r, db.session)
        flash(f"Paired round {next_round_num}.", "success")
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/cut-to-top', methods=['POST'])
    def cut_to_top(tid):
        require_admin()
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        if t.cut not in ('top8', 'top4'):
            flash('Cut not configured.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        top_n = 8 if t.cut == 'top8' else 4
        standings = compute_standings(t, db.session)
        if len(standings) < top_n:
            flash('Not enough players for cut.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        next_round_num = db.session.query(Round).filter_by(tournament_id=tid).count() + 1
        r = Round(tournament_id=tid, number=next_round_num)
        db.session.add(r)
        db.session.commit()
        seeds = [row['tp'] for row in standings[:top_n]]
        table = 1
        for i in range(top_n // 2):
            p1 = seeds[i]
            p2 = seeds[top_n - 1 - i]
            m = Match(round_id=r.id, player1_id=p1.id, player2_id=p2.id, table_number=table)
            db.session.add(m)
            table += 1
        db.session.commit()
        flash(f'Cut to top {top_n} paired.', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/match/<int:mid>', methods=['GET','POST'])
    @login_required
    def report_match(mid):
        m = db.session.get(Match, mid)
        if not m: abort(404)
        from .models import TournamentPlayer, MatchResult
        # Only participants or admin can report
        if not current_user.is_admin and current_user.id not in (m.player1.user_id, m.player2.user_id):
            abort(403)
        if request.method == 'POST':
            p1_wins = int(request.form['p1_wins'])
            p2_wins = int(request.form['p2_wins'])
            draws   = int(request.form.get('draws', 0))
            m.result = MatchResult(player1_wins=p1_wins, player2_wins=p2_wins, draws=draws)
            m.completed = True
            db.session.commit()
            flash("Result submitted.", "success")
            return redirect(url_for('view_tournament', tid=m.round.tournament_id))
        return render_template('match/report.html', m=m)

    @app.route('/t/<int:tid>/standings')
    def standings(tid):
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        standings = compute_standings(t, db.session)
        return render_template('tournament/standings.html', t=t, standings=standings)

    return app

app = create_app()
