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
        prev_round = db.session.query(Round).filter_by(tournament_id=tid).order_by(Round.number.desc()).first()
        if prev_round and any(not m.completed for m in prev_round.matches):
            flash('Previous round not completed.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        current_rounds = prev_round.number if prev_round else 0
        player_count = db.session.query(TournamentPlayer).filter_by(tournament_id=tid, dropped=False).count()
        round_limit = t.rounds_override or recommended_rounds(player_count)
        if current_rounds < round_limit:
            next_round_num = current_rounds + 1
            r = Round(tournament_id=tid, number=next_round_num)
            db.session.add(r)
            db.session.commit()
            swiss_pair_round(t, r, db.session)
            flash(f"Paired round {next_round_num}.", "success")
            return redirect(url_for('view_tournament', tid=tid))
        # Elimination rounds
        if not t.cut.startswith('top'):
            flash('Cut not configured.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        winners = []
        for m in prev_round.matches.order_by('table_number'):
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
        next_round_num = current_rounds + 1
        r = Round(tournament_id=tid, number=next_round_num)
        db.session.add(r)
        db.session.commit()
        table = 1
        for i in range(0, len(winners), 2):
            m = Match(round_id=r.id, player1_id=winners[i].id, player2_id=winners[i+1].id, table_number=table)
            db.session.add(m)
            table += 1
        db.session.commit()
        flash(f"Paired round {next_round_num}.", "success")
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/cut-to-top', methods=['POST'])
    def cut_to_top(tid):
        require_admin()
        t = db.session.get(Tournament, tid)
        if not t:
            abort(404)
        if not t.cut.startswith('top'):
            flash('Cut not configured.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        prev_round = db.session.query(Round).filter_by(tournament_id=tid).order_by(Round.number.desc()).first()
        if prev_round and any(not m.completed for m in prev_round.matches):
            flash('Previous round not completed.', 'error')
            return redirect(url_for('view_tournament', tid=tid))
        top_n = int(t.cut[3:])
        standings = [row for row in compute_standings(t, db.session) if not row['tp'].dropped]
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

    @app.route('/t/<int:tid>/round/<int:rid>/repair', methods=['POST'])
    def repair_round(tid, rid):
        require_admin()
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
        swiss_pair_round(t, r, db.session)
        flash('Round re-paired.', 'success')
        return redirect(url_for('view_tournament', tid=tid))

    @app.route('/t/<int:tid>/round/<int:rid>/delete', methods=['POST'])
    def delete_round(tid, rid):
        require_admin()
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
        return render_template('tournament/round.html', t=r.tournament, r=r, has_results=has_results)

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
            if request.form.get('drop_p1'):
                m.player1.dropped = True
            if m.player2_id and request.form.get('drop_p2'):
                m.player2.dropped = True
            # Auto-drop losers in elimination rounds
            t = m.round.tournament
            active = db.session.query(TournamentPlayer).filter_by(
                tournament_id=t.id, dropped=False
            ).count()
            round_limit = t.rounds_override or recommended_rounds(active)
            if m.round.number > round_limit and m.player2_id:
                if p1_wins > p2_wins:
                    m.player2.dropped = True
                elif p2_wins > p1_wins:
                    m.player1.dropped = True
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

    @app.route('/t/<int:tid>/bracket')
    def bracket(tid):
        t = db.session.get(Tournament, tid)
        if not t: abort(404)
        rounds = db.session.query(Round).filter_by(tournament_id=tid).order_by(Round.number).all()
        players = db.session.query(TournamentPlayer).filter_by(tournament_id=tid).all()
        round_limit = t.rounds_override or recommended_rounds(len(players))
        elim_rounds = [r for r in rounds if r.number > round_limit]
        return render_template('tournament/bracket.html', t=t, rounds=elim_rounds)

    @app.route('/admin/users')
    def admin_users():
        require_admin()
        from .models import User, Tournament, TournamentPlayer
        users = db.session.query(User).order_by(User.name).all()
        tournaments = db.session.query(Tournament).order_by(Tournament.name).all()
        return render_template('admin/users.html', users=users, tournaments=tournaments)

    @app.route('/admin/users/<int:uid>/add', methods=['POST'])
    def admin_add_user_to_tournament(uid):
        require_admin()
        from .models import TournamentPlayer
        tid = int(request.form['tournament_id'])
        if not db.session.query(TournamentPlayer).filter_by(user_id=uid, tournament_id=tid).first():
            tp = TournamentPlayer(user_id=uid, tournament_id=tid)
            db.session.add(tp)
            db.session.commit()
        flash('User added to tournament.', 'success')
        return redirect(url_for('admin_users'))

    @app.route('/admin/users/<int:uid>/remove/<int:tid>', methods=['POST'])
    def admin_remove_user_from_tournament(uid, tid):
        require_admin()
        from .models import TournamentPlayer
        tp = db.session.query(TournamentPlayer).filter_by(user_id=uid, tournament_id=tid).first()
        if tp:
            db.session.delete(tp)
            db.session.commit()
        flash('User removed from tournament.', 'success')
        return redirect(url_for('admin_users'))

    return app

app = create_app()
