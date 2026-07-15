import json
import random
from itertools import product

from sqlalchemy import select
from sqlalchemy.dialects import mysql

from app.app import db
from app.models import Tournament, User, TournamentPlayer, Role, Round, Match, MatchResult, Venue, SiteLog, TournamentLog
from app.pairing import pair_round, compute_standings, draft_seating_tables, seeded_cut_pairs
from datetime import datetime


def test_my_tournaments_query_uses_mysql_portable_null_ordering():
    statement = (
        select(TournamentPlayer)
        .join(Tournament)
        .filter(TournamentPlayer.user_id == 1)
        .order_by(Tournament.start_time.is_(None), Tournament.start_time.desc(), Tournament.created_at.desc())
    )

    compiled = str(statement.compile(dialect=mysql.dialect()))

    assert 'NULLS LAST' not in compiled
    assert 'tournament.start_time IS NULL' in compiled


def test_tournament_create_pairing_standings(session):
    role_user = session.query(Role).filter_by(name='user').first()
    # create tournament
    t = Tournament(name='Test Event', format='Constructed')
    session.add(t)
    session.commit()

    # add players
    players = []
    for i in range(2):
        u = User(email=f'p{i}@ex.com', name=f'P{i}', role=role_user)
        session.add(u)
        session.commit()
        tp = TournamentPlayer(tournament_id=t.id, user_id=u.id)
        session.add(tp)
        session.commit()
        players.append(tp)

    # round 1 pairing
    r1 = Round(tournament_id=t.id, number=1)
    session.add(r1)
    session.commit()
    matches = pair_round(t, r1, session)
    assert len(matches) == 1

    # record a result
    m = matches[0]
    res = MatchResult(player1_wins=2, player2_wins=0)
    m.result = res
    m.completed = True
    session.commit()

    standings = compute_standings(t, session)
    points = [row['points'] for row in standings]
    assert sorted(points) == [0, 3]

    # delete tournament
    session.delete(t)
    session.commit()
    assert session.query(Tournament).count() == 0


def test_round_robin_pairings_unique(session):
    role_user = session.query(Role).filter_by(name='user').first()
    t = Tournament(name='Round Robin Event', format='Constructed', pairing_type='round_robin')
    session.add(t)
    session.commit()

    for i in range(4):
        u = User(email=f'rr{i}@ex.com', name=f'RR{i}', role=role_user)
        session.add(u)
        session.commit()
        tp = TournamentPlayer(tournament_id=t.id, user_id=u.id)
        session.add(tp)
        session.commit()

    seen_pairs = set()
    total_rounds = 3
    for rnd in range(1, total_rounds + 1):
        r = Round(tournament_id=t.id, number=rnd)
        session.add(r)
        session.commit()
        matches = pair_round(t, r, session)
        assert matches
        for m in matches:
            if m.player2_id is None:
                continue
            pair = frozenset({m.player1_id, m.player2_id})
            assert pair not in seen_pairs
            seen_pairs.add(pair)


def test_tournament_start_time(session):
    start = datetime(2024, 1, 1, 10, 0)
    t = Tournament(name='Start Event', format='Constructed', start_time=start)
    session.add(t)
    session.commit()
    fetched = session.get(Tournament, t.id)
    assert fetched.start_time == start


def test_swiss_pairings_avoid_repeats(session):
    role_user = session.query(Role).filter_by(name='user').first()
    t = Tournament(name='Swiss Event', format='Constructed')
    session.add(t)
    session.commit()

    random.seed(123)

    for i in range(4):
        u = User(email=f'swiss{i}@ex.com', name=f'Swiss{i}', role=role_user)
        session.add(u)
        session.commit()
        tp = TournamentPlayer(tournament_id=t.id, user_id=u.id)
        session.add(tp)
        session.commit()

    r1 = Round(tournament_id=t.id, number=1)
    session.add(r1)
    session.commit()
    matches_r1 = pair_round(t, r1, session)
    assert len(matches_r1) == 2
    first_round_pairs = {
        frozenset({m.player1_id, m.player2_id})
        for m in matches_r1
        if m.player2_id is not None
    }

    # winners win 2-0 to avoid draws
    for match in matches_r1:
        result = MatchResult(player1_wins=2, player2_wins=0)
        match.result = result
        match.completed = True
    session.commit()

    r2 = Round(tournament_id=t.id, number=2)
    session.add(r2)
    session.commit()
    matches_r2 = pair_round(t, r2, session)
    assert len(matches_r2) == 2
    for match in matches_r2:
        if match.player2_id is None:
            continue
        pair = frozenset({match.player1_id, match.player2_id})
        assert pair not in first_round_pairs


def test_swiss_32_players_all_round_result_combinations(session):
    role_user = session.query(Role).filter_by(name='user').first()
    tournament = Tournament(name='Swiss 32 Combo Event', format='Constructed')
    session.add(tournament)
    session.commit()

    random.seed(2026)

    for i in range(32):
        user = User(email=f'combo32_{i}@ex.com', name=f'Combo32_{i}', role=role_user)
        session.add(user)
        session.commit()
        session.add(TournamentPlayer(tournament_id=tournament.id, user_id=user.id))
        session.commit()

    total_rounds = 5
    round_matches = {}
    for round_number in range(1, total_rounds + 1):
        rnd = Round(tournament_id=tournament.id, number=round_number)
        session.add(rnd)
        session.commit()
        matches = pair_round(tournament, rnd, session)
        assert len(matches) == 16
        round_matches[round_number] = matches

        for match in matches:
            match.result = MatchResult(player1_wins=2, player2_wins=0)
            match.completed = True
        session.commit()

    for choices in product((0, 1), repeat=total_rounds):
        for round_number, player1_wins in enumerate(choices, start=1):
            for match in round_matches[round_number]:
                if player1_wins:
                    match.result = MatchResult(player1_wins=2, player2_wins=0)
                else:
                    match.result = MatchResult(player1_wins=0, player2_wins=2)
                match.completed = True
        session.commit()

        standings = compute_standings(tournament, session)
        assert len(standings) == 32
        assert all(0 <= row['points'] <= 15 for row in standings)

def test_swiss_no_second_bye_when_alternative_exists(session):
    role_user = session.query(Role).filter_by(name='user').first()
    t = Tournament(name='Swiss Bye Event', format='Constructed')
    session.add(t)
    session.commit()

    random.seed(7)
    players = []
    for i in range(5):
        u = User(email=f'bye{i}@ex.com', name=f'Bye{i}', role=role_user)
        session.add(u)
        session.commit()
        tp = TournamentPlayer(tournament_id=t.id, user_id=u.id)
        session.add(tp)
        session.commit()
        players.append(tp)

    bye_counts = {tp.id: 0 for tp in players}
    for rnd in range(1, 3):
        r = Round(tournament_id=t.id, number=rnd)
        session.add(r)
        session.commit()
        matches = pair_round(t, r, session)
        for m in matches:
            if m.player2_id is None:
                bye_counts[m.player1_id] += 1
            else:
                m.result = MatchResult(player1_wins=2, player2_wins=0)
                m.completed = True
        session.commit()

    assert max(bye_counts.values()) == 1


def test_swiss_all_unique_until_cut_then_repeat_allowed(session):
    role_user = session.query(Role).filter_by(name='user').first()
    t = Tournament(name='Swiss Cut Event', format='Constructed', cut='top4', rounds_override=2)
    session.add(t)
    session.commit()

    random.seed(21)
    for i in range(4):
        u = User(email=f'cut{i}@ex.com', name=f'Cut{i}', role=role_user)
        session.add(u)
        session.commit()
        tp = TournamentPlayer(tournament_id=t.id, user_id=u.id)
        session.add(tp)
        session.commit()

    seen_pairs = set()
    for rnd in range(1, 4):
        r = Round(tournament_id=t.id, number=rnd)
        session.add(r)
        session.commit()
        matches = pair_round(t, r, session)

        for m in matches:
            if m.player2_id is None:
                continue
            pair = frozenset({m.player1_id, m.player2_id})
            if rnd <= 2:
                assert pair not in seen_pairs
            seen_pairs.add(pair)
            m.result = MatchResult(player1_wins=2, player2_wins=0)
            m.completed = True
        session.commit()


def _add_tournament_players(session, tournament, count, prefix):
    role_user = session.query(Role).filter_by(name='user').first()
    players = []
    for i in range(count):
        user = User(email=f'{prefix}{i}@ex.com', name=f'{prefix}{i}', role=role_user)
        session.add(user)
        session.commit()
        player = TournamentPlayer(tournament_id=tournament.id, user_id=user.id)
        session.add(player)
        session.commit()
        players.append(player)
    return players


def test_draft_round_one_uses_big_x_little_x_from_saved_seating(session):
    tournament = Tournament(name='Draft Seating Event', format='Draft')
    session.add(tournament)
    session.commit()
    players = _add_tournament_players(session, tournament, 8, 'draftseat')
    tournament.pairing_options = json.dumps({'draft_seating': [[player.id for player in players]]})
    session.commit()

    rnd = Round(tournament_id=tournament.id, number=1)
    session.add(rnd)
    session.commit()

    matches = pair_round(tournament, rnd, session)
    pairs = [(match.player1_id, match.player2_id) for match in sorted(matches, key=lambda m: m.table_number)]

    assert pairs == [
        (players[0].id, players[4].id),
        (players[1].id, players[5].id),
        (players[2].id, players[6].id),
        (players[3].id, players[7].id),
    ]


def test_draft_round_one_uses_big_x_little_x_for_each_pod_with_partial_pod(session, monkeypatch):
    tournament = Tournament(name='Partial Pod Draft Event', format='Draft')
    session.add(tournament)
    session.commit()
    players = _add_tournament_players(session, tournament, 15, 'draftpartial')
    tournament.pairing_options = json.dumps({
        'draft_seating': [
            [player.id for player in players[:8]],
            [player.id for player in players[8:]],
        ]
    })
    session.commit()
    monkeypatch.setattr('app.pairing.random.randrange', lambda stop: 0)

    rnd = Round(tournament_id=tournament.id, number=1)
    session.add(rnd)
    session.commit()

    matches = pair_round(tournament, rnd, session)
    pairs = [(match.player1_id, match.player2_id) for match in sorted(matches, key=lambda m: m.table_number)]

    assert pairs == [
        (players[0].id, players[4].id),
        (players[1].id, players[5].id),
        (players[2].id, players[6].id),
        (players[3].id, players[7].id),
        (players[8].id, players[11].id),
        (players[12].id, players[9].id),
        (players[10].id, players[13].id),
        (players[14].id, None),
    ]


def test_draft_seating_is_persisted_for_round_one_pairings(session):
    tournament = Tournament(name='Persisted Draft Seating Event', format='Draft')
    session.add(tournament)
    session.commit()
    _add_tournament_players(session, tournament, 8, 'draftpersist')

    random.seed(99)
    seating = draft_seating_tables(tournament, session)
    saved_seating = [[player.id for player in table] for table in seating]
    session.commit()

    rnd = Round(tournament_id=tournament.id, number=1)
    session.add(rnd)
    session.commit()
    matches = pair_round(tournament, rnd, session)
    pairs = [(match.player1_id, match.player2_id) for match in sorted(matches, key=lambda m: m.table_number)]

    table = saved_seating[0]
    assert pairs == [
        (table[0], table[4]),
        (table[1], table[5]),
        (table[2], table[6]),
        (table[3], table[7]),
    ]
    assert json.loads(tournament.pairing_options)['draft_seating'] == saved_seating


def test_seeded_cut_pairs_first_against_last():
    seeds = list(range(1, 9))

    assert seeded_cut_pairs(seeds) == [(1, 8), (2, 7), (3, 6), (4, 5)]

def test_bulk_register_adds_existing_users(client, session):
    manager_role = session.query(Role).filter_by(name='manager').one()
    user_role = session.query(Role).filter_by(name='user').one()
    manager = User(email='manager-bulk@example.com', name='Bulk Manager', role=manager_role)
    manager.set_password('secret')
    existing_one = User(email='existing1@example.com', name='Existing One', role=user_role)
    existing_two = User(email='existing2@example.com', name='Existing Two', role=user_role)
    tournament = Tournament(name='Bulk Add Event', format='Constructed')
    session.add_all([manager, existing_one, existing_two, tournament])
    session.commit()

    with client:
        assert client.post('/login', data={'email': manager.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            '/admin/bulk-register',
            data={
                'tournament_id': str(tournament.id),
                'existing_user_ids': [str(existing_one.id), str(existing_two.id)],
                'names': 'New Person',
            },
            follow_redirects=True,
        )

    assert response.status_code == 200
    tournament_player_ids = {
        entry.user_id
        for entry in session.query(TournamentPlayer).filter_by(tournament_id=tournament.id).all()
    }
    assert existing_one.id in tournament_player_ids
    assert existing_two.id in tournament_player_ids
    new_user = session.query(User).filter_by(name='New Person').one()
    assert new_user.id in tournament_player_ids


def test_bulk_edit_tournament_controls_stay_bound_to_bulk_form(client, session):
    bulk_role = Role(
        name='bulk form manager',
        permissions=json.dumps({'tournaments.bulk_manage': True, 'tournaments.manage': True}),
        level=100,
    )
    user = User(email='bulk-form-manager@example.com', name='Bulk Form Manager', role=bulk_role)
    user.set_password('secret')
    tournament = Tournament(name='Bulk Form Event', format='Modern')
    venue = Venue(name='Bulk Form Venue')
    session.add_all([bulk_role, user, tournament, venue])
    session.commit()

    with client:
        assert client.post('/login', data={'email': user.email, 'password': 'secret'}).status_code == 302
        response = client.get('/')

    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'id="bulk-tournament-form"' in html
    assert 'name="bulk_action" required' in html
    assert 'name="bulk_venue_id"' not in html
    assert 'Venue assignment is managed from each venue page.' in html
    assert f'name="tournament_ids" value="{tournament.id}"' in html
    assert html.index('<form id="bulk-tournament-form"') < html.index('<ul class="cards">')
    assert html.index('<ul class="cards">') < html.index('</form>', html.index('<ul class="cards">'))



def test_tournament_manager_can_bulk_add_tournament_to_venue(client, session):
    manager_role = session.query(Role).filter_by(name='manager').one()
    user = User(email='manager-bulk-venue@example.com', name='Manager Bulk Venue', role=manager_role)
    user.set_password('secret')
    tournament = Tournament(name='Manager Bulk Venue Event', format='Modern')
    venue = Venue(name='Manager Bulk Venue')
    session.add_all([user, tournament, venue])
    session.commit()

    with client:
        assert client.post('/login', data={'email': user.email, 'password': 'secret'}).status_code == 302
        page = client.get(f'/admin/venues/{venue.id}')
        response = client.post(
            f'/admin/venues/{venue.id}/tournaments/bulk-add',
            data={
                'tournament_ids': [str(tournament.id)],
            },
        )

    html = page.get_data(as_text=True)
    assert page.status_code == 200
    assert 'Bulk Add Tournaments' in html
    assert f'name="tournament_ids" value="{tournament.id}"' in html
    assert response.status_code == 302
    assert response.location == f'/admin/venues/{venue.id}'
    session.expire_all()
    assert session.get(Tournament, tournament.id).venue_id == venue.id

def test_bulk_edit_tournaments_adds_selected_tournament_to_venue(client, session):
    bulk_role = Role(
        name='bulk venue manager',
        permissions=json.dumps({'tournaments.bulk_manage': True, 'venues.manage': True}),
        level=100,
    )
    user = User(email='bulk-venue-manager@example.com', name='Bulk Venue Manager', role=bulk_role)
    user.set_password('secret')
    tournament = Tournament(name='Bulk Venue Event', format='Modern')
    venue = Venue(name='Bulk Venue')
    session.add_all([bulk_role, user, tournament, venue])
    session.commit()

    with client:
        assert client.post('/login', data={'email': user.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            f'/admin/venues/{venue.id}/tournaments/bulk-add',
            data={
                'tournament_ids': [str(tournament.id)],
            },
        )

    assert response.status_code == 302
    assert response.location == f'/admin/venues/{venue.id}'
    session.expire_all()
    assert session.get(Tournament, tournament.id).venue_id == venue.id


def test_bulk_edit_tournaments_adds_multiple_unique_tournaments_to_venue(client, session):
    bulk_role = Role(
        name='bulk multi venue manager',
        permissions=json.dumps({'tournaments.bulk_manage': True, 'venues.manage': True}),
        level=100,
    )
    user = User(email='bulk-multi-venue-manager@example.com', name='Bulk Multi Venue Manager', role=bulk_role)
    user.set_password('secret')
    first = Tournament(name='Bulk Venue Event One', format='Modern')
    second = Tournament(name='Bulk Venue Event Two', format='Legacy')
    venue = Venue(name='Bulk Multi Venue')
    session.add_all([bulk_role, user, first, second, venue])
    session.commit()

    with client:
        assert client.post('/login', data={'email': user.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            f'/admin/venues/{venue.id}/tournaments/bulk-add',
            data={
                'tournament_ids': [str(first.id), str(second.id)],
            },
        )

    assert response.status_code == 302
    assert response.location == f'/admin/venues/{venue.id}'
    session.expire_all()
    assert session.get(Tournament, first.id).venue_id == venue.id
    assert session.get(Tournament, second.id).venue_id == venue.id


def test_bulk_edit_tournaments_ignores_duplicate_tournament_ids(client, session):
    bulk_role = Role(
        name='bulk duplicate venue manager',
        permissions=json.dumps({'tournaments.bulk_manage': True, 'venues.manage': True}),
        level=100,
    )
    user = User(email='bulk-duplicate-venue-manager@example.com', name='Bulk Duplicate Venue Manager', role=bulk_role)
    user.set_password('secret')
    tournament = Tournament(name='Bulk Duplicate Venue Event', format='Modern')
    venue = Venue(name='Bulk Duplicate Venue')
    session.add_all([bulk_role, user, tournament, venue])
    session.commit()

    with client:
        assert client.post('/login', data={'email': user.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            f'/admin/venues/{venue.id}/tournaments/bulk-add',
            data={
                'tournament_ids': [str(tournament.id), str(tournament.id), str(tournament.id)],
            },
        )

    assert response.status_code == 302
    assert response.location == f'/admin/venues/{venue.id}'
    session.expire_all()
    assert session.get(Tournament, tournament.id).venue_id == venue.id



def test_venue_bulk_add_keeps_assignment_when_audit_logging_fails(client, session, monkeypatch):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(
        email='bulk-log-failure-admin@example.com',
        name='Bulk Log Failure Admin',
        role=admin_role,
        is_admin=True,
    )
    admin.set_password('secret')
    tournament = Tournament(name='Audit Failure Venue Event', format='Modern')
    venue = Venue(name='Audit Failure Venue')
    session.add_all([admin, tournament, venue])
    session.commit()

    original_add = db.session.add

    def fail_on_audit_log(instance):
        if isinstance(instance, (SiteLog, TournamentLog)):
            raise RuntimeError('simulated audit log failure')
        return original_add(instance)

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        monkeypatch.setattr(db.session, 'add', fail_on_audit_log)
        response = client.post(
            f'/admin/venues/{venue.id}/tournaments/bulk-add',
            data={
                'tournament_ids': [str(tournament.id)],
            },
        )

    assert response.status_code == 302
    assert response.location == f'/admin/venues/{venue.id}'
    session.expire_all()
    assert session.get(Tournament, tournament.id).venue_id == venue.id


def test_bulk_delete_tournaments_removes_selected_tournaments(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(
        email='bulk-delete-admin@example.com',
        name='Bulk Delete Admin',
        role=admin_role,
        is_admin=True,
    )
    admin.set_password('secret')
    first = Tournament(name='Bulk Delete Event One', format='Modern')
    second = Tournament(name='Bulk Delete Event Two', format='Legacy')
    session.add_all([admin, first, second])
    session.commit()
    first_id = first.id
    second_id = second.id

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            '/admin/tournaments/bulk',
            data={
                'bulk_action': 'delete',
                'tournament_ids': [str(first_id), str(second_id)],
            },
        )

    assert response.status_code == 302
    assert response.location == '/'
    session.expire_all()
    assert session.get(Tournament, first_id) is None
    assert session.get(Tournament, second_id) is None
    assert session.query(TournamentLog).filter_by(tournament_id=first_id, action='bulk_delete').one()
    assert session.query(SiteLog).filter_by(action='bulk_delete_tournament').count() == 2


def test_bulk_delete_keeps_deletion_when_audit_logging_fails(client, session, monkeypatch):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(
        email='bulk-delete-log-failure-admin@example.com',
        name='Bulk Delete Log Failure Admin',
        role=admin_role,
        is_admin=True,
    )
    admin.set_password('secret')
    tournament = Tournament(name='Audit Failure Delete Event', format='Modern')
    session.add_all([admin, tournament])
    session.commit()
    tournament_id = tournament.id

    original_add = db.session.add

    def fail_on_audit_log(instance):
        if isinstance(instance, (SiteLog, TournamentLog)):
            raise RuntimeError('simulated audit log failure')
        return original_add(instance)

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        monkeypatch.setattr(db.session, 'add', fail_on_audit_log)
        response = client.post(
            '/admin/tournaments/bulk',
            data={
                'bulk_action': 'delete',
                'tournament_ids': [str(tournament_id)],
            },
        )

    assert response.status_code == 302
    assert response.location == '/'
    session.expire_all()
    assert session.get(Tournament, tournament_id) is None


def test_venue_bulk_add_rejects_empty_tournament_selection(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(
        email='bulk-invalid-venue-admin@example.com',
        name='Bulk Invalid Admin',
        role=admin_role,
        is_admin=True,
    )
    admin.set_password('secret')
    tournament = Tournament(name='Invalid Venue Event', format='Modern')
    venue = Venue(name='Existing Venue')
    session.add_all([admin, tournament, venue])
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            f'/admin/venues/{venue.id}/tournaments/bulk-add',
            data={
                'tournament_ids': [],
            },
        )

    assert response.status_code == 302
    assert response.location == f'/admin/venues/{venue.id}'
    session.expire_all()
    assert session.get(Tournament, tournament.id).venue_id is None


def test_tournament_name_uses_format_timestamp_and_venue(client, session):
    from app.models import Venue, User, Role, Tournament

    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='admin-tournament-name@example.com', name='Tournament Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    venue = Venue(name='Convention Center')
    session.add_all([admin, venue])
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            '/admin/tournaments/new',
            data={
                'name': 'Store Championship',
                'format': 'Modern',
                'structure': 'swiss',
                'cut': 'top8',
                'commander_points': '3,2,1,0,1',
                'round_length': '50',
                'start_table_number': '1',
                'start_time': '2026-06-02T19:30',
                'venue_id': str(venue.id),
            },
        )

    assert response.status_code == 302
    tournament = session.query(Tournament).filter_by(format='Modern').one()
    assert tournament.name == 'Modern - 20260602 - 1930 - Store Championship'
    assert tournament.venue_id == venue.id


def test_tournament_edit_auto_fills_lowest_contiguous_table_range(client, session, app):
    app.config['LAST_TABLE_NUMBER'] = 20
    admin_role = session.query(Role).filter_by(name='admin').one()
    user_role = session.query(Role).filter_by(name='user').one()
    admin = User(email='admin-table-fill@example.com', name='Table Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    blocker_one = Tournament(name='Blocker One', format='Modern', start_table_number=1)
    blocker_two = Tournament(name='Blocker Two', format='Modern', start_table_number=4)
    target = Tournament(name='Target Tables', format='Modern', start_table_number=10)
    session.add_all([admin, blocker_one, blocker_two, target])
    session.commit()
    for tournament in (blocker_one, blocker_two, target):
        for i in range(4):
            user = User(email=f'table-{tournament.id}-{i}@example.com', name=f'Table {tournament.id} {i}', role=user_role)
            session.add(user)
            session.flush()
            session.add(TournamentPlayer(tournament_id=tournament.id, user_id=user.id))
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            f'/admin/tournaments/{target.id}/edit',
            data={
                'name': 'Target Tables',
                'format': 'Modern',
                'structure': 'swiss',
                'cut': 'none',
                'round_length': '50',
                'start_table_number': '',
            },
        )

    assert response.status_code == 302
    session.refresh(target)
    assert target.start_table_number == 6


def test_duplicate_booth_numbers_are_blocked_across_artists_and_vendors(client, session):
    from app.models import ArtistProfile, Vendor

    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='admin-booth@example.com', name='Booth Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    venue = Venue(name='Booth Venue')
    vendor = Vendor(name='Existing Vendor', venue=venue, booth_number='12')
    session.add_all([admin, venue, vendor])
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            '/admin/venues/artists',
            data={
                'name': 'Duplicate Artist',
                'venue_id': str(venue.id),
                'booth_number': '12',
            },
            follow_redirects=True,
        )

    assert response.status_code == 200
    assert b'already assigned to vendor Existing Vendor' in response.data
    assert session.query(ArtistProfile).filter_by(name='Duplicate Artist').first() is None


def test_tournament_join_link_uses_local_qr_image(client, session):
    tournament = Tournament(name='Local QR Event', format='Constructed')
    session.add(tournament)
    session.commit()

    response = client.get(f'/t/{tournament.id}/join-link')

    assert response.status_code == 200
    html = response.get_data(as_text=True)
    assert f'src="/t/{tournament.id}/join-qr.png"' in html
    assert 'api.qrserver.com' not in html


def test_tournament_join_qr_returns_png(client, session):
    tournament = Tournament(name='PNG QR Event', format='Constructed')
    session.add(tournament)
    session.commit()

    response = client.get(f'/t/{tournament.id}/join-qr.png')

    assert response.status_code == 200
    assert response.mimetype == 'image/png'
    assert response.data.startswith(b'\x89PNG\r\n\x1a\n')
    assert len(response.data) > 100


def test_player_join_qr_only_visible_to_tournament_managers(client, session):
    manager_role = session.query(Role).filter_by(name='manager').one()
    user_role = session.query(Role).filter_by(name='user').one()
    manager = User(email='qr-manager@example.com', name='QR Manager', role=manager_role)
    manager.set_password('secret')
    player = User(email='qr-player@example.com', name='QR Player', role=user_role)
    player.set_password('secret')
    tournament = Tournament(name='QR Visibility Event', format='Constructed')
    session.add_all([manager, player, tournament])
    session.commit()

    with client:
        assert client.post('/login', data={'email': player.email, 'password': 'secret'}).status_code == 302
        response = client.get(f'/t/{tournament.id}')
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'Player Join QR' not in html
        assert 'placeholder="Passcode"' in html

        client.get('/logout')
        assert client.post('/login', data={'email': manager.email, 'password': 'secret'}).status_code == 302
        response = client.get(f'/t/{tournament.id}')
        assert response.status_code == 200
        html = response.get_data(as_text=True)
        assert 'Player Join QR' in html


def test_home_active_count_matches_active_tournament_page_for_legacy_completed_tournaments(session, client):
    role_admin = session.query(Role).filter_by(name='admin').first()
    role_user = session.query(Role).filter_by(name='user').first()
    admin = User(email='legacy-admin@example.com', name='Legacy Admin', role=role_admin, is_admin=True)
    admin.set_password('secret')
    tournament = Tournament(name='Legacy Completed Event', format='Constructed', rounds_override=1)
    session.add_all([admin, tournament])
    session.commit()

    player_one = User(email='legacy-player-one@example.com', name='Legacy Player One', role=role_user)
    player_two = User(email='legacy-player-two@example.com', name='Legacy Player Two', role=role_user)
    session.add_all([player_one, player_two])
    session.commit()

    tournament_player_one = TournamentPlayer(tournament_id=tournament.id, user_id=player_one.id)
    tournament_player_two = TournamentPlayer(tournament_id=tournament.id, user_id=player_two.id)
    session.add_all([tournament_player_one, tournament_player_two])
    session.commit()

    result = MatchResult(player1_wins=2, player2_wins=0)
    round_one = Round(tournament_id=tournament.id, number=1)
    session.add_all([result, round_one])
    session.commit()
    session.add(Match(
        round_id=round_one.id,
        player1_id=tournament_player_one.id,
        player2_id=tournament_player_two.id,
        table_number=1,
        completed=True,
        result_id=result.id,
    ))
    session.commit()

    assert tournament.ended_at is None
    assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302

    home_response = client.get('/home')
    active_response = client.get('/')

    assert home_response.status_code == 200
    assert active_response.status_code == 200
    assert b'<span>Active tournaments</span><strong>0</strong>' in home_response.data
    assert b'Legacy Completed Event' not in active_response.data
