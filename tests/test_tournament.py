import json
import random
from itertools import product

from app.app import db
from app.models import Tournament, User, TournamentPlayer, Role, Round, MatchResult, Venue
from app.pairing import pair_round, compute_standings
from datetime import datetime


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


def test_bulk_edit_tournaments_adds_selected_tournament_to_venue(client, session):
    bulk_role = Role(
        name='bulk venue manager',
        permissions=json.dumps({'tournaments.bulk_manage': True}),
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
            '/admin/tournaments/bulk',
            data={
                'bulk_action': 'venue',
                'bulk_venue_id': str(venue.id),
                'tournament_ids': [str(tournament.id)],
            },
        )

    assert response.status_code == 302
    assert response.location == '/'
    session.expire_all()
    assert session.get(Tournament, tournament.id).venue_id == venue.id


def test_bulk_edit_tournaments_rejects_invalid_venue_id(client, session):
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
            '/admin/tournaments/bulk',
            data={
                'bulk_action': 'venue',
                'bulk_venue_id': 'not-a-venue-id',
                'tournament_ids': [str(tournament.id)],
            },
        )

    assert response.status_code == 302
    assert response.location == '/'
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
