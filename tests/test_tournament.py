import random

from app.app import db
from app.models import Tournament, User, TournamentPlayer, Role, Round, MatchResult
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
