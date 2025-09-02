from app.app import db
from app.models import Tournament, User, TournamentPlayer, Role, Round, MatchResult
from app.pairing import swiss_pair_round, compute_standings


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
    matches = swiss_pair_round(t, r1, session)
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
