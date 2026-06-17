from datetime import date

from app.models import (
    League,
    LeagueCube,
    LeagueCubeVote,
    LeaguePlayDate,
    LeaguePlayDateCube,
    LeaguePlayer,
    Match,
    Role,
    Round,
    SiteLog,
    Tournament,
    TournamentPlayer,
    User,
)


def _user(session, email, name, role_name='user', is_admin=False):
    role = session.query(Role).filter_by(name=role_name).one()
    user = User(email=email, name=name, role=role, is_admin=is_admin)
    user.set_password('secret')
    session.add(user)
    session.flush()
    return user


def test_admin_can_delete_league_and_audit_log(client, session):
    admin = _user(session, 'league-delete-admin@example.com', 'League Admin', 'admin', True)
    league = League(name='Delete Me', is_cube_league=True)
    tournament = Tournament(name='League Event', format='Draft', league=league)
    session.add_all([league, tournament])
    session.commit()

    assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
    response = client.post(f'/admin/leagues/{league.id}/delete')

    assert response.status_code == 302
    assert session.get(League, league.id) is None
    session.refresh(tournament)
    assert tournament.league_id is None
    log = session.query(SiteLog).filter_by(action='league_delete').one()
    assert log.result == 'success'
    assert f'league_id={league.id}' in log.error


def test_cube_league_votes_are_limited_to_three_per_play_date(client, session):
    player = _user(session, 'cube-voter@example.com', 'Cube Voter')
    league = League(name='Cube League', is_cube_league=True)
    session.add(league)
    session.flush()
    session.add(LeaguePlayer(league_id=league.id, user_id=player.id))
    first = LeagueCube(
        league_id=league.id,
        cube_cobra_url='https://cubecobra.com/cube/overview/alpha',
        title='Alpha Cube',
        image_url='https://cubecobra.com/content/alpha.png',
    )
    second = LeagueCube(
        league_id=league.id,
        cube_cobra_url='https://cubecobra.com/cube/overview/beta',
        title='Beta Cube',
    )
    play_date = LeaguePlayDate(league_id=league.id, play_date=date(2026, 7, 1), is_active=True)
    session.add_all([first, second, play_date])
    session.flush()
    session.add_all([
        LeaguePlayDateCube(play_date_id=play_date.id, cube_id=first.id),
        LeaguePlayDateCube(play_date_id=play_date.id, cube_id=second.id),
    ])
    session.commit()

    assert client.post(
        '/login',
        data={'email': player.email, 'password': 'secret'},
    ).status_code == 302
    response = client.post(
        f'/leagues/{league.id}/cubes',
        data={f'votes_{play_date.id}_{first.id}': '2', f'votes_{play_date.id}_{second.id}': '2'},
    )
    assert response.status_code == 302
    assert session.query(LeagueCubeVote).count() == 0

    response = client.post(
        f'/leagues/{league.id}/cubes',
        data={f'votes_{play_date.id}_{first.id}': '2', f'votes_{play_date.id}_{second.id}': '1'},
    )
    assert response.status_code == 302
    votes = session.query(LeagueCubeVote).order_by(LeagueCubeVote.cube_id).all()
    assert [vote.votes for vote in votes] == [2, 1]


def test_player_cannot_drop_opponent_when_reporting_match(client, session):
    player_one = _user(session, 'player-one@example.com', 'Player One')
    player_two = _user(session, 'player-two@example.com', 'Player Two')
    tournament = Tournament(name='Drop Test', format='Constructed')
    session.add(tournament)
    session.flush()
    tp_one = TournamentPlayer(tournament_id=tournament.id, user_id=player_one.id)
    tp_two = TournamentPlayer(tournament_id=tournament.id, user_id=player_two.id)
    session.add_all([tp_one, tp_two])
    session.flush()
    round_one = Round(tournament_id=tournament.id, number=1)
    session.add(round_one)
    session.flush()
    match = Match(round_id=round_one.id, player1_id=tp_one.id, player2_id=tp_two.id, table_number=1)
    session.add(match)
    session.commit()

    assert client.post('/login', data={'email': player_one.email, 'password': 'secret'}).status_code == 302
    response = client.post(
        f'/match/{match.id}',
        data={'p1_wins': '2', 'p2_wins': '0', 'draws': '0', 'drop_p2': 'on'},
    )

    assert response.status_code == 302
    session.refresh(tp_one)
    session.refresh(tp_two)
    assert not tp_one.dropped
    assert not tp_two.dropped


def test_player_can_view_member_leagues_without_manage_controls(client, session):
    member = _user(session, 'league-member@example.com', 'League Member')
    other = _user(session, 'league-other@example.com', 'League Other')
    league = League(name='Members Only League', is_cube_league=True)
    hidden = League(name='Hidden League')
    session.add_all([league, hidden])
    session.flush()
    session.add(LeaguePlayer(league_id=league.id, user_id=member.id))
    session.commit()

    assert client.post('/login', data={'email': member.email, 'password': 'secret'}).status_code == 302
    response = client.get('/my-leagues')
    assert response.status_code == 200
    assert b'Members Only League' in response.data
    assert b'Hidden League' not in response.data

    response = client.get(f'/leagues/{league.id}')
    assert response.status_code == 200
    assert b'League Settings' not in response.data
    assert b'Assign Players' not in response.data
    assert b'Import Tournament' not in response.data
    assert b'Cube Voting' in response.data

    client.get('/logout')
    assert client.post('/login', data={'email': other.email, 'password': 'secret'}).status_code == 302
    assert client.get(f'/leagues/{league.id}').status_code == 403


def test_cube_league_vote_totals_update_when_votes_change(client, session):
    player = _user(session, 'cube-updater@example.com', 'Cube Updater')
    league = League(name='Update Vote League', is_cube_league=True)
    session.add(league)
    session.flush()
    session.add(LeaguePlayer(league_id=league.id, user_id=player.id))
    first = LeagueCube(
        league_id=league.id,
        cube_cobra_url='https://cubecobra.com/cube/overview/first',
        title='First Cube',
    )
    second = LeagueCube(
        league_id=league.id,
        cube_cobra_url='https://cubecobra.com/cube/overview/second',
        title='Second Cube',
    )
    play_date = LeaguePlayDate(league_id=league.id, play_date=date(2026, 8, 1), is_active=True)
    session.add_all([first, second, play_date])
    session.flush()
    session.add_all([
        LeaguePlayDateCube(play_date_id=play_date.id, cube_id=first.id),
        LeaguePlayDateCube(play_date_id=play_date.id, cube_id=second.id),
    ])
    session.commit()

    assert client.post(
        '/login',
        data={'email': player.email, 'password': 'secret'},
    ).status_code == 302
    response = client.post(
        f'/leagues/{league.id}/cubes',
        data={f'votes_{play_date.id}_{first.id}': '2', f'votes_{play_date.id}_{second.id}': '1'},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b'Total votes: 2' in response.data
    assert b'Total votes: 1' in response.data

    response = client.post(
        f'/leagues/{league.id}/cubes',
        data={f'votes_{play_date.id}_{first.id}': '0', f'votes_{play_date.id}_{second.id}': '3'},
        follow_redirects=True,
    )
    assert response.status_code == 200
    assert b'Total votes: 0' in response.data
    assert b'Total votes: 3' in response.data
    votes = session.query(LeagueCubeVote).order_by(LeagueCubeVote.cube_id).all()
    assert [(vote.cube_id, vote.votes) for vote in votes] == [(second.id, 3)]


def test_cube_cobra_titles_drop_list_prefix():
    from app.app import clean_cube_cobra_title

    assert clean_cube_cobra_title('Cube Cobra List: FirstCube') == 'FirstCube'
    assert clean_cube_cobra_title('Food Fight - Cube Cobra List') == 'Food Fight'


def test_cube_cobra_image_proxy_allows_subdomains(client, session, monkeypatch):
    import app.app as app_module

    player = _user(session, 'cube-proxy@example.com', 'Cube Proxy')
    session.commit()

    class FakeResponse:
        headers = {'Content-Type': 'image/png', 'Content-Length': '7'}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, size):
            return b'pngdata'

    monkeypatch.setattr(
        app_module.urllib.request,
        'urlopen',
        lambda req, timeout: FakeResponse(),
    )

    assert client.post(
        '/login',
        data={'email': player.email, 'password': 'secret'},
    ).status_code == 302
    response = client.get('/cube-cobra-image?url=https://images.cubecobra.com/content/alpha.png')

    assert response.status_code == 200
    assert response.content_type == 'image/png'
    assert response.data == b'pngdata'


def test_cube_cobra_image_proxy_rejects_large_content_length(client, session, monkeypatch):
    import app.app as app_module

    player = _user(session, 'cube-proxy-large@example.com', 'Cube Proxy Large')
    session.commit()

    class FakeResponse:
        headers = {
            'Content-Type': 'image/png',
            'Content-Length': str(app_module.CUBE_COBRA_IMAGE_MAX_BYTES + 1),
        }

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, size):
            raise AssertionError('large images should be rejected before reading the body')

    monkeypatch.setattr(
        app_module.urllib.request,
        'urlopen',
        lambda req, timeout: FakeResponse(),
    )

    assert client.post(
        '/login',
        data={'email': player.email, 'password': 'secret'},
    ).status_code == 302
    response = client.get('/cube-cobra-image?url=https://cubecobra.com/content/large.png')

    assert response.status_code == 413


def test_cube_cobra_image_proxy_rejects_large_body_without_content_length(client, session, monkeypatch):
    import app.app as app_module

    player = _user(session, 'cube-proxy-large-body@example.com', 'Cube Proxy Large Body')
    session.commit()

    class FakeResponse:
        headers = {'Content-Type': 'image/png'}

        def __enter__(self):
            return self

        def __exit__(self, exc_type, exc, tb):
            return False

        def read(self, size):
            assert size == app_module.CUBE_COBRA_IMAGE_MAX_BYTES + 1
            return b'x' * size

    monkeypatch.setattr(
        app_module.urllib.request,
        'urlopen',
        lambda req, timeout: FakeResponse(),
    )

    assert client.post(
        '/login',
        data={'email': player.email, 'password': 'secret'},
    ).status_code == 302
    response = client.get('/cube-cobra-image?url=https://cubecobra.com/content/large-body.png')

    assert response.status_code == 413


def test_cube_cobra_images_use_local_proxy(client, session):
    player = _user(session, 'cube-image@example.com', 'Cube Image')
    league = League(name='Image League', is_cube_league=True)
    session.add(league)
    session.flush()
    session.add(LeaguePlayer(league_id=league.id, user_id=player.id))
    cube = LeagueCube(
        league_id=league.id,
        cube_cobra_url='https://cubecobra.com/cube/overview/alpha',
        title='Alpha Cube',
        image_url='https://cubecobra.com/content/alpha.png',
    )
    play_date = LeaguePlayDate(league_id=league.id, play_date=date(2026, 7, 1), is_active=True)
    session.add_all([cube, play_date])
    session.flush()
    session.add(LeaguePlayDateCube(play_date_id=play_date.id, cube_id=cube.id))
    session.commit()

    assert client.post(
        '/login',
        data={'email': player.email, 'password': 'secret'},
    ).status_code == 302
    response = client.get(f'/leagues/{league.id}/cubes')

    assert response.status_code == 200
    assert b'/cube-cobra-image?url=https://cubecobra.com/content/alpha.png' in response.data
    assert b'referrerpolicy="no-referrer"' in response.data
