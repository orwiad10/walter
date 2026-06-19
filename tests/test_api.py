from app.models import ApiKey, ApiLog, League, MatchResult, Role, Round, SiteLog, Tournament, TournamentPlayer, User
from app.pairing import pair_round


def test_admin_can_create_api_key_and_call_admin_api(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='api-admin@example.com', name='API Admin', role=admin_role, is_admin=True)
    admin.set_password('secret')
    session.add(admin)
    session.commit()

    with client:
        assert client.post('/login', data={'email': admin.email, 'password': 'secret'}).status_code == 302
        response = client.post('/settings', data={'action': 'api_key', 'name': 'Tests'})

    assert response.status_code == 200
    token = response.get_data(as_text=True).split('<code>')[1].split('</code>')[0]
    key = session.query(ApiKey).filter_by(user_id=admin.id).one()
    assert token.startswith('wlt_')
    assert key.prefix == token[:12]
    assert session.query(SiteLog).filter_by(action='api_key_create', result='success').count() == 1

    create_response = client.post(
        '/api/v1/leagues',
        json={'name': 'API League', 'is_cube_league': True},
        headers={'Authorization': f'Bearer {token}'},
    )

    assert create_response.status_code == 201
    assert create_response.get_json()['name'] == 'API League'
    assert session.query(League).filter_by(name='API League').one().is_cube_league
    assert session.query(SiteLog).filter_by(action='api.leagues.create', result='success').count() == 1
    api_log = session.query(ApiLog).filter_by(path='/api/v1/leagues').one()
    assert api_log.method == 'POST'
    assert api_log.status_code == 201
    assert 'API League' in api_log.request_body
    assert 'API League' in api_log.response_body
    assert '[redacted]' in api_log.request_headers


def test_non_admin_cannot_create_api_key(client, session):
    user_role = session.query(Role).filter_by(name='user').one()
    user = User(email='api-user@example.com', name='API User', role=user_role)
    user.set_password('secret')
    session.add(user)
    session.commit()

    with client:
        assert client.post('/login', data={'email': user.email, 'password': 'secret'}).status_code == 302
        response = client.post('/settings', data={'action': 'api_key', 'name': 'Nope'})

    assert response.status_code == 403
    assert session.query(ApiKey).count() == 0


def test_api_key_can_create_tournament(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='api-tourney@example.com', name='API Tourney', role=admin_role, is_admin=True)
    admin.set_password('secret')
    token = ApiKey.create_token()
    session.add(admin)
    session.flush()
    session.add(ApiKey.from_token(token, admin, 'Direct', created_by=admin))
    session.commit()

    response = client.post(
        '/api/v1/tournaments',
        json={'name': 'API Tournament', 'format': 'Draft'},
        headers={'X-API-Key': token},
    )

    assert response.status_code == 201
    assert response.get_json()['format'] == 'Draft'
    assert session.query(Tournament).filter_by(name='API Tournament').one().format == 'Draft'


def test_api_key_can_read_tournament_standings_and_latest_round(client, session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='api-read@example.com', name='API Read', role=admin_role, is_admin=True)
    token = ApiKey.create_token()
    session.add(admin)
    session.flush()
    session.add(ApiKey.from_token(token, admin, 'Read bot', created_by=admin))

    tournament = Tournament(name='Read Only Open', format='Draft')
    users = [User(name=f'Player {idx}', email=f'p{idx}@example.com') for idx in range(1, 5)]
    session.add(tournament)
    session.add_all(users)
    session.flush()
    entries = [TournamentPlayer(tournament_id=tournament.id, user_id=user.id) for user in users]
    session.add_all(entries)
    session.flush()

    round_one = Round(tournament_id=tournament.id, number=1)
    session.add(round_one)
    session.flush()
    matches = pair_round(tournament, round_one, session)
    first_match = matches[0]
    first_match.completed = True
    first_match.result = MatchResult(player1_wins=2, player2_wins=0, draws=0)
    session.commit()

    standings_response = client.get(
        f'/api/v1/tournaments/{tournament.id}/standings',
        headers={'Authorization': f'Bearer {token}'},
    )
    latest_round_response = client.get(
        f'/api/v1/tournaments/{tournament.id}/rounds/latest',
        headers={'Authorization': f'Bearer {token}'},
    )

    assert standings_response.status_code == 200
    standings = standings_response.get_json()['standings']
    assert standings[0]['rank'] == 1
    assert standings[0]['points'] == 3
    assert standings[0]['name'].startswith('Player ')

    assert latest_round_response.status_code == 200
    latest_round = latest_round_response.get_json()['round']
    assert latest_round['number'] == 1
    assert len(latest_round['matches']) == 2
    assert latest_round['matches'][0]['table_number'] == 1
    assert len(latest_round['matches'][0]['players']) == 2


def _admin_api_token(session):
    admin_role = session.query(Role).filter_by(name='admin').one()
    admin = User(email='discord-admin@example.com', name='Discord Admin', role=admin_role, is_admin=True)
    token = ApiKey.create_token()
    session.add(admin)
    session.flush()
    session.add(ApiKey.from_token(token, admin, 'Discord bot', created_by=admin))
    return token





def test_connect_get_without_parameters_returns_status_for_bot_probe(client, session):
    token = _admin_api_token(session)

    response = client.get(
        '/connect',
        headers={
            'Authorization': f'Bearer {token}',
            'User-Agent': 'WalterDiscordBot/1.0',
        },
    )

    assert response.status_code == 200
    assert response.get_json() == {
        'ok': True,
        'endpoint': '/connect',
        'message': 'Use POST with discord_user_id and one_time_pass to connect a Discord account.',
    }
    api_log = session.query(ApiLog).filter_by(path='/connect').order_by(ApiLog.id.desc()).first()
    assert api_log is not None
    assert api_log.status_code == 200


def test_discord_authorization_accepts_legacy_connect_endpoint(client, session):
    token = _admin_api_token(session)
    user_role = session.query(Role).filter_by(name='user').one()
    player = User(email='discord-connect@example.com', name='Discord Connect', role=user_role)
    one_time_pass = 'connectpass123'
    player.discord_username = 'walterconnect'
    player.set_discord_authorization_token(one_time_pass)
    session.add(player)
    session.commit()

    response = client.post(
        '/connect',
        json={
            'discord_user_id': '2345678901',
            'discord_username': 'walterconnect',
            'one_time_pass': one_time_pass,
        },
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == 200
    session.refresh(player)
    assert player.discord_user_id == '2345678901'
    assert player.discord_authorization_token_hash is None
    api_log = session.query(ApiLog).filter_by(path='/connect').order_by(ApiLog.id.desc()).first()
    assert api_log is not None
    assert api_log.status_code == 200
    site_log = session.query(SiteLog).filter_by(action='api.discord.authorize').order_by(SiteLog.id.desc()).first()
    assert site_log is not None
    assert site_log.result == 'success'
    assert f'user_id={player.id}' in site_log.error
    assert 'discord_user_id=2345678901' in site_log.error
    assert 'discord_username=walterconnect' in site_log.error


def test_discord_authorization_logs_bot_username_for_invalid_pass(client, session):
    token = _admin_api_token(session)

    response = client.post(
        '/connect',
        json={
            'discord_user_id': '4567890123',
            'discord_username': 'wrongpassuser',
            'one_time_pass': 'not-the-pass',
        },
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == 403
    site_log = session.query(SiteLog).filter_by(action='api.discord.authorize').order_by(SiteLog.id.desc()).first()
    assert site_log is not None
    assert site_log.result == 'failure'
    assert 'error=invalid pass' in site_log.error
    assert 'discord_user_id=4567890123' in site_log.error
    assert 'discord_username=wrongpassuser' in site_log.error


def test_discord_authorization_accepts_connect_query_parameters(client, session):
    token = _admin_api_token(session)
    user_role = session.query(Role).filter_by(name='user').one()
    player = User(email='discord-connect-query@example.com', name='Discord Connect Query', role=user_role)
    one_time_pass = 'connectquery123'
    player.discord_username = 'walterquery'
    player.set_discord_authorization_token(one_time_pass)
    session.add(player)
    session.commit()

    response = client.get(
        '/connect',
        query_string={
            'discord_user_id': '3456789012',
            'discord_username': 'walterquery',
            'one_time_pass': one_time_pass,
        },
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == 200
    session.refresh(player)
    assert player.discord_user_id == '3456789012'
    assert player.discord_authorization_token_hash is None


def test_discord_authorization_requires_username_and_one_time_pass(client, session):
    token = _admin_api_token(session)
    user_role = session.query(Role).filter_by(name='user').one()
    player = User(email='discord-player@example.com', name='Discord Player', role=user_role)
    one_time_pass = 'abc123pass'
    player.discord_username = 'walterplayer'
    player.set_discord_authorization_token(one_time_pass)
    session.add(player)
    session.commit()

    response = client.post(
        '/api/v1/discord/authorize/',
        json={
            'discord_user_id': '1234567890',
            'discord_username': 'walterplayer',
            'one_time_pass': one_time_pass,
        },
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == 200
    session.refresh(player)
    assert player.discord_user_id == '1234567890'
    assert player.discord_authorization_token_hash is None


def test_discord_report_pairing_requires_authorized_participant(client, session):
    token = _admin_api_token(session)
    user_role = session.query(Role).filter_by(name='user').one()
    tournament = Tournament(name='Discord Open', format='Draft')
    players = []
    for idx in range(1, 5):
        user = User(name=f'Discord Player {idx}', email=f'discord{idx}@example.com', role=user_role)
        if idx == 1:
            user.discord_username = 'discord1'
            user.discord_user_id = '111'
        players.append(user)
    session.add(tournament)
    session.add_all(players)
    session.flush()
    entries = [TournamentPlayer(tournament_id=tournament.id, user_id=user.id) for user in players]
    session.add_all(entries)
    session.flush()
    round_one = Round(tournament_id=tournament.id, number=1)
    session.add(round_one)
    session.flush()
    matches = pair_round(tournament, round_one, session)
    session.commit()

    table = next(match.table_number for match in matches if players[0].id in {match.player1.user_id, match.player2.user_id})
    response = client.post(
        '/api/v1/discord/report-pairing',
        json={
            'discord_user_id': '111',
            'tournament_id': tournament.id,
            'table_number': table,
            'player1_wins': 2,
            'player2_wins': 1,
            'draws': 0,
        },
        headers={'Authorization': f'Bearer {token}'},
    )

    assert response.status_code == 200
    reported_match = session.query(Round).filter_by(tournament_id=tournament.id).one().matches[table - 1]
    assert reported_match.completed is True
    assert reported_match.result.player1_wins == 2
    assert reported_match.result.player2_wins == 1

    blocked_response = client.post(
        '/api/v1/discord/report-pairing',
        json={
            'discord_user_id': '999',
            'tournament_id': tournament.id,
            'table_number': table,
            'player1_wins': 2,
            'player2_wins': 0,
            'draws': 0,
        },
        headers={'Authorization': f'Bearer {token}'},
    )
    assert blocked_response.status_code == 403


def test_discord_settings_show_pass_prominently_and_disable_password_managers(client, session):
    user_role = session.query(Role).filter_by(name='user').one()
    user = User(email='discord-settings@example.com', name='Discord Settings', role=user_role)
    user.set_password('secret')
    session.add(user)
    session.commit()

    with client:
        assert client.post('/login', data={'email': user.email, 'password': 'secret'}).status_code == 302
        response = client.post(
            '/settings',
            data={
                'action': 'discord_connection',
                'discord_username': 'waltersettings',
                'generate_discord_pass': '1',
            },
        )

    html = response.get_data(as_text=True)
    assert response.status_code == 200
    assert 'Current Discord username: <strong>waltersettings</strong>' in html
    assert 'class="one-time-discord-pass"' in html
    assert 'autocomplete="off"' in html
    assert 'data-lpignore="true"' in html
