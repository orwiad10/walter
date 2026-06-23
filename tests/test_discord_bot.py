import discord_bot


def test_discord_bot_registers_connect_command_instead_of_authorize():
    command_names = set(discord_bot.registered_command_names(discord_bot.bot.tree))

    assert 'connect' in command_names
    assert 'authorize' not in command_names


def test_discord_bot_registers_all_expected_slash_commands():
    command_names = set(discord_bot.registered_command_names(discord_bot.bot.tree))

    assert {
        'connect',
        'cube_poll',
        'pairings',
        'report_pairing',
        'league_play_dates',
        'league_standings',
        'leagues',
        'standings',
        'tournaments',
    }.issubset(command_names)


def test_http_error_detail_collapses_html_title():
    from io import BytesIO
    from urllib.error import HTTPError

    exc = HTTPError(
        'http://walter.test/api/v1/discord/authorize',
        405,
        'METHOD NOT ALLOWED',
        {'Content-Type': 'text/html; charset=utf-8'},
        BytesIO(b'<html><head><title>405 Method Not Allowed</title></head></html>'),
    )

    assert discord_bot._format_http_error_detail(exc) == '405 Method Not Allowed'


def test_guild_command_sync_is_disabled_by_default_to_avoid_duplicates():
    assert discord_bot.BOT_SYNC_GUILD_COMMANDS is False
    assert discord_bot.BOT_CLEAR_GUILD_COMMANDS is True


def test_ready_announcement_is_disabled_by_default():
    assert discord_bot.BOT_ANNOUNCE_READY is False


def test_authorize_discord_user_uses_connect_endpoint_first(monkeypatch):
    import asyncio

    calls = []

    def fake_post(path, payload):
        calls.append((path, payload))
        return {'authorized': True}

    api = discord_bot.WalterApiClient('http://walter.test', 'token')
    monkeypatch.setattr(api, '_post_json_sync', fake_post)

    result = asyncio.run(api.authorize_discord_user(123, 'walteruser', 'pass123'))

    assert result == {'authorized': True}
    assert calls == [('/connect', {
        'discord_user_id': '123',
        'discord_username': 'walteruser',
        'discord_display_name': '',
        'discord_global_name': '',
        'one_time_pass': 'pass123',
    })]


def test_authorize_discord_user_falls_back_after_405(monkeypatch):
    import asyncio

    calls = []

    def fake_post(path, payload):
        calls.append(path)
        if path == '/connect':
            raise discord_bot.WalterApiError('Walter API returned HTTP 405: Method Not Allowed')
        return {'authorized': True}

    api = discord_bot.WalterApiClient('http://walter.test', 'token')
    monkeypatch.setattr(api, '_post_json_sync', fake_post)

    assert asyncio.run(api.authorize_discord_user(123, 'walteruser', 'pass123')) == {'authorized': True}
    assert calls == ['/connect', '/api/v1/discord/authorize']


def test_post_redirect_handler_preserves_connect_post_on_http_to_https_redirect():
    import json
    from urllib import request

    body = json.dumps({'one_time_pass': 'pass123'}).encode('utf-8')
    original = request.Request(
        'http://walter-pair.us/connect',
        data=body,
        headers={
            'Accept': 'application/json',
            'Authorization': 'Bearer token',
            'Content-Type': 'application/json',
            'User-Agent': 'WalterDiscordBot/1.0',
        },
        method='POST',
    )

    redirected = discord_bot._PreservePostRedirectHandler().redirect_request(
        original,
        None,
        301,
        'Moved Permanently',
        {},
        'https://walter-pair.us/connect',
    )

    assert redirected is not None
    assert redirected.full_url == 'https://walter-pair.us/connect'
    assert redirected.get_method() == 'POST'
    assert redirected.data == body
    assert redirected.get_header('Content-type') == 'application/json'
    assert redirected.get_header('Authorization') == 'Bearer token'


def test_post_redirect_handler_rejects_cross_host_redirect():
    from urllib import request

    original = request.Request(
        'http://walter-pair.us/connect',
        data=b'{}',
        headers={'Content-Type': 'application/json'},
        method='POST',
    )

    redirected = discord_bot._PreservePostRedirectHandler().redirect_request(
        original,
        None,
        302,
        'Found',
        {},
        'https://example.com/connect',
    )

    assert redirected is None


def test_format_league_standings_includes_record_and_events():
    payload = {
        'league': {'name': 'Friday League'},
        'standings': [{
            'rank': 1,
            'name': 'Player One',
            'league_points': 9,
            'wins': 3,
            'losses': 1,
            'draws': 0,
            'played': 2,
        }],
    }

    assert discord_bot.format_league_standings(payload) == (
        '**League standings: Friday League**\n'
        '1. Player One — 9 pts (3-1-0, 2 events)'
    )


def test_format_cube_poll_includes_options_and_vote_totals():
    payload = {
        'league': {'name': 'Cube League'},
        'play_date': {'play_date': '2026-07-01'},
        'cubes': [
            {'title': 'Alpha Cube', 'votes': 2, 'cube_cobra_url': 'https://cubecobra.com/cube/alpha'},
            {'title': 'Beta Cube', 'votes': 1, 'cube_cobra_url': 'https://cubecobra.com/cube/beta'},
        ],
    }

    formatted = discord_bot.format_cube_poll(payload)

    assert '**Cube vote: Cube League — 2026-07-01**' in formatted
    assert '1️⃣ **Alpha Cube** — 2 vote(s)' in formatted
    assert '2️⃣ **Beta Cube** — 1 vote(s)' in formatted


def test_format_league_play_dates_shows_ids_for_cube_poll():
    payload = {
        'league': {'id': 7, 'name': 'Cube League'},
        'play_dates': [
            {'id': 42, 'play_date': '2026-07-01', 'is_active': True, 'available_cube_count': 3},
            {'id': 43, 'play_date': '2026-07-08', 'is_active': False, 'available_cube_count': 1},
        ],
    }

    formatted = discord_bot.format_league_play_dates(payload)

    assert '**Play dates for Cube League**' in formatted
    assert '/cube_poll league_id:<league id> play_date_id:<play date id>' in formatted
    assert '42: 2026-07-01 (active, 3 cube(s))' in formatted
    assert '43: 2026-07-08 (inactive, 1 cube(s))' in formatted


def test_cache_cube_poll_metadata_uses_registered_poll_payload():
    payload = {
        'poll': {'league_id': 7, 'play_date_id': 42, 'channel_id': '12345', 'message_id': '67890'},
        'cube_vote': {'cubes': [{'id': 111}, {'id': 222}]},
    }
    client = discord_bot.WalterBot()

    metadata = client._cache_cube_poll_metadata(payload)

    assert metadata == {'league_id': 7, 'play_date_id': 42, 'channel_id': 12345, 'cube_ids': [111, 222]}
    assert client._cube_polls[67890] == metadata
