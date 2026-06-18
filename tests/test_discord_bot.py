import discord_bot


def test_discord_bot_registers_connect_command_instead_of_authorize():
    command_names = set(discord_bot.registered_command_names(discord_bot.bot.tree))

    assert 'connect' in command_names
    assert 'authorize' not in command_names


def test_discord_bot_registers_all_expected_slash_commands():
    command_names = set(discord_bot.registered_command_names(discord_bot.bot.tree))

    assert {
        'connect',
        'pairings',
        'report_pairing',
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
