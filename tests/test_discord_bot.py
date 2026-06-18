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
