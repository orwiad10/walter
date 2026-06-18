import discord_bot


def test_discord_bot_registers_connect_command_instead_of_authorize():
    command_names = {command.name for command in discord_bot.bot.tree.get_commands()}

    assert 'connect' in command_names
    assert 'authorize' not in command_names
