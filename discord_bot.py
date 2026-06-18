"""Discord bot for Walter tournament updates and player result reporting.

The bot talks to the Walter site through the API key exported by the startup
scripts. It only calls read endpoints and exposes slash commands for standings
and pairings, plus an optional polling loop that posts new pairings to a
configured channel when a new round appears.
"""

from __future__ import annotations

import asyncio
import os
import sys
from pathlib import Path
from typing import Any
from urllib import error, request

VENDORED_DISCORD_PATH = Path(__file__).resolve().parent / 'walter-bot'
if VENDORED_DISCORD_PATH.is_dir():
    sys.path.insert(0, str(VENDORED_DISCORD_PATH))

import discord
from discord import app_commands


BOT_TOKEN = os.environ.get('BOT_TOKEN', '').strip()
BOT_CHANNEL_ID = os.environ.get('BOT_CHANNEL_ID', '').strip()
BOT_API_BASE_URL = os.environ.get('BOT_API_BASE_URL', 'http://127.0.0.1:5000').strip().rstrip('/')
BOT_API_KEY = os.environ.get('BOT_API_KEY', '').strip()
BOT_POLL_TOURNAMENT_ID = os.environ.get('BOT_POLL_TOURNAMENT_ID', '').strip()
BOT_POLL_INTERVAL_SECONDS = int(os.environ.get('BOT_POLL_INTERVAL_SECONDS', '30') or 30)
BOT_ANNOUNCE_READY = os.environ.get('BOT_ANNOUNCE_READY', 'true').strip().lower() not in {'0', 'false', 'no', 'off'}
BOT_SYNC_GUILD_COMMANDS = os.environ.get('BOT_SYNC_GUILD_COMMANDS', 'true').strip().lower() not in {'0', 'false', 'no', 'off'}


class WalterApiError(RuntimeError):
    """Raised when the Walter API cannot return a successful response."""


class WalterApiClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key

    async def get_json(self, path: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._get_json_sync, path)

    async def post_json(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        return await asyncio.to_thread(self._post_json_sync, path, payload)

    def _get_json_sync(self, path: str) -> dict[str, Any]:
        url = f'{self.base_url}{path}'
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.api_key}',
            'User-Agent': 'WalterDiscordBot/1.0',
        }
        api_request = request.Request(url, headers=headers)
        try:
            with request.urlopen(api_request, timeout=10) as response:
                import json

                return json.loads(response.read().decode('utf-8'))
        except error.HTTPError as exc:
            detail = exc.read().decode('utf-8', errors='replace')
            raise WalterApiError(f'Walter API returned HTTP {exc.code}: {detail}') from exc
        except error.URLError as exc:
            raise WalterApiError(f'Could not reach Walter API: {exc.reason}') from exc

    def _post_json_sync(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        import json

        url = f'{self.base_url}{path}'
        body = json.dumps(payload).encode('utf-8')
        headers = {
            'Accept': 'application/json',
            'Authorization': f'Bearer {self.api_key}',
            'Content-Type': 'application/json',
            'User-Agent': 'WalterDiscordBot/1.0',
        }
        api_request = request.Request(url, data=body, headers=headers, method='POST')
        try:
            with request.urlopen(api_request, timeout=10) as response:
                return json.loads(response.read().decode('utf-8'))
        except error.HTTPError as exc:
            detail = exc.read().decode('utf-8', errors='replace')
            raise WalterApiError(f'Walter API returned HTTP {exc.code}: {detail}') from exc
        except error.URLError as exc:
            raise WalterApiError(f'Could not reach Walter API: {exc.reason}') from exc

    async def tournaments(self) -> dict[str, Any]:
        return await self.get_json('/api/v1/tournaments')

    async def standings(self, tournament_id: int) -> dict[str, Any]:
        return await self.get_json(f'/api/v1/tournaments/{tournament_id}/standings')

    async def latest_round(self, tournament_id: int) -> dict[str, Any]:
        return await self.get_json(f'/api/v1/tournaments/{tournament_id}/rounds/latest')

    async def authorize_discord_user(self, discord_user_id: int, discord_username: str, one_time_pass: str) -> dict[str, Any]:
        return await self.post_json('/api/v1/discord/authorize', {
            'discord_user_id': str(discord_user_id),
            'discord_username': discord_username,
            'one_time_pass': one_time_pass,
        })

    async def report_pairing(
        self,
        discord_user_id: int,
        tournament_id: int,
        table_number: int,
        player1_wins: int,
        player2_wins: int,
        draws: int,
    ) -> dict[str, Any]:
        return await self.post_json('/api/v1/discord/report-pairing', {
            'discord_user_id': str(discord_user_id),
            'tournament_id': tournament_id,
            'table_number': table_number,
            'player1_wins': player1_wins,
            'player2_wins': player2_wins,
            'draws': draws,
        })


def _truncate_lines(lines: list[str], limit: int = 1900) -> str:
    output: list[str] = []
    total = 0
    for line in lines:
        next_total = total + len(line) + 1
        if next_total > limit:
            output.append('…')
            break
        output.append(line)
        total = next_total
    return '\n'.join(output) or 'No data found.'


def registered_command_names(tree: app_commands.CommandTree[Any]) -> list[str]:
    return sorted(command.name for command in tree.get_commands())


def format_standings(payload: dict[str, Any]) -> str:
    tournament = payload.get('tournament') or {}
    standings = payload.get('standings') or []
    lines = [f"**Standings: {tournament.get('name', 'Tournament')}**"]
    if not standings:
        lines.append('No standings are available yet.')
        return '\n'.join(lines)

    for row in standings:
        dropped = ' (dropped)' if row.get('dropped') else ''
        lines.append(f"{row['rank']}. {row['name']} — {row['points']} pts{dropped}")
    return _truncate_lines(lines)


def format_pairings(payload: dict[str, Any]) -> str:
    tournament = payload.get('tournament') or {}
    round_payload = payload.get('round') or {}
    lines = [f"**{tournament.get('name', 'Tournament')} — Round {round_payload.get('number', '?')} pairings**"]
    matches = round_payload.get('matches') or []
    if not matches:
        lines.append('No pairings are available for this round.')
        return '\n'.join(lines)

    for match in matches:
        names = [player['name'] for player in match.get('players') or []]
        if match.get('is_bye') and names:
            pairing = f'{names[0]} has the bye'
        else:
            pairing = ' vs. '.join(names)
        lines.append(f"Table {match['table_number']}: {pairing}")
    return _truncate_lines(lines)


class WalterBot(discord.Client):
    def __init__(self):
        super().__init__(intents=discord.Intents.default())
        self.tree = app_commands.CommandTree(self)
        self.api = WalterApiClient(BOT_API_BASE_URL, BOT_API_KEY)
        self._last_announced_round: int | None = None
        self._ready_announced = False
        self._guild_commands_synced = False

    async def setup_hook(self):
        synced_commands = await self.tree.sync()
        command_names = ', '.join(registered_command_names(self.tree))
        print(f'Synced {len(synced_commands)} global Discord slash command(s): {command_names}')
        if BOT_CHANNEL_ID and BOT_POLL_TOURNAMENT_ID:
            self.loop.create_task(self._poll_pairings())
        elif BOT_CHANNEL_ID:
            print('BOT_CHANNEL_ID is configured, but BOT_POLL_TOURNAMENT_ID is not; automatic pairing posts are disabled.')
        else:
            print('BOT_CHANNEL_ID is not configured; the bot cannot post messages to a Discord channel.')

    async def on_ready(self):
        assert self.user is not None
        print(f'Logged in as {self.user} (ID: {self.user.id})')
        print(f'Connected to {len(self.guilds)} Discord server(s).')
        print(f'Walter API: {BOT_API_BASE_URL}')

        if BOT_SYNC_GUILD_COMMANDS and not self._guild_commands_synced:
            await self._sync_guild_commands()

        if BOT_CHANNEL_ID and BOT_ANNOUNCE_READY and not self._ready_announced:
            channel = await self._get_messageable_channel(BOT_CHANNEL_ID)
            if channel is not None:
                await channel.send('Walter bot is online. Use `/tournaments`, `/standings`, `/pairings`, or `/connect` to get started.')
                self._ready_announced = True

    async def _sync_guild_commands(self):
        command_names = ', '.join(registered_command_names(self.tree))
        for guild in self.guilds:
            try:
                self.tree.copy_global_to(guild=guild)
                synced_commands = await self.tree.sync(guild=guild)
                print(f'Synced {len(synced_commands)} slash command(s) to guild {guild.id}: {command_names}')
            except discord.DiscordException as exc:
                print(f'Could not sync slash commands to guild {guild.id}: {exc}')
        self._guild_commands_synced = True

    async def _get_messageable_channel(self, channel_id: str) -> discord.abc.Messageable | None:
        try:
            channel = self.get_channel(int(channel_id))
            if channel is None:
                channel = await self.fetch_channel(int(channel_id))
        except (TypeError, ValueError, discord.DiscordException) as exc:
            print(f'Could not resolve BOT_CHANNEL_ID={channel_id}: {exc}')
            return None

        if not isinstance(channel, discord.abc.Messageable):
            print(f'Configured BOT_CHANNEL_ID={channel_id} is not messageable.')
            return None
        return channel

    async def _poll_pairings(self):
        await self.wait_until_ready()
        channel = await self._get_messageable_channel(BOT_CHANNEL_ID)
        if channel is None:
            return

        tournament_id = int(BOT_POLL_TOURNAMENT_ID)
        while not self.is_closed():
            try:
                payload = await self.api.latest_round(tournament_id)
                round_number = int((payload.get('round') or {}).get('number') or 0)
                if round_number and round_number != self._last_announced_round:
                    await channel.send(format_pairings(payload))
                    self._last_announced_round = round_number
            except Exception as exc:
                print(f'Pairing poll failed: {exc}')
            await asyncio.sleep(max(BOT_POLL_INTERVAL_SECONDS, 10))


bot = WalterBot()


@bot.tree.command(name='tournaments', description='List Walter tournaments.')
async def tournaments(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True)
    try:
        payload = await bot.api.tournaments()
        tournaments_payload = payload.get('tournaments') or []
        lines = ['**Walter tournaments**']
        for tournament in tournaments_payload[:25]:
            lines.append(f"{tournament['id']}: {tournament['name']} ({tournament['format']})")
        await interaction.followup.send(_truncate_lines(lines), ephemeral=True)
    except WalterApiError as exc:
        await interaction.followup.send(str(exc), ephemeral=True)


@bot.tree.command(name='standings', description='Print tournament standings.')
@app_commands.describe(tournament_id='Walter tournament ID')
async def standings(interaction: discord.Interaction, tournament_id: int):
    await interaction.response.defer(thinking=True)
    try:
        await interaction.followup.send(format_standings(await bot.api.standings(tournament_id)))
    except WalterApiError as exc:
        await interaction.followup.send(str(exc), ephemeral=True)


@bot.tree.command(name='pairings', description='Print pairings for the latest round.')
@app_commands.describe(tournament_id='Walter tournament ID')
async def pairings(interaction: discord.Interaction, tournament_id: int):
    await interaction.response.defer(thinking=True)
    try:
        await interaction.followup.send(format_pairings(await bot.api.latest_round(tournament_id)))
    except WalterApiError as exc:
        await interaction.followup.send(str(exc), ephemeral=True)


@bot.tree.command(name='connect', description='Connect this Discord account to your Walter user with a one-time pass.')
@app_commands.describe(one_time_pass='One-time pass generated from your Walter user settings page')
async def connect(interaction: discord.Interaction, one_time_pass: str):
    await interaction.response.defer(thinking=True, ephemeral=True)
    username = interaction.user.name
    try:
        payload = await bot.api.authorize_discord_user(interaction.user.id, username, one_time_pass)
        user = payload.get('user') or {}
        await interaction.followup.send(f"Connected Discord to Walter user **{user.get('name', 'Unknown')}**.", ephemeral=True)
    except WalterApiError as exc:
        await interaction.followup.send(str(exc), ephemeral=True)


@bot.tree.command(name='report_pairing', description='Report your latest-round tournament pairing result.')
@app_commands.describe(
    tournament_id='Walter tournament ID',
    table_number='Table number from the latest round pairings',
    player1_wins='Wins for the first-listed player at the table',
    player2_wins='Wins for the second-listed player at the table',
    draws='Drawn games in the match',
)
async def report_pairing(
    interaction: discord.Interaction,
    tournament_id: int,
    table_number: int,
    player1_wins: int,
    player2_wins: int,
    draws: int = 0,
):
    await interaction.response.defer(thinking=True, ephemeral=True)
    try:
        payload = await bot.api.report_pairing(
            interaction.user.id,
            tournament_id,
            table_number,
            player1_wins,
            player2_wins,
            draws,
        )
        match = payload.get('match') or {}
        await interaction.followup.send(
            f"Result reported for table {match.get('table_number', table_number)}: "
            f"{player1_wins}-{player2_wins}-{draws}.",
            ephemeral=True,
        )
    except WalterApiError as exc:
        await interaction.followup.send(str(exc), ephemeral=True)


def main():
    if not BOT_TOKEN:
        raise SystemExit('BOT_TOKEN is required.')
    if not BOT_API_KEY:
        raise SystemExit('BOT_API_KEY is required.')
    bot.run(BOT_TOKEN)


if __name__ == '__main__':
    main()
