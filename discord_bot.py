"""Read-only Discord bot for Walter tournament updates.

The bot talks to the Walter site through the API key exported by the startup
scripts. It only calls read endpoints and exposes slash commands for standings
and pairings, plus an optional polling loop that posts new pairings to a
configured channel when a new round appears.
"""

from __future__ import annotations

import asyncio
import os
from typing import Any
from urllib import error, request

import discord
from discord import app_commands


BOT_TOKEN = os.environ.get('BOT_TOKEN', '').strip()
BOT_CHANNEL_ID = os.environ.get('BOT_CHANNEL_ID', '').strip()
BOT_API_BASE_URL = os.environ.get('BOT_API_BASE_URL', 'http://127.0.0.1:5000').strip().rstrip('/')
BOT_API_KEY = os.environ.get('BOT_API_KEY', '').strip()
BOT_POLL_TOURNAMENT_ID = os.environ.get('BOT_POLL_TOURNAMENT_ID', '').strip()
BOT_POLL_INTERVAL_SECONDS = int(os.environ.get('BOT_POLL_INTERVAL_SECONDS', '30') or 30)


class WalterApiError(RuntimeError):
    """Raised when the Walter API cannot return a successful response."""


class WalterApiClient:
    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key

    async def get_json(self, path: str) -> dict[str, Any]:
        return await asyncio.to_thread(self._get_json_sync, path)

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

    async def tournaments(self) -> dict[str, Any]:
        return await self.get_json('/api/v1/tournaments')

    async def standings(self, tournament_id: int) -> dict[str, Any]:
        return await self.get_json(f'/api/v1/tournaments/{tournament_id}/standings')

    async def latest_round(self, tournament_id: int) -> dict[str, Any]:
        return await self.get_json(f'/api/v1/tournaments/{tournament_id}/rounds/latest')


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

    async def setup_hook(self):
        await self.tree.sync()
        if BOT_CHANNEL_ID and BOT_POLL_TOURNAMENT_ID:
            self.loop.create_task(self._poll_pairings())

    async def on_ready(self):
        assert self.user is not None
        print(f'Logged in as {self.user} (ID: {self.user.id})')
        print(f'Walter API: {BOT_API_BASE_URL}')

    async def _poll_pairings(self):
        await self.wait_until_ready()
        channel = self.get_channel(int(BOT_CHANNEL_ID))
        if channel is None:
            channel = await self.fetch_channel(int(BOT_CHANNEL_ID))
        if not isinstance(channel, discord.abc.Messageable):
            print(f'Configured BOT_CHANNEL_ID={BOT_CHANNEL_ID} is not messageable.')
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


def main():
    if not BOT_TOKEN:
        raise SystemExit('BOT_TOKEN is required.')
    if not BOT_API_KEY:
        raise SystemExit('BOT_API_KEY is required.')
    bot.run(BOT_TOKEN)


if __name__ == '__main__':
    main()
