"""Discord bot for Walter tournament updates and player result reporting.

The bot talks to the Walter site through the API key exported by the startup
scripts. It only calls read endpoints and exposes slash commands for standings
and pairings, plus an optional polling loop that posts new pairings to a
configured channel when a new round appears.
"""

from __future__ import annotations

import asyncio
import os
import re
import sys
from pathlib import Path
from typing import Any
from urllib import error, parse, request


def _bot_log(message: str) -> None:
    print(message, flush=True)

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
BOT_ANNOUNCE_READY = os.environ.get('BOT_ANNOUNCE_READY', 'false').strip().lower() not in {'0', 'false', 'no', 'off'}
BOT_SYNC_GUILD_COMMANDS = os.environ.get('BOT_SYNC_GUILD_COMMANDS', 'false').strip().lower() not in {'0', 'false', 'no', 'off'}
BOT_CLEAR_GUILD_COMMANDS = os.environ.get('BOT_CLEAR_GUILD_COMMANDS', 'true').strip().lower() not in {'0', 'false', 'no', 'off'}
CUBE_POLL_EMOJIS = ['1️⃣', '2️⃣', '3️⃣', '4️⃣', '5️⃣', '6️⃣', '7️⃣', '8️⃣', '9️⃣', '🔟']


class WalterApiError(RuntimeError):
    """Raised when the Walter API cannot return a successful response."""


def _format_http_error_detail(exc: error.HTTPError) -> str:
    body = exc.read().decode('utf-8', errors='replace').strip()
    content_type = exc.headers.get('Content-Type', '') if exc.headers else ''
    if 'application/json' in content_type:
        try:
            import json

            payload = json.loads(body)
            if isinstance(payload, dict):
                return str(payload.get('error') or payload.get('message') or payload)
        except ValueError:
            pass
    if '<html' in body.lower():
        title_match = re.search(r'<title>(.*?)</title>', body, re.IGNORECASE | re.DOTALL)
        if title_match:
            return re.sub(r'\s+', ' ', title_match.group(1)).strip()
        return exc.reason or 'HTTP error'
    return body or exc.reason or 'HTTP error'


class _PreservePostRedirectHandler(request.HTTPRedirectHandler):
    """Follow same-host redirects without converting JSON POSTs into GETs."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if code not in {301, 302, 303, 307, 308}:
            return None

        old = parse.urlsplit(req.full_url)
        new = parse.urlsplit(newurl)
        if (old.hostname or '').lower() != (new.hostname or '').lower():
            return None

        old_port = old.port or (443 if old.scheme == 'https' else 80)
        new_port = new.port or (443 if new.scheme == 'https' else 80)
        if old_port != new_port and not (old.scheme == 'http' and old_port == 80 and new.scheme == 'https' and new_port == 443):
            return None

        return request.Request(
            newurl,
            data=req.data,
            headers=dict(req.header_items()),
            origin_req_host=req.origin_req_host,
            unverifiable=True,
            method=req.get_method(),
        )


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
            detail = _format_http_error_detail(exc)
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
            opener = request.build_opener(_PreservePostRedirectHandler)
            with opener.open(api_request, timeout=10) as response:
                return json.loads(response.read().decode('utf-8'))
        except error.HTTPError as exc:
            detail = _format_http_error_detail(exc)
            raise WalterApiError(f'Walter API returned HTTP {exc.code}: {detail}') from exc
        except error.URLError as exc:
            raise WalterApiError(f'Could not reach Walter API: {exc.reason}') from exc

    async def tournaments(self) -> dict[str, Any]:
        return await self.get_json('/api/v1/tournaments')

    async def leagues(self) -> dict[str, Any]:
        return await self.get_json('/api/v1/leagues')

    async def league_standings(self, league_id: int) -> dict[str, Any]:
        return await self.get_json(f'/api/v1/leagues/{league_id}/standings')

    async def league_play_dates(self, league_id: int) -> dict[str, Any]:
        return await self.get_json(f'/api/v1/leagues/{league_id}/play-dates')

    async def standings(self, tournament_id: int) -> dict[str, Any]:
        return await self.get_json(f'/api/v1/tournaments/{tournament_id}/standings')

    async def latest_round(self, tournament_id: int) -> dict[str, Any]:
        return await self.get_json(f'/api/v1/tournaments/{tournament_id}/rounds/latest')

    async def authorize_discord_user(
        self,
        discord_user_id: int,
        discord_username: str,
        one_time_pass: str,
        discord_display_name: str = '',
        discord_global_name: str = '',
    ) -> dict[str, Any]:
        payload = {
            'discord_user_id': str(discord_user_id),
            'discord_username': discord_username,
            'discord_display_name': discord_display_name,
            'discord_global_name': discord_global_name,
            'one_time_pass': one_time_pass,
        }
        _bot_log(
            'Discord connect request: '
            f'discord_user_id={discord_user_id}; '
            f'discord_username={discord_username or "<missing>"}; '
            f'discord_display_name={discord_display_name or "<missing>"}; '
            f'discord_global_name={discord_global_name or "<missing>"}'
        )
        try:
            return await self.post_json('/connect', payload)
        except WalterApiError as exc:
            if 'HTTP 405' not in str(exc):
                raise
            return await self.post_json('/api/v1/discord/authorize', payload)

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

    async def cube_vote_poll(self, league_id: int, play_date_id: int) -> dict[str, Any]:
        return await self.get_json(f'/api/v1/leagues/{league_id}/cube-votes/{play_date_id}')

    async def register_cube_poll(self, league_id: int, play_date_id: int, channel_id: int, message_id: int) -> dict[str, Any]:
        return await self.post_json('/api/v1/discord/cube-polls', {
            'league_id': league_id,
            'play_date_id': play_date_id,
            'channel_id': str(channel_id),
            'message_id': str(message_id),
        })

    async def submit_cube_vote(
        self,
        discord_user_id: int,
        league_id: int,
        play_date_id: int,
        cube_id: int,
        selected: bool,
    ) -> dict[str, Any]:
        return await self.post_json('/api/v1/discord/cube-vote', {
            'discord_user_id': str(discord_user_id),
            'league_id': league_id,
            'play_date_id': play_date_id,
            'cube_id': cube_id,
            'selected': selected,
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


def format_league_standings(payload: dict[str, Any]) -> str:
    league = payload.get('league') or {}
    standings = payload.get('standings') or []
    lines = [f"**League standings: {league.get('name', 'League')}**"]
    if not standings:
        lines.append('No league standings are available yet.')
        return '\n'.join(lines)

    for row in standings:
        lines.append(
            f"{row['rank']}. {row['name']} — {row['league_points']} pts "
            f"({row['wins']}-{row['losses']}-{row['draws']}, {row['played']} events)"
        )
    return _truncate_lines(lines)


def format_league_play_dates(payload: dict[str, Any]) -> str:
    league = payload.get('league') or {}
    play_dates = payload.get('play_dates') or []
    lines = [
        f"**Play dates for {league.get('name', 'League')}**",
        'Use the play date ID with `/cube_poll league_id:<league id> play_date_id:<play date id>`.',
    ]
    if not play_dates:
        lines.append('No play dates are configured for this league.')
        return '\n'.join(lines)

    for play_date in play_dates:
        status = 'active' if play_date.get('is_active') else 'inactive'
        cube_count = play_date.get('available_cube_count', 0)
        lines.append(f"{play_date['id']}: {play_date['play_date']} ({status}, {cube_count} cube(s))")
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


def format_cube_poll(payload: dict[str, Any]) -> str:
    league = payload.get('league') or {}
    play_date = payload.get('play_date') or {}
    cubes = (payload.get('cubes') or [])[:len(CUBE_POLL_EMOJIS)]
    lines = [
        f"**Cube vote: {league.get('name', 'League')} — {play_date.get('play_date', 'play date')}**",
        'React to vote. Connected Discord accounts mirror Walter cube voting; each reaction is one vote (up to 3 total votes on Walter).',
    ]
    if not cubes:
        lines.append('No cubes are available for this play date.')
        return '\n'.join(lines)
    for index, cube in enumerate(cubes):
        lines.append(f"{CUBE_POLL_EMOJIS[index]} **{cube.get('title', 'Cube')}** — {cube.get('votes', 0)} vote(s)")
        if cube.get('cube_cobra_url'):
            lines.append(f"   {cube['cube_cobra_url']}")
    return _truncate_lines(lines)


class WalterBot(discord.Client):
    def __init__(self):
        intents = discord.Intents.default()
        intents.reactions = True
        super().__init__(intents=intents)
        self.tree = app_commands.CommandTree(self)
        self.api = WalterApiClient(BOT_API_BASE_URL, BOT_API_KEY)
        self._last_announced_round: int | None = None
        self._ready_announced = False
        self._guild_commands_synced = False
        self._cube_polls: dict[int, dict[str, Any]] = {}

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

        if not self._guild_commands_synced:
            if BOT_SYNC_GUILD_COMMANDS:
                await self._sync_guild_commands()
            elif BOT_CLEAR_GUILD_COMMANDS:
                await self._clear_guild_commands()

        if BOT_CHANNEL_ID and BOT_ANNOUNCE_READY and not self._ready_announced:
            channel = await self._get_messageable_channel(BOT_CHANNEL_ID)
            if channel is not None:
                await channel.send('Walter bot is online. Use `/tournaments`, `/leagues`, `/standings`, `/league_standings`, `/pairings`, or `/connect` to get started.')
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

    async def _clear_guild_commands(self):
        for guild in self.guilds:
            try:
                self.tree.clear_commands(guild=guild)
                await self.tree.sync(guild=guild)
                print(f'Cleared guild-specific slash commands for guild {guild.id}; using global commands only.')
            except discord.DiscordException as exc:
                print(f'Could not clear guild slash commands for guild {guild.id}: {exc}')
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

    async def _refresh_cube_poll_message(self, message_id: int):
        metadata = self._cube_polls.get(message_id)
        if not metadata:
            return
        try:
            payload = await self.api.cube_vote_poll(metadata['league_id'], metadata['play_date_id'])
            message = metadata.get('message')
            if message is None:
                channel = await self._get_messageable_channel(str(metadata['channel_id']))
                if channel is None or not hasattr(channel, 'fetch_message'):
                    return
                message = await channel.fetch_message(message_id)
                metadata['message'] = message
            await message.edit(content=format_cube_poll(payload))
        except Exception as exc:
            print(f'Cube poll refresh failed for message {message_id}: {exc}')

    async def _poll_cube_vote_updates(self, message_id: int):
        while not self.is_closed() and message_id in self._cube_polls:
            await self._refresh_cube_poll_message(message_id)
            await asyncio.sleep(max(BOT_POLL_INTERVAL_SECONDS, 10))

    async def on_raw_reaction_add(self, payload: discord.RawReactionActionEvent):
        await self._handle_cube_vote_reaction(payload, True)

    async def on_raw_reaction_remove(self, payload: discord.RawReactionActionEvent):
        await self._handle_cube_vote_reaction(payload, False)

    async def _handle_cube_vote_reaction(self, payload: discord.RawReactionActionEvent, selected: bool):
        if payload.user_id == (self.user.id if self.user else None):
            return
        metadata = self._cube_polls.get(payload.message_id)
        if not metadata:
            return
        emoji = str(payload.emoji)
        cube_ids = metadata.get('cube_ids') or []
        if emoji not in CUBE_POLL_EMOJIS:
            return
        index = CUBE_POLL_EMOJIS.index(emoji)
        if index >= len(cube_ids):
            return
        try:
            await self.api.submit_cube_vote(payload.user_id, metadata['league_id'], metadata['play_date_id'], cube_ids[index], selected)
            await self._refresh_cube_poll_message(payload.message_id)
        except WalterApiError as exc:
            print(f'Could not mirror Discord cube vote for user {payload.user_id}: {exc}')


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


@bot.tree.command(name='leagues', description='List Walter leagues.')
async def leagues(interaction: discord.Interaction):
    await interaction.response.defer(thinking=True)
    try:
        payload = await bot.api.leagues()
        leagues_payload = payload.get('leagues') or []
        lines = ['**Walter leagues**']
        for league in leagues_payload[:25]:
            league_type = 'cube league' if league.get('is_cube_league') else 'league'
            lines.append(f"{league['id']}: {league['name']} ({league_type})")
        await interaction.followup.send(_truncate_lines(lines), ephemeral=True)
    except WalterApiError as exc:
        await interaction.followup.send(str(exc), ephemeral=True)


@bot.tree.command(name='league_play_dates', description='List cube league play dates for /cube_poll.')
@app_commands.describe(league_id='Walter cube league ID')
async def league_play_dates(interaction: discord.Interaction, league_id: int):
    await interaction.response.defer(thinking=True, ephemeral=True)
    try:
        await interaction.followup.send(
            format_league_play_dates(await bot.api.league_play_dates(league_id)),
            ephemeral=True,
        )
    except WalterApiError as exc:
        await interaction.followup.send(str(exc), ephemeral=True)


@bot.tree.command(name='league_standings', description='Print league standings.')
@app_commands.describe(league_id='Walter league ID')
async def league_standings(interaction: discord.Interaction, league_id: int):
    await interaction.response.defer(thinking=True)
    try:
        await interaction.followup.send(format_league_standings(await bot.api.league_standings(league_id)))
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
    display_name = getattr(interaction.user, 'display_name', '') or ''
    global_name = getattr(interaction.user, 'global_name', '') or ''
    try:
        payload = await bot.api.authorize_discord_user(
            interaction.user.id,
            username,
            one_time_pass,
            discord_display_name=display_name,
            discord_global_name=global_name,
        )
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


@bot.tree.command(name='cube_poll', description='Post and pin a Discord mirror of a Walter cube vote.')
@app_commands.describe(
    league_id='Walter cube league ID',
    play_date_id='Walter league play date ID for the cube vote',
)
async def cube_poll(interaction: discord.Interaction, league_id: int, play_date_id: int):
    await interaction.response.defer(thinking=True, ephemeral=True)
    try:
        payload = await bot.api.cube_vote_poll(league_id, play_date_id)
        cubes = (payload.get('cubes') or [])[:len(CUBE_POLL_EMOJIS)]
        if not cubes:
            await interaction.followup.send('That cube vote does not have any cubes to poll.', ephemeral=True)
            return
        message = await interaction.channel.send(format_cube_poll(payload))
        for emoji in CUBE_POLL_EMOJIS[:len(cubes)]:
            await message.add_reaction(emoji)
        try:
            await message.pin(reason='Walter cube vote poll')
        except discord.DiscordException as exc:
            await interaction.followup.send(f'Posted the poll, but could not pin it: {exc}', ephemeral=True)
        else:
            await interaction.followup.send('Posted and pinned the cube vote poll.', ephemeral=True)
        bot._cube_polls[message.id] = {
            'league_id': league_id,
            'play_date_id': play_date_id,
            'channel_id': message.channel.id,
            'message': message,
            'cube_ids': [cube['id'] for cube in cubes],
        }
        await bot.api.register_cube_poll(league_id, play_date_id, message.channel.id, message.id)
        bot.loop.create_task(bot._poll_cube_vote_updates(message.id))
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
