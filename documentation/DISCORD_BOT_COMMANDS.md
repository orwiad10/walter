# Walter Discord Bot Command Guide

**Separate slash-command documentation**  
Version 1.0 · Generated 16 August 2026

## 1. Purpose and prerequisites

The bundled Walter bot provides nine Discord slash commands for tournament discovery, standings, pairings, league/cube workflows, account connection, and result reporting. The bot must be online, its commands synchronized, and its API key configured with Walter's `tournaments.manage` permission.

Commands may take time to appear after a global sync. Command output marked **ephemeral** is visible only to the invoking Discord user. Do not paste Walter one-time passes or API keys into public chat.

## 2. Discovery commands

### `/tournaments`
Lists up to 25 Walter tournaments as `ID: name (format)`. The response is ephemeral. Use the numeric ID with `/standings`, `/pairings`, or `/report_pairing`.

**Parameters:** none.  
**Typical use:** `/tournaments`

### `/leagues`
Lists up to 25 leagues, identifying standard versus cube leagues. The response is ephemeral. Use the numeric ID with league commands.

**Parameters:** none.  
**Typical use:** `/leagues`

### `/league_play_dates league_id:<number>`
Lists a cube league's Walter play-date IDs for use with `/cube_poll`. The response is ephemeral.

- `league_id` — required numeric cube league ID.

**Typical use:** `/league_play_dates league_id:7`

## 3. Standings and pairings

### `/standings tournament_id:<number>`
Posts tournament standings, including rank, player, points, and supported tiebreak information. The successful response is visible in the channel; API errors are ephemeral.

- `tournament_id` — required numeric Walter tournament ID.

**Typical use:** `/standings tournament_id:42`

### `/league_standings league_id:<number>`
Posts ranked league standings. Displayed fields reflect the league's configured scoring/rating system.

- `league_id` — required numeric Walter league ID.

**Typical use:** `/league_standings league_id:7`

### `/pairings tournament_id:<number>`
Posts table assignments for the latest paired round. Each pairing identifies table and players; byes are indicated by Walter's response formatting.

- `tournament_id` — required numeric Walter tournament ID.

**Typical use:** `/pairings tournament_id:42`

If no round exists, the bot returns the API error ephemerally.

## 4. Connect a Walter account

### `/connect one_time_pass:<text>`
Links the invoking Discord account to a Walter user. The entire interaction is ephemeral.

1. In Walter, open **Settings**.
2. Save your Discord username (without concern for a leading `@`; Walter normalizes it).
3. Generate a new Discord connection pass.
4. In Discord, run `/connect` and enter that pass.
5. Confirm the connected Walter name in the private bot response.

The username must match the invoking Discord username case-insensitively. The pass is single-use and consumed on success. Generating a new pass disconnects the previous Discord user ID until reconnection. A Discord identity cannot be attached to two Walter users.

## 5. Report a pairing result

### `/report_pairing tournament_id:<number> table_number:<number> player1_wins:<number> player2_wins:<number> [draws:<number>]`
Reports a two-player result for the latest round. The command response is ephemeral.

- `tournament_id` — required tournament ID.
- `table_number` — required table number from `/pairings`.
- `player1_wins` — required wins for the **first-listed** player.
- `player2_wins` — required wins for the **second-listed** player.
- `draws` — optional drawn games; defaults to 0.

**Example:** `/report_pairing tournament_id:42 table_number:3 player1_wins:2 player2_wins:1 draws:0`

Before submitting, verify which player is listed first. Scores must be whole non-negative numbers. The caller must have connected Discord and be a player at that table. Commander reporting is not supported by this command. Walter rejects changes after the next round has been paired; contact event staff for corrections.

## 6. Cube poll command

### `/cube_poll league_id:<number> play_date_id:<number>`
Posts a Discord mirror of a Walter cube vote in the current channel, adds one reaction emoji per available cube, and attempts to pin the message. The command's confirmation is ephemeral; the poll itself is public.

- `league_id` — required cube league ID.
- `play_date_id` — required Walter league play-date ID (discover it with `/league_play_dates`).

**Typical use:** `/cube_poll league_id:7 play_date_id:19`

React to select a cube; remove the reaction to deselect it. The bot mirrors changes to Walter and refreshes totals. Only connected Discord accounts can vote, the cube must still be on that date's ballot, and Walter permits no more than three selected cubes per user/date. The bot recognizes at most the first set of cubes for which it has configured reaction emojis. It requires permission to send messages, add reactions, read reaction events/history, and pin/manage messages if pinning is desired. Failure to pin does not discard a successfully posted poll.

## 7. Automatic pairing announcements

When `bot_channel_id` and `bot_poll_tournament_id` are configured, the bot periodically checks for a newly paired round and posts pairings to the target channel. `bot_poll_interval_seconds` controls the interval. This feature is automatic and is not a slash command.

## 8. Visibility summary

- Ephemeral on success: `/tournaments`, `/leagues`, `/league_play_dates`, `/connect`, `/report_pairing`, and `/cube_poll` confirmation.
- Channel-visible on success: `/standings`, `/league_standings`, `/pairings`, plus the poll created by `/cube_poll`.
- Errors are generally returned ephemerally to avoid clutter and accidental disclosure.

## 9. Troubleshooting

**Command is missing:** Wait for global synchronization, restart with correct token/application configuration, or enable guild syncing temporarily for immediate development updates. Avoid keeping both stale guild copies and global commands, which can appear duplicated.

**401 / invalid API key:** The bot key is missing, malformed, or revoked. Create a new administrator API key and update `bot_api_key` securely.

**403:** The key owner lacks `tournaments.manage`, the Discord account is not connected, or the caller is not allowed to perform the requested write.

**404:** Recheck tournament, league, play-date, table, or poll IDs; the latest round may not exist yet.

**409:** The operation conflicts with current state, commonly a duplicate Discord connection, cube vote limit, or result report after the next round was paired.

**Poll reactions do nothing:** Connect with `/connect`; verify reaction event intents/permissions, that the reaction is one created by the bot, and that the cube remains on the ballot.

**Ready announcement absent:** It is disabled by default. Configure `bot_channel_id` and set `bot_announce_ready: true` only if wanted.

## 10. Operator configuration checklist

Set `bot_runtime_script: "discord_bot.py"`, `bot_token`, `bot_api_base_url`, and `bot_api_key`. Optional values include `bot_channel_id`, `bot_poll_tournament_id`, `bot_poll_interval_seconds`, `bot_announce_ready`, `bot_sync_guild_commands`, and `bot_clear_guild_commands`. Keep the bot token and API key outside source control, grant only required Discord permissions, and use HTTPS when the API is remote.
