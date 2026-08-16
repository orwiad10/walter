# Walter Site Guide

**Complete page-by-page documentation**  
Version 1.0 · Generated 16 August 2026

## About this guide

Walter is a web application for running Magic: The Gathering tournaments and leagues. This guide documents the visible site by audience and workflow. Paths containing `<id>` use the numeric identifier shown by Walter. Features are permission-controlled: a page may be hidden or return **403 Forbidden** unless the signed-in account has the corresponding permission.

## 1. Public and account pages

### Landing page — `/`
The public entry point. Signed-in users are directed into Walter; visitors can proceed to sign in or registration. It also establishes the site theme and primary navigation.

### Home dashboard — `/home`
The signed-in overview. It presents relevant active tournaments and shortcuts based on the user's role. Use this as the normal starting point after login.

### Register — `/register`
Creates a player account. Enter the requested identity, email, and password fields. Public registration may require a valid tournament invitation when invite-only mode is enabled. Submission sends a six-digit email verification PIN rather than immediately activating the account.

### Verify registration — `/register/verify` and `/register/verify/<token>`
Completes pending registration with the emailed PIN. The token form supports verification links. PINs expire according to the server configuration; restart registration if the token is invalid or expired.

### Sign in and out — `/login`, `/logout`
Sign in with the registered email and password. Failed attempts are security logged and may contribute to IP blocking. Sign out when using a shared device.

### Password reset — `/password-reset`, `/password-reset/<token>`
Request a reset email, then open its token page to set a replacement password. Tokens are time limited and single-purpose.

## 2. Player dashboard and preferences

### User settings — `/settings`
Manage appearance (light or dark mode), Discord identity, Discord connection passes, and—when permitted—API keys. A generated Discord pass is shown once and is used with the bot's `/connect` command. API keys are also shown once; store them securely.

### Revoke API key — `/settings/api-keys/<id>/revoke`
A settings action that permanently revokes one of the current user's keys. Existing integrations using it will begin receiving HTTP 401 responses.

### My tournaments — `/my-tournaments`
Lists tournaments associated with the current player, including quick links to event details, rounds, standings, and deck submission.

### My leagues — `/my-leagues`
Lists the leagues in which the current user participates and links to league standings and cube voting where applicable.

## 3. Tournament player pages

### Tournament overview — `/t/<id>`
The event hub. It shows format, structure, state, players, current round, join status, and organizer controls when authorized. Players can request to join; staff can add or replace players, manage rounds, and complete the event.

### Join link and QR code — `/t/<id>/join-link`, `/t/<id>/join-qr.png`
The shareable registration page displays an event pass/link and a scannable PNG QR code. Organizers can distribute either to players. The QR endpoint is an image resource rather than an HTML page.

### Join action — `/t/<id>/join`
Submits the current account's join request or passcode. Depending on tournament settings, entry may be immediate or remain pending for staff approval.

### Round page — `/t/<id>/round/<round-id>`
Displays pairings by table, match completion state, and round context. Players select their match to report a result. Staff can access repair/delete controls when authorized.

### Match report — `/match/<match-id>`
Reports or edits the selected table result. Two-player events record wins and draws; Commander/multiplayer events record placements and draw state. Walter prevents invalid or late changes based on tournament state and permissions.

### Standings — `/t/<id>/standings`
Ranks players using match points and tiebreakers (including opponent match-win, game-win, and opponent game-win percentages where applicable). Dropped players remain identifiable. Treat standings as provisional until all results are entered.

### Elimination bracket — `/t/<id>/bracket`
Shows the Top 8 or Top 4 playoff bracket once the event is cut. Pairing and winner progression are displayed according to the event state.

### Draft seating — `/t/<id>/draft-seating`
Shows randomized or assigned pod/seating information for Draft events. Use the displayed seat order before opening product.

### Tournament logs — `/t/<id>/logs`
An authorized audit trail of pairing, scoring, timer, player, and tournament-management actions.

## 4. Decklists

### Decklist gallery — `/t/<id>/decklists`
Shows submitted decks according to visibility and event permissions. Staff can review player submissions; players see what the tournament policy allows.

### Player deck — `/t/<id>/players/<player-id>/deck`
Displays a single registered player's parsed deck, source information, and any uploaded deck image.

### Deck search — `/t/<id>/deck/search`
JSON-backed card lookup used by manual deck entry. Search by card name and choose the intended printing/result.

### Manual submission — `/t/<id>/deck/manual`
Accepts a manually assembled main deck and sideboard. Review counts and unresolved cards before submitting.

### MTGO import — `/t/<id>/deck/mtgo`
Imports a Magic Online text decklist. Walter parses quantities, card names, and sideboard lines; correct any unrecognized entries.

### Deck image upload/delete — `/t/<id>/deck/image`, `/t/<id>/deck/image/delete`
Uploads a deck photo under server size/type constraints, or removes the current image. Avoid including personal information in photographs.

## 5. Leagues and cube leagues

### League view — `/leagues/<id>`
Shows league metadata, membership, linked tournaments, results, and ranked standings. Scoring may use total/percentage results or Colley ratings; optional Glicko ratings show rating and deviation.

### League settings — `/leagues/<id>/settings`
Authorized league configuration for name, dates, scoring system, percentage counted, Glicko, and league-specific options.

### Cubes and voting — `/leagues/<id>/cubes`
For cube leagues, manages Cube Cobra entries, play dates, ballot availability, and player votes. A player may allocate no more than three total cube selections per play date. Image previews may be proxied by `/cube-cobra-image`.

## 6. Communication and support

### Message center — `/messages`
Role-aware entry point that directs users to the appropriate mailbox.

### Player inbox — `/messages/player` or `/messages/inbox`
Lists received messages with read/unread state. Open a message to mark and view it.

### Sent messages — `/messages/sent`
Lists messages sent by the current user.

### Compose — `/messages/player/send` or `/messages/send`
Sends a direct message to an allowed recipient. Recipient search is assisted by `/api/users/search` and the unread navigation badge by `/api/messages/unread`.

### Message detail and reply — `/messages/view/<id>`, `/messages/<id>/reply`
Shows a conversation item and supports a reply when the current user is a participant.

### Judge messaging — `/messages/judge`
Judge-facing inbox and compose workflow for tournament assistance.

### Admin messaging — `/messages/admin`
Administrator broadcast/direct-message workflow with broader recipient selection.

### Reports — `/reports`
Submit and review the current user's site or event issues. Include actionable detail without credentials or private API keys.

### Lost and found — `/lost-and-found`
Browse or submit lost-and-found items across available venues. Venue staff also reach a scoped view at `/admin/venues/<venue-id>/lost-and-found`.

## 7. Tournament administration

### Admin panel — `/admin/panel`
Central operations dashboard and administrative navigation. Access depends on granular permissions, not merely whether a link is visible.

### New tournament — `/admin/tournaments/new`
Creates Commander, Draft, or supported 60-card constructed events. Configure name, format, Swiss/elimination structure, dates, round settings, league, venue, registration, and timers as applicable.

### Edit tournament — `/admin/tournaments/<id>/edit`
Updates tournament configuration. Be cautious changing structure or format after pairings/results exist.

### Ended tournaments — `/admin/tournaments/ended`
Archive of completed events with routes to inspect, reopen, or delete when authorized.

### Bulk tournament actions — `/admin/tournaments/bulk`
Applies supported operations to multiple selected events. Confirm the selection before submitting.

### Complete, reopen, delete — `/admin/tournaments/<id>/complete`, `/reopen`, `/delete`
Lifecycle actions. Complete freezes the ordinary event workflow; reopen restores an ended event; delete is destructive and should follow backup policy.

### Player and join-request actions
`/t/<id>/join-requests/<request-id>/approve` and `/reject` resolve pending entries. `/t/<id>/players/add` registers a player directly and `/t/<id>/players/<player-id>/replace` swaps an entry while preserving event continuity where supported.

### Round controls
`/t/<id>/set-rounds` sets the planned count; `/pair-next-round` creates pairings; `/round/<round-id>/repair` rebuilds/fixes a round; `/round/<round-id>/delete` rolls it back. Verify results and backups before destructive round actions.

### Timer controls
`/t/<id>/start-timer/<timer>`, `/pause-timer/<timer>`, `/stop-timer/<timer>`, and `/restart-timer/<timer>` control named tournament timers. The timer bar appears on event pages and is shared across clients.

## 8. League administration

### League list/create — `/admin/leagues`
Lists all leagues and creates new standard or cube leagues.

### League detail — `/admin/leagues/<id>`
Manages members, linked tournaments, manual results, scoring, play dates, and cube-league administration.

### Delete league — `/admin/leagues/<id>/delete`
Permanently removes the league subject to database constraints. Export or back up first.

## 9. Venue, vendor, artist, and schedule administration

### Venues — `/admin/venues`
Lists and creates event locations.

### Venue detail/update — `/admin/venues/<id>`, `/admin/venues/<id>/update`
Views location details, tournament calendar, lost-and-found items, and editable venue fields.

### Bulk add venue tournaments — `/admin/venues/<id>/tournaments/bulk-add`
Creates multiple scheduled events for a venue from one form.

### Vendors — `/admin/venues/vendors`
Creates/lists vendors; `/admin/venues/vendors/<id>/update` edits an existing vendor.

### Artists — `/admin/venues/artists`
Creates/lists event artists; `/admin/venues/artists/<id>/update` edits an existing artist.

### Schedule — `/admin/schedule`
Combined operational calendar for venues and tournaments. `/admin/schedule/export.csv` downloads it as CSV.

### Lost-item update — `/admin/venues/<venue-id>/lost-and-found/<item-id>/update`
Changes item status/details, such as marking an item claimed.

## 10. People and access administration

### Users — `/admin/users`
Searchable user roster with bulk-selection tools.

### User detail — `/admin/users/<id>`
Shows account, roles/permissions, tournament associations, and administrative actions.

### User actions
`/admin/users/<id>/add` adds a user to an event; `/remove/<tournament-id>` removes that association; `/update` edits the account; `/delete` removes it. `/admin/users/bulk-delete` deletes a validated selection.

### Register player — `/admin/register-player`
Creates a single player account administratively.

### Bulk register — `/admin/bulk-register`
Imports multiple player records. Validate duplicates and malformed rows before confirming.

### Staff — `/admin/staff`
Lists and manages staff assignments.

### Tournament judges — `/admin/tournaments/<id>/judges`
Assigns judges to a specific event.

### Judge break — `/admin/judges/<user-id>/break`
Toggles/records a judge break state for staffing visibility.

### Permissions — `/admin/permissions`
Edits role permission assignments using the permission schema. Changes take effect across navigation and server-side authorization; preserve at least one viable administrator path.

### Registration invites — `/admin/registration-invites`
Creates and lists invite/passcodes for controlled account creation or event onboarding. `/admin/registration-invites/<id>/revoke` invalidates one.

## 11. Operations, safety, and auditing

### Site settings — `/admin/site-settings`
Edits runtime-backed site options exposed by the application. Validate operational and email settings before relying on them in production.

### Backups — `/admin/backup`
Creates, lists, restores, or manages backups according to the selected form action. `/admin/backup/export` exports a backup artifact. Restores are high impact: schedule downtime and retain the pre-restore copy.

### Site logs — `/admin/logs`
Audit history for application actions and outcomes.

### API logs — `/admin/api-logs`
Request/response audit records for API traffic. Authorization values are redacted, but bodies may contain operational data; limit access appropriately.

### Submitted reports — `/admin/reports`
Administrative report queue. `/admin/reports/<id>/update` changes status/assignment, and `/admin/reports/export.csv` exports records.

### Bad logins — `/admin/security/bad-logins`
Shows failed authentication activity for security review.

### IP blacklist — `/admin/security/ip-blacklist`
Lists blocked addresses. `/toggle` enables/disables an entry and `/export` downloads the list. Verify shared/NAT addresses before blocking.

### Current connections — `/admin/current-connections`
Shows recently tracked clients/connections. `/admin/current-connections/blacklist` adds a selected address to the blacklist.

## 12. Media and utility resources

### Media — `/media/<filename>`
Serves authorized uploaded media through a safe path. Direct availability depends on the referenced file and access rules.

### Cube image proxy — `/cube-cobra-image`
Fetches an allowed Cube Cobra/Scryfall preview with host and size safeguards; used by cube pages rather than normal navigation.

## 13. Recommended workflows

### Run a Swiss tournament
1. Create the event under **Admin → New tournament**.
2. Share its join link/QR or add players directly.
3. Resolve pending join requests and confirm the roster.
4. Set rounds and pair the next round.
5. Players report matches; staff monitor incomplete tables.
6. Review standings, then pair again only after results are correct.
7. Optionally cut to an elimination bracket.
8. Complete the event and verify logs/results.

### Run a cube league vote
1. Create a cube league and add Cube Cobra entries.
2. Add play dates and select available cubes for each date.
3. Members vote on the league cubes page (up to three selections).
4. Optionally use `/league_play_dates` and `/cube_poll` in Discord.
5. Review totals, select the cube, and retain the vote history.

## 14. Access and troubleshooting

A **401** usually means the session or API credential is absent/invalid. A **403** means the identity lacks permission. A **404** may mean the object does not exist or is deliberately hidden. A **409** generally indicates a state conflict (for example, a vote limit or attempting to alter a result after another round exists). Never share passwords, one-time Discord passes, reset links, API keys, bot tokens, or backup encryption material.
