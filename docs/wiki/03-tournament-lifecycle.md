# 3. Tournament lifecycle management

This section tracks an event from configuration through staffing.

## Configure events
* The **New Tournament** form captures structure, REL, commander scoring, round lengths, draft/deck timers, seating start, and optional join approval in a single table-driven editor.【F:app/templates/admin/new_tournament.html†L3-L114】
* Cube-only toggles, start time pickers, and cut presets help organisers standardise their offerings while still allowing overrides when needed.【F:app/templates/admin/new_tournament.html†L21-L114】

## Assign staff & judges
* Dedicated judge assignment lets organisers select a head judge and toggle any number of floor judges per event.【F:app/templates/admin/judges.html†L3-L20】
* The **Staff Management** view aggregates every tournament with its staffing plan, offering one-click break timers for judges and live countdowns until they return.【F:app/templates/admin/staff.html†L3-L29】

## Publish schedules
* The schedule table estimates start/end times for each tournament and ships with quick export/print buttons for venue signage or social posts.【F:app/templates/admin/schedule.html†L3-L19】

## Monitor the live hub
* Tournament detail pages surface head/floor judges, passcode visibility, join workflows, pairing controls, and quick links into standings, brackets, and logs.【F:app/templates/tournament/view.html†L3-L67】
* Players see their deck submission status, and staff can collect lists via the built-in card searcher, paste, MTGO file upload, or deck photos to match paper requirements.【F:app/templates/tournament/view.html†L69-L195】

![Tournament overview](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-tournament-overview.png)
