# 4. Rounds, pairings & results

## Pairing control room
* Round pages list every table with format-aware rendering (BYE detection for Swiss, four-player pods for Commander) and quick links to report or edit results based on staff/player permissions.【F:app/templates/tournament/round.html†L1-L75】
* Managers can re-pair or delete a round (before results are posted) directly from the same screen, saving time during judge calls.【F:app/templates/tournament/round.html†L6-L15】
* The shared timer bar keeps the round/draft/deck clocks front-and-centre so the scorekeeper and judges stay in sync.【F:app/templates/tournament/round.html†L4-L5】【F:app/templates/tournament/_timer_bar.html†L1-L27】

![Round control panel](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-round-pairings.png)

## Entering results
* The reporting form adapts by format: Commander captures placements for up to four players plus drops/draws, while Constructed events capture game wins, draws, and drop toggles (and auto-awards BYEs).【F:app/templates/match/report.html†L1-L90】

## Tracking standings
* Standings display the full tiebreak suite (points, OMW%, GW%, OGW%) and include print-friendly formatting for quick posting.【F:app/templates/tournament/standings.html†L1-L25】
* When a cut is configured, the projected top is highlighted so staff know where the bubble currently sits.【F:app/templates/tournament/standings.html†L27-L36】

![Standings table](browser:/invocations/ggqhabqb/artifacts/artifacts/wiki-standings.png)
