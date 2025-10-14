# MTG Tournament Swiss App (Flask + SQLite)

## Quickstart
1) Modify config.yaml
   -change settings as needed in config.yaml

2) Start Server
   -run start-server.ps1 to install pre-reqs and start flask

## Features
   - Player & Admin login
   - Tournaments: Commander, Draft, Constructed
   - WotC recommended Swiss round counts (override allowed)
   - Swiss pairing (avoid rematches, handle byes)
   - Match reporting with game wins (for GW%)
   - Standings with tiebreakers: OMW%, GW%, OGW%
   - Cut to Top 8 / Top 4

## Notes
   - Default secret key is set for dev; change FLASK_SECRET in production.
   - Passwords are stored encrypted with AES-256 using a seed specified via `PASSWORD_SEED`.
   - This is an MVP. You can extend forms, validation, and UI as needed.

## Wiki
   -See the wiki for screen shots of the app