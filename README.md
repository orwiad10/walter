# MTG Tournament Swiss App (Flask + SQLite)

## Quickstart
1) Create and activate a virtualenv, then install deps:
   python -m venv .venv
   .venv\Scripts\activate   (Windows)
   source .venv/bin/activate  (macOS/Linux)
   pip install -r requirements.txt

2) Set the Flask env vars (dev):
   set FLASK_APP=app.app:app     (Windows)
   export FLASK_APP=app.app:app  (macOS/Linux)

3) Initialize the DB and create an admin:
   flask --app app.app db-init
   flask --app app.app create-admin --email admin@example.com --password admin123

4) Run:
   flask --app app.app run --debug

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
- This is an MVP. You can extend forms, validation, and UI as needed.
