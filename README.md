# MTG Tournament Swiss App (FastAPI + NiceGUI + SQLite)

## Quickstart
1) Create and activate a virtualenv, then install deps:
   python -m venv .venv
   .venv\Scripts\activate   (Windows)
   source .venv/bin/activate  (macOS/Linux)
   pip install -r requirements.txt

2) Optional environment variables:
   set PASSWORD_SEED=some-random-string     (Windows)
   export PASSWORD_SEED=some-random-string  (macOS/Linux)
   # Optional: specify a separate SQLite database file for logs
   set MTG_LOG_DB_PATH=mtg_logs.db          (Windows)
   export MTG_LOG_DB_PATH=mtg_logs.db       (macOS/Linux)

3) Initialize the DB:
   python - <<'PY'
from app.app import create_app, db
create_app()
db.create_all()
PY

4) Run:
   uvicorn app.app:app --reload

## Features
- Player & Admin login
- Tournaments: Commander, Draft, Constructed
- WotC recommended Swiss round counts (override allowed)
- Swiss pairing (avoid rematches, handle byes)
- Match reporting with game wins (for GW%)
- Standings with tiebreakers: OMW%, GW%, OGW%
- Cut to Top 8 / Top 4

## Notes
- Passwords are stored encrypted with AES-256 using a seed specified via `PASSWORD_SEED`.
- This is an MVP. You can extend forms, validation, and UI as needed.
