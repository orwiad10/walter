# WaLTER Operations Wiki

## Quick setup
1. Create and activate a virtual environment, then install dependencies:
   ```bash
   python -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```
   These commands mirror the quickstart documented in the project README.【F:README.md†L3-L26】
2. Set the Flask environment variables (at minimum `FLASK_APP=app.app:app`). Optional knobs such as `PASSWORD_SEED` and `MTG_LOG_DB_PATH` match the upstream defaults.【F:README.md†L10-L18】
3. Initialize the database and default admin account:
   ```bash
   flask --app app.app db-init
   ```
   The command seeds `admin@example.com` / `admin123` for local administration.【F:README.md†L20-L26】
4. (Optional) Load the curated demo dataset used for the screenshots in this guide:
   ```bash
   python scripts/seed_sample_data.py --reset
   ```
   The script rebuilds the schema, provisions staff & player accounts, schedules tournaments, pairs round one, and records supporting artefacts such as messages, lost-and-found items, and conduct reports.【F:scripts/seed_sample_data.py†L21-L219】
5. Run the development server:
   ```bash
   flask --app app.app run --debug
   ```

## Page directory
1. [Dashboard & global navigation](01-dashboard-and-navigation.md)
2. [Authentication & accounts](02-authentication-and-accounts.md)
3. [Tournament lifecycle management](03-tournament-lifecycle.md)
4. [Rounds, pairings & results](04-rounds-and-results.md)
5. [Player tools & deck submission](05-player-engagement.md)
6. [Messaging & announcements](06-communications.md)
7. [Support desks: Lost & Found + incident reports](07-support-and-ops.md)
8. [Admin toolbox](08-admin-toolbox.md)
