#!/bin/bash
DB_FILE="$1"
if [ -z "$DB_FILE" ]; then
  DB_FILE="mtg_tournament_$(date +%Y%m%d%H%M%S).db"
fi
export MTG_DB_PATH="$DB_FILE"
export FLASK_APP=app.app:app
python -m pip install -r requirements.txt >/dev/null
python -m flask db-init
python -m flask create-admin --email admin@example.com --password admin123
flask --app app.app run --debug
