#!/bin/bash
CONFIG_FILE="config.yaml"
if [ ! -f "$CONFIG_FILE" ]; then
  echo "Missing $CONFIG_FILE"
  exit 1
fi

read_yaml() {
  python - <<PY
import yaml,sys
cfg=yaml.safe_load(open(sys.argv[1]))
print(cfg.get(sys.argv[2],''))
PY
}

DB_FILE=$(read_yaml "$CONFIG_FILE" db_file)
ADMIN_EMAIL=$(read_yaml "$CONFIG_FILE" admin_email)
ADMIN_PASS=$(read_yaml "$CONFIG_FILE" admin_pass)
SECRET=$(read_yaml "$CONFIG_FILE" secret)

if [ -z "$DB_FILE" ]; then
  DB_FILE="mtg_tournament_$(date +%Y%m%d%H%M%S).db"
fi
if [ -z "$ADMIN_EMAIL" ]; then
  ADMIN_EMAIL="admin@example.com"
fi
if [ -z "$ADMIN_PASS" ]; then
  ADMIN_PASS="admin123"
fi
if [ -z "$SECRET" ]; then
  SECRET="dev-secret-change-me"
fi

export MTG_DB_PATH="$DB_FILE"
export FLASK_APP=app.app:app
export FLASK_SECRET="$SECRET"
python -m pip install -r requirements.txt >/dev/null
python -m flask db-init
python -m flask create-admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASS"
flask --app app.app run --debug
