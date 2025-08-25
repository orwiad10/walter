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

DEFAULT_DB_FILE="mtg_tournament.db"
DEFAULT_LOG_DB_FILE="mtg_tournament_logs.db"

DB_FILE=$(read_yaml "$CONFIG_FILE" db_file)
LOG_DB_FILE=$(read_yaml "$CONFIG_FILE" log_db_file)
ADMIN_EMAIL=$(read_yaml "$CONFIG_FILE" admin_email)
ADMIN_PASS=$(read_yaml "$CONFIG_FILE" admin_pass)
FLASK_SECRET=$(read_yaml "$CONFIG_FILE" flask_secret)
PASSWORD_SEED=$(read_yaml "$CONFIG_FILE" password_seed)
FLASK_IP=$(read_yaml "$CONFIG_FILE" flask_ip)
FLASK_PORT=$(read_yaml "$CONFIG_FILE" flask_port)

if [ -z "$DB_FILE" ]; then
  DB_FILE="$DEFAULT_DB_FILE"
fi
if [ -z "$LOG_DB_FILE" ]; then
  LOG_DB_FILE="$DEFAULT_LOG_DB_FILE"
fi
if [ -z "$ADMIN_EMAIL" ]; then
  ADMIN_EMAIL="admin@example.com"
fi
if [ -z "$ADMIN_PASS" ]; then
  ADMIN_PASS="admin123"
fi
if [ -z "$FLASK_SECRET" ]; then
  FLASK_SECRET="dev-secret-change-me"
fi
if [ -z "$PASSWORD_SEED" ]; then
  PASSWORD_SEED="dev-password-seed-change-me"
fi
if [ -z "$FLASK_IP" ]; then
  FLASK_IP="127.0.0.1"
fi
if [ -z "$FLASK_PORT" ]; then
  FLASK_PORT="5000"
fi

if [ "$DB_FILE" = "$DEFAULT_DB_FILE" ]; then
  TS=$(date +%Y%m%d%H%M%S)
  DB_FILE="mtg_tournament_${TS}.db"
  LOG_DB_FILE="mtg_tournament_logs_${TS}.db"
elif [ "$LOG_DB_FILE" = "$DEFAULT_LOG_DB_FILE" ]; then
  LOG_DB_FILE="${DB_FILE%.db}_logs.db"
fi

export MTG_DB_PATH="$DB_FILE"
export MTG_LOG_DB_PATH="$LOG_DB_FILE"
export FLASK_APP=app.app:app
export FLASK_SECRET="$FLASK_SECRET"
export PASSWORD_SEED="$PASSWORD_SEED"
export FLASK_RUN_HOST="$FLASK_IP"
export FLASK_RUN_PORT="$FLASK_PORT"
python -m pip install -r requirements.txt >/dev/null
python -m flask db-init
python -m flask create-admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASS"
flask --app app.app run --debug --host "$FLASK_IP" --port "$FLASK_PORT"
