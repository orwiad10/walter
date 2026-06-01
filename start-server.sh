#!/usr/bin/env bash
# Bash script to set up and run the MTG Tournament Swiss App.
# Installs dependencies, initializes the database, creates an admin user,
# and starts the Flask development server.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
REQUIREMENTS_FILE="$SCRIPT_DIR/requirements.txt"

PYTHON_BIN=""

detect_python() {
  local candidate
  for candidate in python3 python; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info.major >= 3 else 1)' >/dev/null 2>&1; then
      PYTHON_BIN="$candidate"
      return 0
    fi
  done
  return 1
}

run_as_root() {
  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    echo "Installing Python requires root privileges. Re-run as root or install python3 and python3-pip manually." >&2
    exit 1
  fi
}

install_python() {
  echo "Python 3 was not found. Attempting to install python3 and pip with the system package manager..." >&2

  if command -v apt-get >/dev/null 2>&1; then
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get update
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip
  elif command -v dnf >/dev/null 2>&1; then
    run_as_root dnf install -y python3 python3-pip
  elif command -v yum >/dev/null 2>&1; then
    run_as_root yum install -y python3 python3-pip
  elif command -v zypper >/dev/null 2>&1; then
    run_as_root zypper --non-interactive install python3 python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    run_as_root pacman -Sy --noconfirm python python-pip
  elif command -v apk >/dev/null 2>&1; then
    run_as_root apk add --no-cache python3 py3-pip
  elif command -v brew >/dev/null 2>&1; then
    brew install python
  else
    echo "Python 3 is required, and no supported package manager was found. Install python3 and python3-pip manually." >&2
    exit 1
  fi
}

if ! detect_python; then
  install_python
  if ! detect_python; then
    echo "Python 3 installation completed, but no usable python3/python command was found." >&2
    exit 1
  fi
fi

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Missing config.yaml" >&2
  exit 1
fi

# Ensure PyYAML is available so config.yaml can be parsed before installing the
# rest of the application requirements.
"$PYTHON_BIN" - <<'PY'
import subprocess
import sys
try:
    import yaml  # noqa: F401
except ModuleNotFoundError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet', 'PyYAML'])
PY

# Load settings from YAML config.
eval "$("$PYTHON_BIN" - "$CONFIG_FILE" <<'PY'
import shlex
import sys

import yaml

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    cfg = yaml.safe_load(f) or {}

keys = [
    'db_file',
    'log_db_file',
    'admin_email',
    'admin_pass',
    'flask_secret',
    'password_seed',
    'flask_ip',
    'flask_port',
]

for key in keys:
    value = cfg.get(key, '')
    if value is None:
        value = ''
    print(f'{key.upper()}={shlex.quote(str(value))}')
PY
)"

DEFAULT_DB_FILE="mtg_tournament.db"
DEFAULT_LOG_DB_FILE="mtg_tournament_logs.db"

DB_FILE="${DB_FILE:-$DEFAULT_DB_FILE}"
LOG_DB_FILE="${LOG_DB_FILE:-$DEFAULT_LOG_DB_FILE}"
ADMIN_EMAIL="${ADMIN_EMAIL:-admin@example.com}"
ADMIN_PASS="${ADMIN_PASS:-admin123}"
FLASK_SECRET="${FLASK_SECRET:-dev-secret-change-me}"
PASSWORD_SEED="${PASSWORD_SEED:-dev-password-seed-change-me}"
FLASK_IP="${FLASK_IP:-127.0.0.1}"
FLASK_PORT="${FLASK_PORT:-5000}"

cd "$SCRIPT_DIR"

export PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"
export PASSWORD_SEED
export FLASK_SECRET
export FLASK_RUN_HOST="$FLASK_IP"
export FLASK_RUN_PORT="$FLASK_PORT"

TIMESTAMP="$(date +%Y%m%d%H%M%S)"

if [[ "$DB_FILE" == "$DEFAULT_DB_FILE" ]]; then
  DB_FILE="mtg_tournament_${TIMESTAMP}.db"
  LOG_DB_FILE="mtg_tournament_logs_${TIMESTAMP}.db"
elif [[ "$LOG_DB_FILE" == "$DEFAULT_LOG_DB_FILE" ]]; then
  DB_DIR="$(dirname "$DB_FILE")"
  DB_BASE="$(basename "$DB_FILE")"
  DB_BASE="${DB_BASE%.*}"
  if [[ -z "$DB_DIR" || "$DB_DIR" == "." ]]; then
    LOG_DB_FILE="${DB_BASE}_logs.db"
  else
    LOG_DB_FILE="$DB_DIR/${DB_BASE}_logs.db"
  fi
fi

export MTG_DB_PATH="$DB_FILE"
export MTG_LOG_DB_PATH="$LOG_DB_FILE"

printf 'Installing dependencies...\n'
"$PYTHON_BIN" -m pip install -r "$REQUIREMENTS_FILE" >/dev/null

printf 'Stopping existing Flask server on port %s if present...\n' "$FLASK_PORT"
"$PYTHON_BIN" - "$FLASK_PORT" <<'PY'
import os
import sys
import time

import psutil

port = int(sys.argv[1])
current_pid = os.getpid()
pids = set()

for conn in psutil.net_connections(kind='inet'):
    if conn.status == psutil.CONN_LISTEN and conn.laddr and conn.laddr.port == port and conn.pid:
        pids.add(conn.pid)

for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
    try:
        pid = proc.info['pid']
        if pid == current_pid:
            continue
        name = proc.info.get('name') or ''
        cmdline = proc.info.get('cmdline') or []
        first = os.path.basename(cmdline[0]) if cmdline else ''
        if name == 'flask' or first == 'flask':
            pids.add(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

for pid in sorted(pids):
    if pid == current_pid:
        continue
    try:
        proc = psutil.Process(pid)
        print(f'Terminating process {pid} ({proc.name()})')
        proc.terminate()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

deadline = time.time() + 5
while time.time() < deadline:
    remaining = []
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                remaining.append(proc)
        except psutil.NoSuchProcess:
            pass
    if not remaining:
        break
    time.sleep(0.2)

for pid in sorted(pids):
    try:
        proc = psutil.Process(pid)
        if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
            print(f'Force killing process {pid} ({proc.name()})')
            proc.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
PY

printf 'Setting Flask environment...\n'
export FLASK_APP="app.app:app"

printf 'Initializing database...\n'
"$PYTHON_BIN" -m flask --app app.app db-init

printf 'Creating default admin user...\n'
"$PYTHON_BIN" -m flask --app app.app create-admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASS"

printf 'Starting Flask development server...\n'
nohup "$PYTHON_BIN" -m flask --app app.app run --debug --host="$FLASK_IP" --port="$FLASK_PORT" > "$SCRIPT_DIR/flask-server.log" 2>&1 &
FLASK_PID=$!
printf 'Flask server started with PID %s. Logs: %s\n' "$FLASK_PID" "$SCRIPT_DIR/flask-server.log"

sleep 3

APP_URL="http://${FLASK_IP}:${FLASK_PORT}/"
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$APP_URL" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
  open "$APP_URL" >/dev/null 2>&1 || true
fi

printf 'Application URL: %s\n' "$APP_URL"
