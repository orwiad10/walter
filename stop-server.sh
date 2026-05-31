#!/usr/bin/env bash
# Bash script to stop the MTG Tournament Swiss App.
# Terminates the Flask server process and reports whether the configured
# SQLite database is still held open by a Python process.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
REQUIREMENTS_FILE="$SCRIPT_DIR/requirements.txt"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Missing config.yaml" >&2
  exit 1
fi

# Ensure PyYAML is available so config.yaml can be parsed, then install the full
# requirements so psutil is available for process discovery.
python - <<'PY'
import subprocess
import sys
try:
    import yaml  # noqa: F401
except ModuleNotFoundError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet', 'PyYAML'])
PY

printf 'Installing dependencies...\n'
python -m pip install -r "$REQUIREMENTS_FILE" >/dev/null

eval "$(python - "$CONFIG_FILE" <<'PY'
import shlex
import sys

import yaml

with open(sys.argv[1], 'r', encoding='utf-8') as f:
    cfg = yaml.safe_load(f) or {}

for key in ('flask_port', 'db_file'):
    value = cfg.get(key, '')
    if value is None:
        value = ''
    print(f'{key.upper()}={shlex.quote(str(value))}')
PY
)"

FLASK_PORT="${FLASK_PORT:-5000}"
DB_FILE="${DB_FILE:-mtg_tournament.db}"
if [[ "$DB_FILE" != /* ]]; then
  DB_PATH="$SCRIPT_DIR/$DB_FILE"
else
  DB_PATH="$DB_FILE"
fi

printf 'Stopping server on port %s\n' "$FLASK_PORT"
python - "$FLASK_PORT" "$DB_PATH" <<'PY'
import os
import sys
import time

import psutil

port = int(sys.argv[1])
db_path = os.path.abspath(sys.argv[2])
current_pid = os.getpid()
pids = set()

for conn in psutil.net_connections(kind='inet'):
    if conn.laddr and conn.laddr.port == port and conn.pid:
        pids.add(conn.pid)

for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'open_files']):
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
        print(f'Terminating Flask process {pid}')
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
            print(f'Force killing Flask process {pid}')
            proc.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

locking_pids = []
for proc in psutil.process_iter(['pid', 'name', 'open_files']):
    try:
        name = proc.info.get('name') or ''
        if 'python' not in name.lower():
            continue
        for open_file in proc.info.get('open_files') or []:
            if os.path.abspath(open_file.path) == db_path:
                locking_pids.append(proc.info['pid'])
                break
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

for pid in locking_pids:
    try:
        proc = psutil.Process(pid)
        print(f'Terminating Python process {pid} using {db_path}')
        proc.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

time.sleep(1)
still_locked = []
for proc in psutil.process_iter(['pid', 'name', 'open_files']):
    try:
        for open_file in proc.info.get('open_files') or []:
            if os.path.abspath(open_file.path) == db_path:
                still_locked.append(proc.info['pid'])
                break
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

if still_locked:
    print(f'Warning: database {db_path} is still in use by PID(s): {", ".join(map(str, still_locked))}', file=sys.stderr)
else:
    print(f'Database {db_path} is quiesced.')
PY
