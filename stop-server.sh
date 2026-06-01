#!/usr/bin/env bash
# Bash script to stop the MTG Tournament Swiss App.
# Terminates the Flask server process and reports whether the configured
# SQLite database is still held open by a Python process.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
REQUIREMENTS_FILE="$SCRIPT_DIR/requirements.txt"
VENV_DIR="$SCRIPT_DIR/.venv"

PYTHON_BIN=""

detect_python() {
  local candidate
  for candidate in "$VENV_DIR/bin/python" python3 python; do
    if [[ -x "$candidate" || "$candidate" != */* ]] && command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if sys.version_info.major >= 3 else 1)' >/dev/null 2>&1; then
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
    echo "Installing Python support packages requires root privileges. Re-run as root or install python3, python3-pip, and python3-venv manually." >&2
    exit 1
  fi
}

install_python() {
  echo "Python 3 was not found. Attempting to install python3 and pip with the system package manager..." >&2

  if command -v apt-get >/dev/null 2>&1; then
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get update
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y python3 python3-pip python3-venv
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
    echo "Python 3 is required, and no supported package manager was found. Install python3, python3-pip, and python3-venv manually." >&2
    exit 1
  fi
}

install_python_package_support() {
  echo "Python packaging support was not found. Attempting to install pip and venv support with the system package manager..." >&2

  if command -v apt-get >/dev/null 2>&1; then
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get update
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y python3-pip python3-venv
  elif command -v dnf >/dev/null 2>&1; then
    run_as_root dnf install -y python3-pip
  elif command -v yum >/dev/null 2>&1; then
    run_as_root yum install -y python3-pip
  elif command -v zypper >/dev/null 2>&1; then
    run_as_root zypper --non-interactive install python3-pip
  elif command -v pacman >/dev/null 2>&1; then
    run_as_root pacman -Sy --noconfirm python-pip
  elif command -v apk >/dev/null 2>&1; then
    run_as_root apk add --no-cache py3-pip
  elif command -v brew >/dev/null 2>&1; then
    brew install python
  else
    echo "pip/venv support is required, and no supported package manager was found. Install python3-pip and python3-venv manually." >&2
    exit 1
  fi
}

ensure_venv() {
  if [[ -x "$VENV_DIR/bin/python" ]]; then
    PYTHON_BIN="$VENV_DIR/bin/python"
    return 0
  fi

  if ! "$PYTHON_BIN" -m venv "$VENV_DIR"; then
    rm -rf "$VENV_DIR"
    install_python_package_support
    "$PYTHON_BIN" -m venv "$VENV_DIR"
  fi

  PYTHON_BIN="$VENV_DIR/bin/python"
}

ensure_pip() {
  if "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    return 0
  fi

  if "$PYTHON_BIN" -m ensurepip --upgrade >/dev/null 2>&1 && "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    return 0
  fi

  install_python_package_support
  "$PYTHON_BIN" -m ensurepip --upgrade >/dev/null 2>&1 || true
  if ! "$PYTHON_BIN" -m pip --version >/dev/null 2>&1; then
    echo "pip is still unavailable for $PYTHON_BIN after installing package support." >&2
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

# Ensure PyYAML is available so config.yaml can be parsed, then install the full
# requirements so psutil is available for process discovery.
ensure_venv
ensure_pip

"$PYTHON_BIN" - <<'PY'
import subprocess
import sys
try:
    import yaml  # noqa: F401
except ModuleNotFoundError:
    subprocess.check_call([sys.executable, '-m', 'pip', 'install', '--quiet', 'PyYAML'])
PY

printf 'Installing dependencies...\n'
"$PYTHON_BIN" -m pip install -r "$REQUIREMENTS_FILE" >/dev/null

eval "$("$PYTHON_BIN" - "$CONFIG_FILE" <<'PY'
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
"$PYTHON_BIN" - "$FLASK_PORT" "$DB_PATH" <<'PY'
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
