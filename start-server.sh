#!/usr/bin/env bash
# Bash script to set up and run the MTG Tournament Swiss App.
# Installs dependencies, initializes the database, creates an admin user,
# and starts the app with Waitress.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"
REQUIREMENTS_FILE="$SCRIPT_DIR/requirements.txt"
VENV_DIR="$SCRIPT_DIR/.venv"
NGINX_INSTALL_SCRIPT="$SCRIPT_DIR/scripts/install_nginx_config.sh"

PYTHON_BIN=""

detect_python() {
	local candidate

	for candidate in python3.12 python3.11 python3.10 python3; do
		if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(0 if (3, 10) <= sys.version_info[:2] <= (3, 12) else 1)' >/dev/null 2>&1; then
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


install_nginx() {
  if [[ "${OSTYPE:-}" != linux* ]]; then
    return 0
  fi

  if command -v nginx >/dev/null 2>&1; then
    return 0
  fi

  echo "Nginx was not found. Attempting to install nginx with the system package manager..." >&2

  if command -v apt-get >/dev/null 2>&1; then
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get update
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y nginx
  elif command -v dnf >/dev/null 2>&1; then
    run_as_root dnf install -y nginx
  elif command -v yum >/dev/null 2>&1; then
    run_as_root yum install -y nginx
  elif command -v zypper >/dev/null 2>&1; then
    run_as_root zypper --non-interactive install nginx
  elif command -v pacman >/dev/null 2>&1; then
    run_as_root pacman -Sy --noconfirm nginx
  elif command -v apk >/dev/null 2>&1; then
    run_as_root apk add --no-cache nginx
  else
    echo "Nginx is required on Linux, and no supported package manager was found. Install nginx manually." >&2
    exit 1
  fi
}
install_certbot() {
  if [[ "${OSTYPE:-}" != linux* ]]; then
    return 0
  fi

  if command -v certbot >/dev/null 2>&1 && command -v openssl >/dev/null 2>&1; then
    return 0
  fi

  echo "Certbot/OpenSSL support was not found. Attempting to install it with the system package manager..." >&2

  if command -v apt-get >/dev/null 2>&1; then
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get update
    run_as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y certbot openssl
  elif command -v dnf >/dev/null 2>&1; then
    run_as_root dnf install -y certbot openssl
  elif command -v yum >/dev/null 2>&1; then
    run_as_root yum install -y certbot openssl
  elif command -v zypper >/dev/null 2>&1; then
    run_as_root zypper --non-interactive install certbot openssl
  elif command -v pacman >/dev/null 2>&1; then
    run_as_root pacman -Sy --noconfirm certbot openssl
  elif command -v apk >/dev/null 2>&1; then
    run_as_root apk add --no-cache certbot openssl
  else
    echo "Certbot and OpenSSL are required for Let's Encrypt certificates, and no supported package manager was found. Install certbot and openssl manually." >&2
    exit 1
  fi
}

ensure_nginx_running() {
  if [[ "${OSTYPE:-}" != linux* ]]; then
    return 0
  fi

  if command -v systemctl >/dev/null 2>&1; then
    run_as_root systemctl start nginx || true
  else
    run_as_root nginx || true
  fi
}

cert_file_exists() {
  local cert_file="$1"

  if [[ -f "$cert_file" ]]; then
    return 0
  fi

  if [[ "$(id -u)" -eq 0 ]]; then
    return 1
  fi

  if command -v sudo >/dev/null 2>&1; then
    sudo test -f "$cert_file"
    return $?
  fi

  return 1
}

cert_expires_within() {
  local cert_file="$1"
  local days="$2"
  local seconds=$((days * 24 * 60 * 60))

  if ! cert_file_exists "$cert_file"; then
    return 0
  fi

  if openssl x509 -checkend "$seconds" -noout -in "$cert_file" >/dev/null 2>&1; then
    return 1
  fi

  ! run_as_root openssl x509 -checkend "$seconds" -noout -in "$cert_file" >/dev/null 2>&1
}

is_truthy() {
  local value="${1,,}"
  case "$value" in
    1|true|yes|y|on)
      return 0
      ;;
    *)
      return 1
      ;;
  esac
}

validate_letsencrypt_settings() {
  local domain_lower email_lower email_domain
  domain_lower="${TLS_DOMAIN,,}"

  case "$domain_lower" in
    example.com|*.example.com|example.net|*.example.net|example.org|*.example.org|localhost|*.localhost|*.test|*.invalid)
      echo "tls_domain is set to a reserved/example name ($TLS_DOMAIN). Set tls_domain in config.yaml to your real public DNS name before requesting a Let's Encrypt certificate." >&2
      exit 1
      ;;
  esac

  if [[ -n "${LETSENCRYPT_EMAIL:-}" ]]; then
    email_lower="${LETSENCRYPT_EMAIL,,}"
    email_domain="${email_lower##*@}"
    if [[ "$email_lower" != *@* || -z "$email_domain" || "$email_domain" == "$email_lower" ]]; then
      echo "letsencrypt_email must be a valid email address, not: $LETSENCRYPT_EMAIL" >&2
      exit 1
    fi

    case "$email_domain" in
      example.com|*.example.com|example.net|*.example.net|example.org|*.example.org|localhost|*.localhost|*.test|*.invalid)
        echo "letsencrypt_email uses a reserved/example domain ($LETSENCRYPT_EMAIL). Set letsencrypt_email in config.yaml to a real email address, or leave it blank to request without email." >&2
        exit 1
        ;;
    esac
  fi
}

install_http_nginx_config() {
  if [[ "${OSTYPE:-}" != linux* ]]; then
    return 0
  fi

  echo "No tls_domain configured; installing HTTP Nginx config for LAN access."
  "$NGINX_INSTALL_SCRIPT" --acme-webroot "${ACME_WEBROOT:-/var/www/letsencrypt}" --app-config "$CONFIG_FILE"
  ensure_nginx_running
}


trim_whitespace() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

validate_tls_additional_domains() {
  local raw extra

  if [[ -z "${TLS_ADDITIONAL_DOMAINS:-}" ]]; then
    return 0
  fi

  IFS=',' read -ra raw <<< "$TLS_ADDITIONAL_DOMAINS"
  for extra in "${raw[@]}"; do
    extra="$(trim_whitespace "$extra")"
    [[ -z "$extra" ]] && continue
    if [[ "$extra" == *"/"* || "$extra" == *[[:space:]]* ]]; then
      echo "tls_additional_domains entries must be DNS names, not paths or values with spaces: $extra" >&2
      exit 1
    fi
  done
}

append_tls_additional_domain_args() {
  local -n target_args=$1
  local raw extra

  if [[ -z "${TLS_ADDITIONAL_DOMAINS:-}" ]]; then
    return 0
  fi

  IFS=',' read -ra raw <<< "$TLS_ADDITIONAL_DOMAINS"
  for extra in "${raw[@]}"; do
    extra="$(trim_whitespace "$extra")"
    [[ -z "$extra" ]] && continue
    target_args+=(-d "$extra")
  done
}

ensure_letsencrypt_certificate() {
  if [[ "${OSTYPE:-}" != linux* ]]; then
    return 0
  fi

  if [[ -z "${TLS_DOMAIN:-}" ]]; then
    install_http_nginx_config
    return 0
  fi

  if [[ "$TLS_DOMAIN" == *"/"* || "$TLS_DOMAIN" == *" "* ]]; then
    echo "tls_domain must be a DNS name, not a path or value with spaces: $TLS_DOMAIN" >&2
    exit 1
  fi

  validate_letsencrypt_settings
  validate_tls_additional_domains
  install_certbot

  local cert_dir="${TLS_CERT_DIR:-/etc/letsencrypt/live/$TLS_DOMAIN}"
  local acme_webroot="${ACME_WEBROOT:-/var/www/letsencrypt}"
  local renewal_days="${LETSENCRYPT_RENEWAL_DAYS:-30}"
  local dry_run=0
  local fullchain="$cert_dir/fullchain.pem"
  local certbot_args=(certonly --webroot -w "$acme_webroot" -d "$TLS_DOMAIN" --non-interactive --agree-tos --keep-until-expiring)
  append_tls_additional_domain_args certbot_args

  if is_truthy "${LETSENCRYPT_DRY_RUN:-false}"; then
    dry_run=1
    certbot_args+=(--dry-run)
  fi

  if [[ -n "${LETSENCRYPT_EMAIL:-}" ]]; then
    certbot_args+=(--email "$LETSENCRYPT_EMAIL" --no-eff-email)
  else
    echo "No letsencrypt_email configured; requesting the certificate without an email address." >&2
    certbot_args+=(--register-unsafely-without-email)
  fi

  if [[ -n "${LETSENCRYPT_SERVER:-}" ]]; then
    certbot_args+=(--server "$LETSENCRYPT_SERVER")
  fi

  if [[ "$dry_run" -eq 1 ]] || cert_expires_within "$fullchain" "$renewal_days"; then
    if [[ "$dry_run" -eq 1 ]]; then
      echo "Running Let's Encrypt dry run for $TLS_DOMAIN; no certificate files will be created or replaced."
    elif cert_file_exists "$fullchain"; then
      echo "Let's Encrypt certificate for $TLS_DOMAIN expires within $renewal_days days; requesting a replacement."
      certbot_args+=(--force-renewal)
    else
      echo "No Let's Encrypt certificate found for $TLS_DOMAIN; requesting one."
    fi

    echo "Installing HTTP Nginx config so Let's Encrypt can validate $TLS_DOMAIN..."
    run_as_root mkdir -p "$acme_webroot/.well-known/acme-challenge"
    "$NGINX_INSTALL_SCRIPT" --acme-webroot "$acme_webroot" --app-config "$CONFIG_FILE"
    ensure_nginx_running

    run_as_root certbot "${certbot_args[@]}"
  else
    echo "Let's Encrypt certificate for $TLS_DOMAIN is present and valid for more than $renewal_days days."
  fi

  if [[ "$dry_run" -eq 1 ]]; then
    echo "Skipping TLS Nginx config install because letsencrypt_dry_run does not create or renew certificate files."
    return 0
  fi

  echo "Installing TLS Nginx config for $TLS_DOMAIN..."
  local nginx_tls_args=(--tls-domain "$TLS_DOMAIN" --cert-dir "$cert_dir" --acme-webroot "$acme_webroot" --app-config "$CONFIG_FILE")
  if [[ -n "${TLS_ADDITIONAL_DOMAINS:-}" ]]; then
    nginx_tls_args+=(--tls-additional-domains "$TLS_ADDITIONAL_DOMAINS")
  fi
  "$NGINX_INSTALL_SCRIPT" "${nginx_tls_args[@]}"
  ensure_nginx_running
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

venv_python_supported() {
  [[ -x "$VENV_DIR/bin/python" ]] || return 1
  "$VENV_DIR/bin/python" -c 'import sys; raise SystemExit(0 if (3, 10) <= sys.version_info[:2] <= (3, 12) else 1)' >/dev/null 2>&1
}

ensure_venv() {
  if [[ -x "$VENV_DIR/bin/python" ]]; then
    if venv_python_supported; then
      PYTHON_BIN="$VENV_DIR/bin/python"
      return 0
    fi

    echo "Existing virtual environment uses an unsupported Python version; recreating it with $PYTHON_BIN." >&2
    rm -rf "$VENV_DIR"
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

install_nginx

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

ensure_venv
ensure_pip

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
    'tls_domain',
    'tls_cert_dir',
    'tls_additional_domains',
    'letsencrypt_email',
    'letsencrypt_renewal_days',
    'letsencrypt_dry_run',
    'letsencrypt_server',
    'acme_webroot',
    'mailgun_api_key',
    'mailgun_domain',
    'mailgun_from_email',
    'registration_pin_ttl_minutes',
    'account_creation_invite_only',
    'account_lockout_attempts',
    'ip_blacklist_attempts',
    'password_reset_ttl_minutes',
    'bot_install_enabled',
    'bot_install_path',
    'bot_install_editable',
    'bot_install_extras',
    'bot_runtime_enabled',
    'bot_runtime_module',
    'bot_runtime_script',
    'bot_runtime_args',
    'bot_runtime_log_file',
    'bot_runtime_error_log_file',
    'bot_api_base_url',
    'bot_api_key',
    'bot_poll_tournament_id',
    'bot_poll_interval_seconds',
    'bot_token',
    'bot_appid',
    'bot_pubkey',
    'bot_client_id',
    'bot_secret_key',
    'bot_permissions_int',
    'bot_channel_id',
    'bot_announce_ready',
    'bot_sync_guild_commands',
    'bot_clear_guild_commands',
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
FLASK_IP="${FLASK_IP:-0.0.0.0}"
FLASK_PORT="${FLASK_PORT:-5000}"
TLS_DOMAIN="${TLS_DOMAIN:-}"
TLS_CERT_DIR="${TLS_CERT_DIR:-}"
LETSENCRYPT_EMAIL="${LETSENCRYPT_EMAIL:-}"
LETSENCRYPT_RENEWAL_DAYS="${LETSENCRYPT_RENEWAL_DAYS:-30}"
LETSENCRYPT_DRY_RUN="${LETSENCRYPT_DRY_RUN:-false}"
LETSENCRYPT_SERVER="${LETSENCRYPT_SERVER:-}"
ACME_WEBROOT="${ACME_WEBROOT:-/var/www/letsencrypt}"
MAILGUN_API_KEY="${MAILGUN_API_KEY:-}"
MAILGUN_DOMAIN="${MAILGUN_DOMAIN:-}"
MAILGUN_FROM_EMAIL="${MAILGUN_FROM_EMAIL:-}"
REGISTRATION_PIN_TTL_MINUTES="${REGISTRATION_PIN_TTL_MINUTES:-15}"
ACCOUNT_CREATION_INVITE_ONLY="${ACCOUNT_CREATION_INVITE_ONLY:-false}"
ACCOUNT_LOCKOUT_ATTEMPTS="${ACCOUNT_LOCKOUT_ATTEMPTS:-3}"
IP_BLACKLIST_ATTEMPTS="${IP_BLACKLIST_ATTEMPTS:-10}"
PASSWORD_RESET_TTL_MINUTES="${PASSWORD_RESET_TTL_MINUTES:-60}"
BOT_INSTALL_ENABLED="${BOT_INSTALL_ENABLED:-false}"
BOT_INSTALL_PATH="${BOT_INSTALL_PATH:-walter-bot}"
BOT_INSTALL_EDITABLE="${BOT_INSTALL_EDITABLE:-true}"
BOT_INSTALL_EXTRAS="${BOT_INSTALL_EXTRAS:-}"
BOT_RUNTIME_ENABLED="${BOT_RUNTIME_ENABLED:-auto}"
BOT_RUNTIME_MODULE="${BOT_RUNTIME_MODULE:-}"
BOT_RUNTIME_SCRIPT="${BOT_RUNTIME_SCRIPT:-}"
BOT_RUNTIME_ARGS="${BOT_RUNTIME_ARGS:-}"
BOT_RUNTIME_LOG_FILE="${BOT_RUNTIME_LOG_FILE:-walter-bot.log}"
BOT_RUNTIME_ERROR_LOG_FILE="${BOT_RUNTIME_ERROR_LOG_FILE:-walter-bot.err.log}"
BOT_API_BASE_URL="${BOT_API_BASE_URL:-http://127.0.0.1:$FLASK_PORT}"
BOT_API_KEY="${BOT_API_KEY:-}"
BOT_POLL_TOURNAMENT_ID="${BOT_POLL_TOURNAMENT_ID:-}"
BOT_POLL_INTERVAL_SECONDS="${BOT_POLL_INTERVAL_SECONDS:-30}"
BOT_TOKEN="${BOT_TOKEN:-}"
BOT_APPID="${BOT_APPID:-}"
BOT_PUBKEY="${BOT_PUBKEY:-}"
BOT_CLIENT_ID="${BOT_CLIENT_ID:-}"
BOT_SECRET_KEY="${BOT_SECRET_KEY:-}"
BOT_PERMISSIONS_INT="${BOT_PERMISSIONS_INT:-}"
BOT_CHANNEL_ID="${BOT_CHANNEL_ID:-}"
BOT_ANNOUNCE_READY="${BOT_ANNOUNCE_READY:-false}"
BOT_SYNC_GUILD_COMMANDS="${BOT_SYNC_GUILD_COMMANDS:-false}"
BOT_CLEAR_GUILD_COMMANDS="${BOT_CLEAR_GUILD_COMMANDS:-true}"

cd "$SCRIPT_DIR"

export PYTEST_DISABLE_PLUGIN_AUTOLOAD="1"
export PASSWORD_SEED
export FLASK_SECRET
export FLASK_RUN_HOST="$FLASK_IP"
export FLASK_RUN_PORT="$FLASK_PORT"
export MAILGUN_API_KEY
export MAILGUN_DOMAIN
export MAILGUN_FROM_EMAIL
export REGISTRATION_PIN_TTL_MINUTES
export ACCOUNT_CREATION_INVITE_ONLY
export ACCOUNT_LOCKOUT_ATTEMPTS
export IP_BLACKLIST_ATTEMPTS
export PASSWORD_RESET_TTL_MINUTES
export BOT_API_BASE_URL
export BOT_API_KEY
export BOT_POLL_TOURNAMENT_ID
export BOT_POLL_INTERVAL_SECONDS
export BOT_TOKEN
export BOT_APPID
export BOT_PUBKEY
export BOT_CLIENT_ID
export BOT_SECRET_KEY
export BOT_PERMISSIONS_INT
export BOT_CHANNEL_ID
export BOT_ANNOUNCE_READY
export BOT_SYNC_GUILD_COMMANDS
export BOT_CLEAR_GUILD_COMMANDS

ensure_letsencrypt_certificate

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

# The vendored discord.py package is imported directly by discord_bot.py, so
# make sure its third-party runtime dependency is present even if an existing
# virtualenv was created before aiohttp was added to requirements.txt.
if ! "$PYTHON_BIN" - <<'PY' >/dev/null 2>&1
import aiohttp  # noqa: F401
PY
then
  printf 'Installing missing Discord bot dependency aiohttp...\n'
  "$PYTHON_BIN" -m pip install 'aiohttp>=3.7.4,<4' >/dev/null
fi

if is_truthy "$BOT_INSTALL_ENABLED"; then
  bot_install_target="$BOT_INSTALL_PATH"
  if [[ -n "$BOT_INSTALL_EXTRAS" ]]; then
    bot_install_target="${bot_install_target}[${BOT_INSTALL_EXTRAS}]"
  fi
  printf 'Installing Walter bot package from %s...\n' "$BOT_INSTALL_PATH"
  if is_truthy "$BOT_INSTALL_EDITABLE"; then
    "$PYTHON_BIN" -m pip install -e "$bot_install_target" >/dev/null
  else
    "$PYTHON_BIN" -m pip install "$bot_install_target" >/dev/null
  fi
fi

printf 'Stopping existing Flask/Waitress server on port %s if present...\n' "$FLASK_PORT"
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
        command_text = ' '.join(cmdline).lower()
        if name == 'flask' or first == 'flask' or first == 'waitress-serve' or 'waitress' in command_text:
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

stop_existing_bot_runtime() {
  [[ -n "$BOT_RUNTIME_MODULE" || -n "$BOT_RUNTIME_SCRIPT" ]] || return 0

  printf 'Stopping existing Walter bot runtime if present...\n'
  "$PYTHON_BIN" - "$BOT_RUNTIME_MODULE" "$BOT_RUNTIME_SCRIPT" <<'PY'
import os
import sys
import time

import psutil

bot_module = sys.argv[1]
bot_script = sys.argv[2]
current_pid = os.getpid()
script_basename = os.path.basename(bot_script) if bot_script else ''
pids = set()

for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
    try:
        pid = proc.info['pid']
        if pid == current_pid:
            continue
        cmdline = proc.info.get('cmdline') or []
        if not cmdline:
            continue
        command_text = ' '.join(cmdline)
        matches_module = bool(bot_module) and (
            f'-m {bot_module}' in command_text or bot_module in cmdline
        )
        matches_script = bool(bot_script) and (
            bot_script in cmdline or script_basename in [os.path.basename(arg) for arg in cmdline]
        )
        if matches_module or matches_script:
            pids.add(pid)
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        continue

for pid in sorted(pids):
    try:
        proc = psutil.Process(pid)
        print(f'Terminating Walter bot process {pid} ({proc.name()})')
        proc.terminate()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass

deadline = time.time() + 5
while time.time() < deadline:
    alive = []
    for pid in pids:
        try:
            proc = psutil.Process(pid)
            if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
                alive.append(proc)
        except psutil.NoSuchProcess:
            pass
    if not alive:
        break
    time.sleep(0.2)

for pid in sorted(pids):
    try:
        proc = psutil.Process(pid)
        if proc.is_running() and proc.status() != psutil.STATUS_ZOMBIE:
            print(f'Force killing Walter bot process {pid} ({proc.name()})')
            proc.kill()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
PY
}

should_start_bot_runtime() {
  local mode="${BOT_RUNTIME_ENABLED,,}"

  case "$mode" in
    auto|"")
      [[ -n "$BOT_RUNTIME_MODULE" || -n "$BOT_RUNTIME_SCRIPT" ]]
      ;;
    *)
      is_truthy "$BOT_RUNTIME_ENABLED"
      ;;
  esac
}

stop_existing_bot_runtime

printf 'Initializing database...\n'
"$PYTHON_BIN" -m flask --app app.app db-init

printf 'Creating default admin user...\n'
"$PYTHON_BIN" -m flask --app app.app create-admin --email "$ADMIN_EMAIL" --password "$ADMIN_PASS"

printf 'Starting Waitress server...\n'
nohup "$PYTHON_BIN" -m waitress --host="$FLASK_IP" --port="$FLASK_PORT" app.app:app > "$SCRIPT_DIR/waitress-server.log" 2>&1 &
WAITRESS_PID=$!
printf 'Waitress server started with PID %s. Logs: %s\n' "$WAITRESS_PID" "$SCRIPT_DIR/waitress-server.log"

if should_start_bot_runtime; then
  if [[ -n "$BOT_RUNTIME_MODULE" && -n "$BOT_RUNTIME_SCRIPT" ]]; then
    echo "Only one of bot_runtime_module or bot_runtime_script may be configured." >&2
    exit 1
  fi
  if [[ -z "$BOT_RUNTIME_MODULE" && -z "$BOT_RUNTIME_SCRIPT" ]]; then
    echo "bot_runtime_enabled is true, but neither bot_runtime_module nor bot_runtime_script is configured." >&2
    exit 1
  fi
  read -r -a bot_args <<< "$BOT_RUNTIME_ARGS"
  if [[ -n "$BOT_RUNTIME_MODULE" ]]; then
    nohup "$PYTHON_BIN" -m "$BOT_RUNTIME_MODULE" "${bot_args[@]}" > "$SCRIPT_DIR/$BOT_RUNTIME_LOG_FILE" 2> "$SCRIPT_DIR/$BOT_RUNTIME_ERROR_LOG_FILE" &
  else
    nohup "$PYTHON_BIN" "$BOT_RUNTIME_SCRIPT" "${bot_args[@]}" > "$SCRIPT_DIR/$BOT_RUNTIME_LOG_FILE" 2> "$SCRIPT_DIR/$BOT_RUNTIME_ERROR_LOG_FILE" &
  fi
  BOT_PID=$!
  printf 'Walter bot started with PID %s. Logs: %s; errors: %s\n' "$BOT_PID" "$SCRIPT_DIR/$BOT_RUNTIME_LOG_FILE" "$SCRIPT_DIR/$BOT_RUNTIME_ERROR_LOG_FILE"
fi

sleep 3

display_host_for_url() {
  local host="$1"

  # 0.0.0.0 and :: are bind addresses, not browsable destinations. When the
  # app listens on every interface, show the primary address this machine uses
  # for outbound LAN/Internet traffic instead.
  if [[ "$host" == "0.0.0.0" || "$host" == "::" || "$host" == "[::]" || -z "$host" ]]; then
    if command -v ip >/dev/null 2>&1; then
      ip route get 1.1.1.1 2>/dev/null | awk '{for (i = 1; i <= NF; i++) if ($i == "src") {print $(i + 1); exit}}'
      return
    fi
    if command -v hostname >/dev/null 2>&1; then
      hostname -I 2>/dev/null | awk '{print $1}'
      return
    fi
    printf '127.0.0.1\n'
    return
  fi

  printf '%s\n' "$host"
}

APP_HOST="$(display_host_for_url "$FLASK_IP")"
APP_HOST="${APP_HOST:-127.0.0.1}"
APP_URL="http://${APP_HOST}:${FLASK_PORT}/"
if command -v xdg-open >/dev/null 2>&1; then
  xdg-open "$APP_URL" >/dev/null 2>&1 || true
elif command -v open >/dev/null 2>&1; then
  open "$APP_URL" >/dev/null 2>&1 || true
fi

printf 'Application URL: %s\n' "$APP_URL"
