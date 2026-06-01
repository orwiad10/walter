#!/usr/bin/env bash
# Install the Walter Nginx reverse-proxy configuration on Linux.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_CONFIG="$REPO_DIR/nginx/walter.conf"
DEFAULT_TLS_CONFIG="$REPO_DIR/nginx/walter-tls.conf"
DEFAULT_APP_CONFIG="$REPO_DIR/config.yaml"

CONFIG_FILE="$DEFAULT_CONFIG"
SITE_NAME="walter"
DRY_RUN=0
RELOAD_NGINX=1
DISABLE_DEFAULT_SITE=1
TLS_DOMAIN=""
CERT_DIR=""
ACME_WEBROOT="/var/www/letsencrypt"
APP_CONFIG="$DEFAULT_APP_CONFIG"
FLASK_IP="127.0.0.1"
FLASK_PORT="5000"
GENERATED_CONFIG=""
CONFIG_EXPLICIT=0

usage() {
  cat <<USAGE
Usage: $0 [options]

Copies the Walter Nginx config into the correct Linux Nginx location:
  - /etc/nginx/sites-available + sites-enabled when those directories exist
  - /etc/nginx/conf.d otherwise

Options:
  -c, --config PATH     Source Nginx config to install (default: $DEFAULT_CONFIG)
      --tls-domain NAME  Render and install the TLS 1.3 Let's Encrypt config for NAME
      --cert-dir PATH    Let's Encrypt live cert directory (default: /etc/letsencrypt/live/NAME)
      --acme-webroot PATH
                        Webroot for HTTP-01 challenges (default: $ACME_WEBROOT)
      --app-config PATH Config file to read flask_ip/flask_port from (default: $DEFAULT_APP_CONFIG)
  -n, --site-name NAME  Installed site name (default: $SITE_NAME)
      --dry-run         Print actions without changing files
      --no-reload       Do not validate or reload Nginx after installing
      --keep-default-site
                        Leave the packaged default Nginx site enabled
  -h, --help            Show this help
USAGE
}

log() {
  printf '%s\n' "$*"
}

run_root() {
  if [[ "$DRY_RUN" -eq 1 ]]; then
    printf '[dry-run]'
    printf ' %q' "$@"
    printf '\n'
    return 0
  fi

  if [[ "$(id -u)" -eq 0 ]]; then
    "$@"
  elif command -v sudo >/dev/null 2>&1; then
    sudo "$@"
  else
    log "This script needs root privileges. Re-run as root or install sudo." >&2
    exit 1
  fi
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    -c|--config)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        log "Missing value for $1" >&2
        usage >&2
        exit 1
      fi
      CONFIG_FILE="$2"
      CONFIG_EXPLICIT=1
      shift 2
      ;;
    -n|--site-name)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        log "Missing value for $1" >&2
        usage >&2
        exit 1
      fi
      SITE_NAME="$2"
      shift 2
      ;;
    --tls-domain)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        log "Missing value for $1" >&2
        usage >&2
        exit 1
      fi
      TLS_DOMAIN="$2"
      shift 2
      ;;
    --cert-dir)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        log "Missing value for $1" >&2
        usage >&2
        exit 1
      fi
      CERT_DIR="$2"
      shift 2
      ;;
    --acme-webroot)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        log "Missing value for $1" >&2
        usage >&2
        exit 1
      fi
      ACME_WEBROOT="$2"
      shift 2
      ;;
    --app-config)
      if [[ $# -lt 2 || -z "${2:-}" ]]; then
        log "Missing value for $1" >&2
        usage >&2
        exit 1
      fi
      APP_CONFIG="$2"
      shift 2
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --no-reload)
      RELOAD_NGINX=0
      shift
      ;;
    --keep-default-site)
      DISABLE_DEFAULT_SITE=0
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      log "Unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done


if [[ -n "$TLS_DOMAIN" ]]; then
  if [[ "$CONFIG_EXPLICIT" -eq 0 ]]; then
    CONFIG_FILE="$DEFAULT_TLS_CONFIG"
  fi

  if [[ "$TLS_DOMAIN" == *"/"* || "$TLS_DOMAIN" == *" "* ]]; then
    log "TLS domain must be a DNS name, not a path or value with spaces: $TLS_DOMAIN" >&2
    exit 1
  fi

  CERT_DIR="${CERT_DIR:-/etc/letsencrypt/live/$TLS_DOMAIN}"

  if [[ "$DRY_RUN" -ne 1 ]]; then
    for cert_file in "$CERT_DIR/fullchain.pem" "$CERT_DIR/privkey.pem" "$CERT_DIR/chain.pem"; do
      if [[ ! -f "$cert_file" ]]; then
        log "Missing Let's Encrypt certificate file: $cert_file" >&2
        log "Create certificates on this machine first, for example:" >&2
        log "  certbot certonly --webroot -w $ACME_WEBROOT -d $TLS_DOMAIN" >&2
        exit 1
      fi
    done
  fi
fi

if [[ -z "$CONFIG_FILE" || ! -f "$CONFIG_FILE" ]]; then
  log "Nginx config not found: $CONFIG_FILE" >&2
  exit 1
fi

if [[ -z "$SITE_NAME" || "$SITE_NAME" == */* ]]; then
  log "Site name must be a non-empty filename, not a path: $SITE_NAME" >&2
  exit 1
fi

if [[ ! -d /etc/nginx && "$DRY_RUN" -ne 1 ]]; then
  log "/etc/nginx does not exist. Install Nginx first, then re-run this script." >&2
  exit 1
fi


read_config_value() {
  local key="$1"
  local file="$2"

  awk -v key="$key" '
    $0 ~ "^[[:space:]]*" key "[[:space:]]*:" {
      sub("^[[:space:]]*" key "[[:space:]]*:[[:space:]]*", "")
      sub("[[:space:]]+#.*$", "")
      sub("^[[:space:]]+", "")
      sub("[[:space:]]+$", "")
      if (($0 ~ /^".*"$/) || ($0 ~ /^'"'"'.*'"'"'$/)) {
        print substr($0, 2, length($0) - 2)
      } else {
        print
      }
      exit
    }
  ' "$file"
}

load_app_config() {
  if [[ ! -f "$APP_CONFIG" ]]; then
    log "Application config not found: $APP_CONFIG" >&2
    exit 1
  fi

  local configured_ip configured_port
  configured_ip="$(read_config_value flask_ip "$APP_CONFIG")"
  configured_port="$(read_config_value flask_port "$APP_CONFIG")"

  FLASK_IP="${configured_ip:-$FLASK_IP}"
  FLASK_PORT="${configured_port:-$FLASK_PORT}"

  if [[ -z "$FLASK_IP" || "$FLASK_IP" == *[[:space:]]* || "$FLASK_IP" == *"/"* ]]; then
    log "flask_ip in $APP_CONFIG must be a single IP address or hostname, not: $FLASK_IP" >&2
    exit 1
  fi

  if [[ ! "$FLASK_PORT" =~ ^[0-9]+$ || "$FLASK_PORT" -lt 1 || "$FLASK_PORT" -gt 65535 ]]; then
    log "flask_port in $APP_CONFIG must be a TCP port from 1 to 65535, not: $FLASK_PORT" >&2
    exit 1
  fi
}

escape_sed_replacement() {
  printf '%s' "$1" | sed -e 's/[\/&]/\\&/g'
}

render_config() {
  local escaped_domain escaped_cert_dir escaped_acme_webroot escaped_flask_ip escaped_flask_port
  escaped_domain="$(escape_sed_replacement "$TLS_DOMAIN")"
  escaped_cert_dir="$(escape_sed_replacement "$CERT_DIR")"
  escaped_acme_webroot="$(escape_sed_replacement "$ACME_WEBROOT")"
  escaped_flask_ip="$(escape_sed_replacement "$FLASK_IP")"
  escaped_flask_port="$(escape_sed_replacement "$FLASK_PORT")"

  GENERATED_CONFIG="$(mktemp)"
  sed \
    -e "s/__WALTER_DOMAIN__/$escaped_domain/g" \
    -e "s/__WALTER_CERT_DIR__/$escaped_cert_dir/g" \
    -e "s/__WALTER_ACME_WEBROOT__/$escaped_acme_webroot/g" \
    -e "s/__WALTER_FLASK_IP__/$escaped_flask_ip/g" \
    -e "s/__WALTER_FLASK_PORT__/$escaped_flask_port/g" \
    "$CONFIG_FILE" > "$GENERATED_CONFIG"
  CONFIG_FILE="$GENERATED_CONFIG"
}

cleanup_generated_config() {
  if [[ -n "$GENERATED_CONFIG" && -f "$GENERATED_CONFIG" ]]; then
    rm -f "$GENERATED_CONFIG"
  fi
}
trap cleanup_generated_config EXIT

disable_packaged_default_site() {
  if [[ "$DISABLE_DEFAULT_SITE" -ne 1 ]]; then
    return 0
  fi

  local default_site="/etc/nginx/sites-enabled/default"
  if [[ -e "$default_site" || -L "$default_site" ]]; then
    log "Disabling packaged default site at $default_site so Walter answers port 80"
    if [[ -L "$default_site" ]]; then
      run_root rm -f "$default_site"
    else
      run_root mv -f "$default_site" "/etc/nginx/default.disabled"
    fi
  fi

  local default_conf="/etc/nginx/conf.d/default.conf"
  if [[ -e "$default_conf" || -L "$default_conf" ]]; then
    log "Disabling packaged default config at $default_conf so Walter answers port 80"
    run_root mv -f "$default_conf" "$default_conf.disabled"
  fi
}

load_app_config
render_config

if [[ -n "$TLS_DOMAIN" ]]; then
  log "Ensuring ACME challenge webroot exists at $ACME_WEBROOT"
  run_root mkdir -p "$ACME_WEBROOT/.well-known/acme-challenge"
fi

if [[ -d /etc/nginx/sites-available ]]; then
  TARGET_AVAILABLE="/etc/nginx/sites-available/$SITE_NAME"
  TARGET_ENABLED="/etc/nginx/sites-enabled/$SITE_NAME"

  log "Installing $CONFIG_FILE to $TARGET_AVAILABLE"
  run_root install -m 0644 "$CONFIG_FILE" "$TARGET_AVAILABLE"

  if [[ ! -d /etc/nginx/sites-enabled ]]; then
    log "Creating /etc/nginx/sites-enabled"
    run_root mkdir -p /etc/nginx/sites-enabled
  fi

  log "Enabling site at $TARGET_ENABLED"
  run_root ln -sfn "$TARGET_AVAILABLE" "$TARGET_ENABLED"
else
  TARGET_CONF="/etc/nginx/conf.d/$SITE_NAME.conf"

  if [[ ! -d /etc/nginx/conf.d ]]; then
    log "Creating /etc/nginx/conf.d"
    run_root mkdir -p /etc/nginx/conf.d
  fi

  log "Installing $CONFIG_FILE to $TARGET_CONF"
  run_root install -m 0644 "$CONFIG_FILE" "$TARGET_CONF"
fi

disable_packaged_default_site

if [[ "$RELOAD_NGINX" -eq 1 ]]; then
  log "Validating Nginx configuration"
  run_root nginx -t

  if command -v systemctl >/dev/null 2>&1; then
    log "Reloading Nginx with systemctl"
    run_root systemctl reload nginx || run_root systemctl restart nginx
  else
    log "Reloading Nginx with nginx -s reload"
    run_root nginx -s reload || run_root nginx
  fi
else
  log "Skipping Nginx validation and reload (--no-reload)."
fi

log "Nginx config installation complete."
