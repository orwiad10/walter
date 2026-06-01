#!/usr/bin/env bash
# Install the Walter Nginx reverse-proxy configuration on Linux.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
DEFAULT_CONFIG="$REPO_DIR/nginx/walter.conf"

CONFIG_FILE="$DEFAULT_CONFIG"
SITE_NAME="walter"
DRY_RUN=0
RELOAD_NGINX=1

usage() {
  cat <<USAGE
Usage: $0 [options]

Copies the Walter Nginx config into the correct Linux Nginx location:
  - /etc/nginx/sites-available + sites-enabled when those directories exist
  - /etc/nginx/conf.d otherwise

Options:
  -c, --config PATH     Source Nginx config to install (default: $DEFAULT_CONFIG)
  -n, --site-name NAME  Installed site name (default: $SITE_NAME)
      --dry-run         Print actions without changing files
      --no-reload       Do not validate or reload Nginx after installing
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
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --no-reload)
      RELOAD_NGINX=0
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

if [[ "$RELOAD_NGINX" -eq 1 ]]; then
  log "Validating Nginx configuration"
  run_root nginx -t

  if command -v systemctl >/dev/null 2>&1; then
    log "Reloading Nginx with systemctl"
    run_root systemctl reload nginx
  else
    log "Reloading Nginx with nginx -s reload"
    run_root nginx -s reload
  fi
else
  log "Skipping Nginx validation and reload (--no-reload)."
fi

log "Nginx config installation complete."
