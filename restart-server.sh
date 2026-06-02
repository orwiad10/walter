#!/usr/bin/env bash
# Bash script to restart the MTG Tournament Swiss App.
# Stops the running server, then starts it again so config.yaml is reloaded.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STOP_SCRIPT="$SCRIPT_DIR/stop-server.sh"
START_SCRIPT="$SCRIPT_DIR/start-server.sh"
CONFIG_FILE="$SCRIPT_DIR/config.yaml"

if [[ ! -f "$CONFIG_FILE" ]]; then
  echo "Missing config.yaml" >&2
  exit 1
fi

if [[ ! -x "$STOP_SCRIPT" ]]; then
  echo "Missing or non-executable stop-server.sh" >&2
  exit 1
fi

if [[ ! -x "$START_SCRIPT" ]]; then
  echo "Missing or non-executable start-server.sh" >&2
  exit 1
fi

printf 'Restarting server to reload %s...\n' "$CONFIG_FILE"
"$STOP_SCRIPT"
"$START_SCRIPT"
printf 'Server restart complete; config.yaml has been reloaded.\n'
