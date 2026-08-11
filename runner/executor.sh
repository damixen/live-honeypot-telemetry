#!/usr/bin/env bash

echo "$(date -Is) executor started" >> /tmp/executor.log

set -euo pipefail

BASE_DIR="/home/zach/exporter"
PYTHON="$BASE_DIR/.venv/bin/python"
EXPORTER="$BASE_DIR/exporter.py"
OUTPUT_FILE="${OUTPUT_FILE:-$BASE_DIR/telemetry.json}"
LOG_FILE="$BASE_DIR/export.log"

case "$TIME_MODE" in
  daily)
    REPORT_TYPE="daily"
    LOG_FILE="$BASE_DIR/export_daily.log"
    ;;
  last24h)
    REPORT_TYPE="latest"
    ;;
  *)
    echo "Invalid TIME_MODE: $TIME_MODE"
    exit 1
    ;;
esac

exec >>"$LOG_FILE" 2>&1

echo "===== $(date -Is) ====="
echo "Running as $(whoami)"
echo "PATH=$PATH"


cd "$BASE_DIR"

source "$BASE_DIR"/.env

echo "Running exporter..."

if "$PYTHON" "$EXPORTER" "$HOST_ID"; then
    echo "Exporter completed successfully."
else
    echo "WARNING: exporter failed. Will attempt to push existing snapshot."
fi

if [[ ! -f "$OUTPUT_FILE" ]]; then
    echo "ERROR: $OUTPUT_FILE does not exist. Nothing to push."
    exit 1
fi

echo "Pushing snapshot..."

PAYLOAD_FILE="/tmp/telemetry_payload.json"

jq -n \
  --arg report_type "$REPORT_TYPE" \
  --slurpfile data "$OUTPUT_FILE" \
  '{data: $data[0], report_type: $report_type}' \
  > "$PAYLOAD_FILE"


curl -i \
    --fail \
    --silent \
    --show-error \
    -X POST \
    -H "Content-Type: application/json" \
    -H  "X-Require-Whisk-Auth: $DO_FUNCTION_KEY" \
    --data @"$PAYLOAD_FILE" \
    "$DO_FUNCTION_URL"

echo "Push completed successfully."

trap 'echo "Script exited with code $? at $(date -Is)"' EXIT

