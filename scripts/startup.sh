#!/bin/bash
set -e

echo "Starting PKI-Based 2FA Microservice..."
echo "Timezone: $TZ"
echo "Current time: $(date -u)"

# Start cron daemon in the background
echo "Starting cron daemon..."
service cron start

# Verify cron is running
if pgrep cron > /dev/null; then
    echo "Cron daemon started successfully"
else
    echo "ERROR: Failed to start cron daemon" >&2
    exit 1
fi

# Start the FastAPI application
echo "Starting FastAPI application on port 8080..."
exec uvicorn app:app --host 0.0.0.0 --port 8080 --log-level info
