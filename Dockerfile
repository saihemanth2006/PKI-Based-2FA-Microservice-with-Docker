# ============================================================================
# Stage 1: Builder
# ============================================================================
FROM python:3.11-slim AS builder

# Set working directory
WORKDIR /app

# Copy dependency file first (optimize for caching)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt


# ============================================================================
# Stage 2: Runtime
# ============================================================================
FROM python:3.11-slim

# Set timezone to UTC (critical!)
ENV TZ=UTC
ENV PYTHONUNBUFFERED=1
ENV SEED_FILE_PATH=/data/seed.txt
ENV PRIVATE_KEY_PATH=/app/student_private.pem

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        cron \
        tzdata \
        ca-certificates \
        procps && \
    # Configure timezone
    ln -snf /usr/share/zoneinfo/UTC /etc/localtime && \
    echo "UTC" > /etc/timezone && \
    # Clean up
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Copy Python dependencies from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY app.py .
COPY crypto.py .
COPY totp.py .
COPY student_private.pem .

# Copy scripts directory
COPY scripts/ ./scripts/

# Setup cron job
COPY scripts/totp_cron /etc/cron.d/totp_cron
RUN chmod 0644 /etc/cron.d/totp_cron && \
    crontab /etc/cron.d/totp_cron && \
    touch /var/log/cron.log

# Make startup script executable
RUN chmod +x ./scripts/startup.sh

# Create volume mount points
RUN mkdir -p /data /cron && \
    chmod 755 /data /cron

# Expose API port
EXPOSE 8080

# Start cron and application
CMD ["./scripts/startup.sh"]
