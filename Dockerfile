# =============================================================================
# SSH Honeypot - Multi-stage Production Dockerfile
# =============================================================================
# Stage 1: Builder - install dependencies
# Stage 2: Runtime - minimal production image
# =============================================================================

# --- Stage 1: Builder ---
FROM python:3.13-slim AS builder

WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libffi-dev \
        libssl-dev \
        && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies in virtual env
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

COPY pyproject.toml ./
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir --no-build-isolation .

# --- Stage 2: Runtime ---
FROM python:3.13-slim AS runtime

# Labels for container metadata
LABEL maintainer="Not-Just-Pratul <buildwithpratul@gmail.com>"
LABEL description="SSH Honeypot with live SOC dashboard, REST API, and threat intelligence"
LABEL version="1.0.0"

# Create non-root user for security
RUN groupadd -r honeypot && useradd -r -g honeypot -d /app -s /bin/bash honeypot

WORKDIR /app

# Copy virtual env from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application source
COPY src/ ./src/
COPY app.py ./
COPY pyproject.toml ./

# Generate SSH host key
RUN mkdir -p keys && \
    openssl genrsa -out keys/ssh_host_rsa_key 2048 2>/dev/null && \
    chmod 600 keys/ssh_host_rsa_key

# Create logs directory
RUN mkdir -p logs && chown -R honeypot:honeypot /app

# Switch to non-root user
USER honeypot

# Health check - verify the honeypot is listening
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c "import socket; s = socket.socket(); s.settimeout(5); s.connect(('127.0.0.1', ${HONEYPOT_PORT:-2222})); s.close()" || exit 1

# Expose ports
# Honeypot: 2222, Dashboard: 8501, REST API: 8502
EXPOSE 2222 8501 8502

# Default environment variables
ENV HONEYPOT_HOST=0.0.0.0 \
    HONEYPOT_PORT=2222 \
    DASHBOARD_HOST=0.0.0.0 \
    DASHBOARD_PORT=8501 \
    API_HOST=0.0.0.0 \
    API_PORT=8502 \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Run the application
CMD ["python", "-m", "ssh_honeypot", "all"]
