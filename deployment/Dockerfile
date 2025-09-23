# Multi-stage Dockerfile for AI-SOAR Cybersecurity Platform

# Stage 1: Base Python environment
FROM python:3.11-slim AS base

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PYTHONPATH=/app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    gcc \
    g++ \
    build-essential \
    libssl-dev \
    libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# Create app directory and non-root user
WORKDIR /app
RUN groupadd -r aisoar && useradd -r -g aisoar -d /app -s /bin/bash aisoar
RUN chown -R aisoar:aisoar /app

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: MCP Servers
FROM base AS mcp-servers

# Copy source code
COPY --chown=aisoar:aisoar src/ ./src/
COPY --chown=aisoar:aisoar xdr_poller.py ./
COPY --chown=aisoar:aisoar deployment/start_servers.py ./

# Create directories for logs and data
RUN mkdir -p /app/logs /app/data /app/config
RUN chown -R aisoar:aisoar /app/logs /app/data /app/config

# Copy configuration
COPY --chown=aisoar:aisoar config/ ./config/

# Switch to non-root user
USER aisoar

# Expose ports for all MCP servers
EXPOSE 8001 8002 8003 8004 8005

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8001/health || exit 1

# Default command to start all servers
CMD ["python", "start_servers.py"]

# Stage 3: Web Application
FROM base AS web-app

# Copy application code
COPY --chown=aisoar:aisoar . .

# Create directories for logs and data
RUN mkdir -p /app/logs /app/data /app/config /app/src/web/static /app/src/web/templates
RUN chown -R aisoar:aisoar /app/logs /app/data /app/config /app/src

# Copy configuration
COPY --chown=aisoar:aisoar config/ ./config/

# Switch to non-root user
USER aisoar

# Expose web application port
EXPOSE 8080

# Health check for web application
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Start the web application using uvicorn directly
CMD ["python", "-m", "uvicorn", "src.web.app:app", "--host", "0.0.0.0", "--port", "8080"]

# Stage 4: Production Ready (includes both web and MCP servers)
FROM base AS production

# Copy application code
COPY --chown=aisoar:aisoar . .

# Create all necessary directories
RUN mkdir -p /app/logs /app/data /app/config /app/src/web/static /app/src/web/templates
RUN chown -R aisoar:aisoar /app/logs /app/data /app/config /app/src

# Copy configuration
COPY --chown=aisoar:aisoar config/ ./config/

# Switch to non-root user
USER aisoar

# Expose all ports
EXPOSE 8080 8001 8002 8003 8004 8005

# Health check for main web application
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8080/health || exit 1

# Default command starts web application (MCP servers can be started separately)
CMD ["python", "-m", "uvicorn", "src.web.app:app", "--host", "0.0.0.0", "--port", "8080"]
