#!/bin/bash

# Docker deployment script for AI SOAR Platform Web Application
# This script builds and runs the containerized web application

set -e

echo "🚀 AI SOAR Platform - Web Application Deployment"
echo "================================================"

# Check if Docker is running
if ! docker info >/dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

# Function to display usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo "Options:"
    echo "  --build-only    Build containers without starting them"
    echo "  --no-cache      Build without using cache"
    echo "  --dev           Run in development mode with live reload"
    echo "  --logs          Show container logs after starting"
    echo "  --help          Show this help message"
    exit 1
}

# Default options
BUILD_ONLY=false
NO_CACHE=""
DEV_MODE=false
SHOW_LOGS=false

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        --build-only)
            BUILD_ONLY=true
            shift
            ;;
        --no-cache)
            NO_CACHE="--no-cache"
            shift
            ;;
        --dev)
            DEV_MODE=true
            shift
            ;;
        --logs)
            SHOW_LOGS=true
            shift
            ;;
        --help)
            usage
            ;;
        *)
            echo "Unknown option: $1"
            usage
            ;;
    esac
done

# Get the script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

echo "📁 Project root: $PROJECT_ROOT"
echo "🐳 Docker Compose file: $SCRIPT_DIR/docker-compose.yml"

# Change to deployment directory
cd "$SCRIPT_DIR"

# Build containers
echo "🔨 Building containers..."
if [[ "$DEV_MODE" == true ]]; then
    echo "🔧 Building in development mode..."
    docker-compose -f docker-compose.yml -f docker-compose.dev.yml build $NO_CACHE
else
    echo "🏭 Building in production mode..."
    docker-compose build $NO_CACHE
fi

if [[ "$BUILD_ONLY" == true ]]; then
    echo "✅ Build completed. Containers are ready but not started."
    exit 0
fi

# Stop any existing containers
echo "🛑 Stopping existing containers..."
docker-compose down --remove-orphans

# Start containers
echo "🚀 Starting containers..."
if [[ "$DEV_MODE" == true ]]; then
    docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
else
    docker-compose up -d
fi

# Wait for services to be ready
echo "⏳ Waiting for services to start..."
sleep 10

# Check service health
echo "🔍 Checking service health..."

# Function to check if a service is healthy
check_service() {
    local service_name=$1
    local port=$2
    local endpoint=${3:-"/health"}

    echo -n "  Checking $service_name (port $port)... "

    max_attempts=30
    attempt=1

    while [[ $attempt -le $max_attempts ]]; do
        if curl -f -s "http://localhost:$port$endpoint" >/dev/null 2>&1; then
            echo "✅ Ready"
            return 0
        fi

        sleep 2
        ((attempt++))
    done

    echo "❌ Failed to start"
    return 1
}

# Check MCP servers
check_service "VirusTotal Server" 8001 "/meta"
check_service "ServiceNow Server" 8002 "/meta"
check_service "CyberReason Server" 8003 "/meta"
check_service "Cloud IVX Server" 8005 "/meta"
check_service "Web Application" 8080 "/health"
check_service "Nginx Proxy" 80 "/health"

echo ""
echo "🎉 Deployment completed successfully!"
echo ""
echo "📱 Application URLs:"
echo "   Web Interface:    http://localhost"
echo "   Direct Web App:   http://localhost:8080"
echo "   API Documentation: http://localhost:8001/docs (VirusTotal)"
echo "                     http://localhost:8002/docs (ServiceNow)"
echo "                     http://localhost:8003/docs (CyberReason)"
echo "                     http://localhost:8005/docs (Cloud IVX)"
echo ""
echo "📊 Management URLs:"
echo "   Prometheus:       http://localhost:9090"
echo "   Nginx Status:     http://localhost/health"
echo ""

if [[ "$SHOW_LOGS" == true ]]; then
    echo "📜 Showing container logs..."
    docker-compose logs -f
else
    echo "💡 To view logs, run: docker-compose logs -f"
    echo "💡 To stop all services, run: docker-compose down"
fi

echo ""
echo "✅ AI SOAR Platform is now running!"
