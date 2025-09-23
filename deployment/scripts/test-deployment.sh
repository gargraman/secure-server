#!/bin/bash

# AI-SOAR Platform Deployment Testing Script
# Tests both local development and production deployments

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
DEPLOYMENT_DIR="${PROJECT_ROOT}/deployment"

# Default values
TEST_MODE="local"
WAIT_TIMEOUT=120
VERBOSE=false
CLEANUP=false

# Functions
log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}"
}

success() {
    echo -e "${GREEN}✓ $1${NC}"
}

warning() {
    echo -e "${YELLOW}⚠ $1${NC}"
}

error() {
    echo -e "${RED}✗ $1${NC}"
    exit 1
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Test AI-SOAR Platform deployment configurations

OPTIONS:
    -m, --mode MODE         Test mode: local, production, or cloud (default: local)
    -t, --timeout SECONDS  Wait timeout for services (default: 120)
    -v, --verbose          Enable verbose output
    -c, --cleanup          Cleanup containers after tests
    -h, --help             Show this help message

EXAMPLES:
    $0 --mode local --verbose
    $0 --mode production --timeout 180
    $0 --mode cloud --cleanup

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -m|--mode)
            TEST_MODE="$2"
            shift 2
            ;;
        -t|--timeout)
            WAIT_TIMEOUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        -c|--cleanup)
            CLEANUP=true
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Validate test mode
case $TEST_MODE in
    local|production|cloud)
        ;;
    *)
        error "Invalid test mode: $TEST_MODE. Must be local, production, or cloud"
        ;;
esac

log "Starting AI-SOAR Platform deployment test (mode: $TEST_MODE)"

# Pre-flight checks
check_prerequisites() {
    log "Running pre-flight checks..."

    # Check Docker
    if ! command -v docker &> /dev/null; then
        error "Docker is not installed or not in PATH"
    fi
    success "Docker is available"

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        error "Docker Compose is not installed or not in PATH"
    fi
    success "Docker Compose is available"

    # Check curl
    if ! command -v curl &> /dev/null; then
        error "curl is not installed or not in PATH"
    fi
    success "curl is available"

    # Check project structure
    if [[ ! -f "${PROJECT_ROOT}/src/web/app.py" ]]; then
        error "FastAPI application not found at ${PROJECT_ROOT}/src/web/app.py"
    fi
    success "FastAPI application found"

    if [[ ! -d "${PROJECT_ROOT}/src/web/static" ]]; then
        error "Static files directory not found at ${PROJECT_ROOT}/src/web/static"
    fi
    success "Static files directory found"

    if [[ ! -d "${PROJECT_ROOT}/src/web/templates" ]]; then
        error "Templates directory not found at ${PROJECT_ROOT}/src/web/templates"
    fi
    success "Templates directory found"
}

# Test local development environment
test_local_deployment() {
    log "Testing local development deployment..."

    cd "$DEPLOYMENT_DIR"

    # Use development compose file if available
    local COMPOSE_FILE="docker-compose.dev.yml"
    if [[ ! -f "$COMPOSE_FILE" ]]; then
        COMPOSE_FILE="docker-compose.yml"
        warning "Using production compose file for local testing"
    fi

    # Start services
    log "Starting services with $COMPOSE_FILE..."
    docker-compose -f "$COMPOSE_FILE" up -d

    # Wait for services
    log "Waiting for services to become healthy..."
    local attempt=0
    while [[ $attempt -lt $((WAIT_TIMEOUT / 10)) ]]; do
        if docker-compose -f "$COMPOSE_FILE" ps | grep -q "Up"; then
            break
        fi
        sleep 10
        ((attempt++))
    done

    # Test web application
    test_web_application "localhost:8080"

    # Test MCP servers
    test_mcp_servers

    # Test static files
    test_static_files "http://localhost:8080"

    # Test WebSocket
    test_websocket "ws://localhost:8080/ws"

    success "Local deployment test completed"
}

# Test production deployment
test_production_deployment() {
    log "Testing production deployment..."

    cd "$DEPLOYMENT_DIR"

    # Start production services
    log "Starting production services..."
    docker-compose up -d

    # Wait for services
    log "Waiting for services to become healthy..."
    sleep 30

    # Test through Nginx proxy
    test_web_application "localhost"

    # Test static files through Nginx
    test_static_files "http://localhost"

    # Test WebSocket through Nginx
    test_websocket "ws://localhost/ws"

    success "Production deployment test completed"
}

# Test cloud deployment
test_cloud_deployment() {
    log "Testing Google Cloud deployment configuration..."

    # Validate Cloud Build configuration
    if [[ ! -f "${PROJECT_ROOT}/cloudbuild.yaml" ]]; then
        error "Cloud Build configuration not found"
    fi
    success "Cloud Build configuration found"

    # Validate Dockerfile for cloud deployment
    if [[ ! -f "${DEPLOYMENT_DIR}/Dockerfile" ]]; then
        error "Dockerfile not found"
    fi

    # Test Docker build
    log "Testing Docker build for cloud deployment..."
    cd "$PROJECT_ROOT"

    if $VERBOSE; then
        docker build --target production -t ai-soar-test:latest -f deployment/Dockerfile .
    else
        docker build --target production -t ai-soar-test:latest -f deployment/Dockerfile . > /dev/null
    fi
    success "Docker build successful"

    # Test container startup
    log "Testing container startup..."
    docker run -d --name ai-soar-test -p 8081:8080 ai-soar-test:latest

    # Wait for container to start
    sleep 15

    # Test basic health check
    if curl -f -s http://localhost:8081/health > /dev/null; then
        success "Container health check passed"
    else
        warning "Container health check failed"
    fi

    # Cleanup test container
    docker stop ai-soar-test > /dev/null
    docker rm ai-soar-test > /dev/null

    success "Cloud deployment test completed"
}

# Test web application endpoints
test_web_application() {
    local BASE_URL="$1"
    log "Testing web application at $BASE_URL..."

    # Test health endpoint
    if curl -f -s "http://$BASE_URL/health" > /dev/null; then
        success "Health endpoint responding"
    else
        error "Health endpoint not responding"
    fi

    # Test dashboard
    if curl -f -s "http://$BASE_URL/" > /dev/null; then
        success "Dashboard endpoint responding"
    else
        error "Dashboard endpoint not responding"
    fi

    # Test configuration page
    if curl -f -s "http://$BASE_URL/config" > /dev/null; then
        success "Configuration endpoint responding"
    else
        error "Configuration endpoint not responding"
    fi

    # Test alerts page
    if curl -f -s "http://$BASE_URL/alerts" > /dev/null; then
        success "Alerts endpoint responding"
    else
        warning "Alerts endpoint not responding"
    fi

    # Test incidents page
    if curl -f -s "http://$BASE_URL/incidents" > /dev/null; then
        success "Incidents endpoint responding"
    else
        warning "Incidents endpoint not responding"
    fi

    # Test API documentation
    if curl -f -s "http://$BASE_URL/docs" > /dev/null; then
        success "API documentation responding"
    else
        warning "API documentation not responding"
    fi

    # Test meta endpoint
    if curl -f -s "http://$BASE_URL/meta" > /dev/null; then
        success "Meta endpoint responding"
    else
        warning "Meta endpoint not responding"
    fi
}

# Test MCP servers
test_mcp_servers() {
    log "Testing MCP servers..."

    local ports=(8001 8002 8003 8004 8005)
    local servers=("VirusTotal" "ServiceNow" "CyberReason" "Custom REST" "Cloud IVX")

    for i in "${!ports[@]}"; do
        local port="${ports[$i]}"
        local server="${servers[$i]}"

        if curl -f -s "http://localhost:$port/health" > /dev/null; then
            success "$server server responding on port $port"
        else
            warning "$server server not responding on port $port"
        fi
    done
}

# Test static file serving
test_static_files() {
    local BASE_URL="$1"
    log "Testing static file serving..."

    # Test CSS files
    if curl -f -s "$BASE_URL/static/css/dashboard.css" > /dev/null; then
        success "CSS files accessible"
    else
        warning "CSS files not accessible"
    fi

    # Test JavaScript files
    if curl -f -s "$BASE_URL/static/js/common.js" > /dev/null; then
        success "JavaScript files accessible"
    else
        warning "JavaScript files not accessible"
    fi

    # Test 404 handling for missing static files
    local status_code=$(curl -s -o /dev/null -w "%{http_code}" "$BASE_URL/static/nonexistent.css")
    if [[ "$status_code" == "404" ]]; then
        success "Static file 404 handling works"
    else
        warning "Static file 404 handling may not work correctly (got $status_code)"
    fi
}

# Test WebSocket connection
test_websocket() {
    local WS_URL="$1"
    log "Testing WebSocket connection..."

    # Simple WebSocket test using websocat if available
    if command -v websocat &> /dev/null; then
        echo '{"type":"ping","timestamp":"'$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)'"}' | \
            timeout 10 websocat "$WS_URL" > /dev/null 2>&1

        if [[ $? -eq 0 ]]; then
            success "WebSocket connection test passed"
        else
            warning "WebSocket connection test failed"
        fi
    else
        warning "websocat not available, skipping WebSocket test"
    fi
}

# Cleanup function
cleanup_deployment() {
    if [[ "$CLEANUP" == "true" ]]; then
        log "Cleaning up deployment..."

        cd "$DEPLOYMENT_DIR"

        # Stop and remove containers
        if [[ "$TEST_MODE" == "local" ]]; then
            local COMPOSE_FILE="docker-compose.dev.yml"
            if [[ ! -f "$COMPOSE_FILE" ]]; then
                COMPOSE_FILE="docker-compose.yml"
            fi
            docker-compose -f "$COMPOSE_FILE" down -v
        else
            docker-compose down -v
        fi

        # Remove test images
        if [[ "$TEST_MODE" == "cloud" ]]; then
            docker rmi ai-soar-test:latest > /dev/null 2>&1 || true
        fi

        success "Cleanup completed"
    fi
}

# Trap cleanup on exit
trap cleanup_deployment EXIT

# Main execution
main() {
    check_prerequisites

    case $TEST_MODE in
        local)
            test_local_deployment
            ;;
        production)
            test_production_deployment
            ;;
        cloud)
            test_cloud_deployment
            ;;
    esac

    success "All deployment tests completed successfully!"
}

# Run main function
main "$@"
