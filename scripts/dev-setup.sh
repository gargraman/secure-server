#!/bin/bash

# AI-SOAR Platform Development Environment Setup Script
# This script sets up a complete local development environment

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
DEPLOYMENT_DIR="$PROJECT_ROOT/deployment"

echo -e "${BLUE}🚀 AI-SOAR Platform Development Setup${NC}"
echo -e "${BLUE}======================================${NC}"

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}📋 Checking prerequisites...${NC}"

    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is not installed. Please install Docker first.${NC}"
        exit 1
    fi

    # Check Docker Compose
    if ! command -v docker-compose &> /dev/null; then
        echo -e "${RED}❌ Docker Compose is not installed. Please install Docker Compose first.${NC}"
        exit 1
    fi

    # Check Python
    if ! command -v python3 &> /dev/null; then
        echo -e "${RED}❌ Python 3 is not installed. Please install Python 3.11+ first.${NC}"
        exit 1
    fi

    # Check curl
    if ! command -v curl &> /dev/null; then
        echo -e "${RED}❌ curl is not installed. Please install curl first.${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ All prerequisites are installed${NC}"
}

# Setup Python virtual environment
setup_python_env() {
    echo -e "${YELLOW}🐍 Setting up Python virtual environment...${NC}"

    cd "$PROJECT_ROOT"

    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        python3 -m venv venv
        echo -e "${GREEN}✅ Virtual environment created${NC}"
    else
        echo -e "${YELLOW}📁 Virtual environment already exists${NC}"
    fi

    # Activate virtual environment
    source venv/bin/activate

    # Upgrade pip
    pip install --upgrade pip

    # Install dependencies
    if [ -f "requirements.txt" ]; then
        pip install -r requirements.txt
        echo -e "${GREEN}✅ Python dependencies installed${NC}"
    else
        echo -e "${YELLOW}⚠️  requirements.txt not found${NC}"
    fi

    # Install development dependencies
    pip install pytest pytest-asyncio pytest-cov black isort flake8 pre-commit
    echo -e "${GREEN}✅ Development dependencies installed${NC}"
}

# Setup development environment file
setup_env_file() {
    echo -e "${YELLOW}⚙️  Setting up environment configuration...${NC}"

    cd "$DEPLOYMENT_DIR"

    # Copy development environment file
    if [ ! -f ".env" ]; then
        if [ -f ".env.development" ]; then
            cp .env.development .env
            echo -e "${GREEN}✅ Development environment file created${NC}"
        else
            echo -e "${YELLOW}⚠️  .env.development template not found${NC}"
        fi
    else
        echo -e "${YELLOW}📁 Environment file already exists${NC}"
    fi

    echo -e "${BLUE}📝 Please review and update .env file with your configuration${NC}"
}

# Setup pre-commit hooks
setup_pre_commit() {
    echo -e "${YELLOW}🎣 Setting up pre-commit hooks...${NC}"

    cd "$PROJECT_ROOT"

    # Check if we're in a git repository
    if [ -d ".git" ]; then
        # Create .pre-commit-config.yaml if it doesn't exist
        if [ ! -f ".pre-commit-config.yaml" ]; then
            cat > .pre-commit-config.yaml << 'EOF'
repos:
-   repo: https://github.com/pre-commit/pre-commit-hooks
    rev: v4.4.0
    hooks:
    -   id: trailing-whitespace
    -   id: end-of-file-fixer
    -   id: check-yaml
    -   id: check-added-large-files
    -   id: check-json
    -   id: check-merge-conflict
    -   id: debug-statements

-   repo: https://github.com/psf/black
    rev: 23.12.0
    hooks:
    -   id: black
        language_version: python3

-   repo: https://github.com/pycqa/isort
    rev: 5.13.0
    hooks:
    -   id: isort

-   repo: https://github.com/pycqa/flake8
    rev: 6.1.0
    hooks:
    -   id: flake8

-   repo: https://github.com/PyCQA/bandit
    rev: 1.7.5
    hooks:
    -   id: bandit
        args: ["-r", "src/"]
EOF
        fi

        # Install pre-commit hooks
        source venv/bin/activate
        pre-commit install
        echo -e "${GREEN}✅ Pre-commit hooks installed${NC}"
    else
        echo -e "${YELLOW}⚠️  Not in a git repository, skipping pre-commit setup${NC}"
    fi
}

# Create necessary directories
create_directories() {
    echo -e "${YELLOW}📁 Creating necessary directories...${NC}"

    cd "$PROJECT_ROOT"

    # Create directories if they don't exist
    mkdir -p logs data config src/web/static src/web/templates

    # Set permissions
    chmod 755 logs data config

    echo -e "${GREEN}✅ Directories created${NC}"
}

# Start development services
start_dev_services() {
    echo -e "${YELLOW}🐳 Starting development services...${NC}"

    cd "$DEPLOYMENT_DIR"

    # Stop any existing containers
    docker-compose -f docker-compose.dev.yml down --remove-orphans || true

    # Build and start services
    docker-compose -f docker-compose.dev.yml up -d --build

    echo -e "${GREEN}✅ Development services started${NC}"

    # Wait for services to be ready
    echo -e "${YELLOW}⏳ Waiting for services to be ready...${NC}"

    # Wait for Neo4j
    echo -e "${YELLOW}🔍 Waiting for Neo4j...${NC}"
    timeout=60
    while [ $timeout -gt 0 ]; do
        if docker-compose -f docker-compose.dev.yml exec -T neo4j-db cypher-shell -u neo4j -p devpassword123 "RETURN 1" &>/dev/null; then
            echo -e "${GREEN}✅ Neo4j is ready${NC}"
            break
        fi
        timeout=$((timeout-1))
        sleep 2
    done

    if [ $timeout -eq 0 ]; then
        echo -e "${RED}❌ Neo4j failed to start within 120 seconds${NC}"
        exit 1
    fi

    # Wait for Redis
    echo -e "${YELLOW}🔍 Waiting for Redis...${NC}"
    timeout=30
    while [ $timeout -gt 0 ]; do
        if docker-compose -f docker-compose.dev.yml exec -T redis redis-cli ping &>/dev/null; then
            echo -e "${GREEN}✅ Redis is ready${NC}"
            break
        fi
        timeout=$((timeout-1))
        sleep 1
    done

    # Initialize Neo4j database
    echo -e "${YELLOW}🗄️  Initializing Neo4j database...${NC}"
    cd "$PROJECT_ROOT"
    source venv/bin/activate
    export NEO4J_URI=neo4j://localhost:7687
    export NEO4J_USERNAME=neo4j
    export NEO4J_PASSWORD=devpassword123
    python -m src.database.neo4j_setup
    echo -e "${GREEN}✅ Neo4j database initialized${NC}"
}

# Display service information
display_service_info() {
    echo -e "${BLUE}🌐 Development Environment Ready!${NC}"
    echo -e "${BLUE}===================================${NC}"
    echo ""
    echo -e "${GREEN}🚀 Services:${NC}"
    echo -e "  • Web Application:     ${YELLOW}http://localhost:8080${NC}"
    echo -e "  • API Documentation:   ${YELLOW}http://localhost:8080/docs${NC}"
    echo -e "  • Neo4j Browser:       ${YELLOW}http://localhost:7474${NC} (neo4j/devpassword123)"
    echo -e "  • Redpanda Console:    ${YELLOW}http://localhost:8088${NC}"
    echo -e "  • MCP Servers:         ${YELLOW}http://localhost:8001-8005${NC}"
    echo ""
    echo -e "${GREEN}🔧 MCP Server Ports:${NC}"
    echo -e "  • VirusTotal Server:   ${YELLOW}http://localhost:8001${NC}"
    echo -e "  • ServiceNow Server:   ${YELLOW}http://localhost:8002${NC}"
    echo -e "  • CyberReason Server:  ${YELLOW}http://localhost:8003${NC}"
    echo -e "  • Custom REST Server:  ${YELLOW}http://localhost:8004${NC}"
    echo -e "  • Cloud IVX Server:    ${YELLOW}http://localhost:8005${NC}"
    echo ""
    echo -e "${GREEN}📂 Useful Commands:${NC}"
    echo -e "  • View logs:           ${YELLOW}docker-compose -f deployment/docker-compose.dev.yml logs -f${NC}"
    echo -e "  • Stop services:       ${YELLOW}docker-compose -f deployment/docker-compose.dev.yml down${NC}"
    echo -e "  • Restart service:     ${YELLOW}docker-compose -f deployment/docker-compose.dev.yml restart <service>${NC}"
    echo -e "  • Run web app locally: ${YELLOW}source venv/bin/activate && python -m uvicorn src.web.app:app --reload${NC}"
    echo -e "  • Run tests:           ${YELLOW}source venv/bin/activate && pytest${NC}"
    echo ""
    echo -e "${BLUE}Happy coding! 🎉${NC}"
}

# Cleanup function
cleanup_on_error() {
    echo -e "${RED}❌ Setup failed. Cleaning up...${NC}"
    cd "$DEPLOYMENT_DIR"
    docker-compose -f docker-compose.dev.yml down --remove-orphans || true
    exit 1
}

# Set trap for cleanup on error
trap cleanup_on_error ERR

# Main execution
main() {
    check_prerequisites
    setup_python_env
    setup_env_file
    create_directories
    setup_pre_commit
    start_dev_services
    display_service_info
}

# Run main function
main "$@"
