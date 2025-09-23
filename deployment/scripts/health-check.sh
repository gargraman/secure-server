#!/bin/bash

# Health Check Script for AI SOAR Platform
# Usage: ./health-check.sh

set -e

# Color codes
GREEN='\033[0;32m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo "🏥 AI SOAR Platform Health Check"
echo "================================="

# Function to check service health
check_service() {
    local service_name=$1
    local port=$2
    local endpoint=${3:-"/meta"}

    echo -n "Checking $service_name (port $port)... "

    if curl -sf "http://localhost:$port$endpoint" > /dev/null 2>&1; then
        echo -e "${GREEN}✓ OK${NC}"
        return 0
    else
        echo -e "${RED}✗ FAIL${NC}"
        return 1
    fi
}

# Check Docker services
echo -e "\n📦 Docker Services:"
if docker-compose -f deployment/docker-compose.yml ps | grep -q "Up"; then
    echo -e "${GREEN}✓ Docker services are running${NC}"
else
    echo -e "${RED}✗ Docker services not running${NC}"
    exit 1
fi

# Check individual MCP servers
echo -e "\n🔧 MCP Servers:"
failed_services=0

check_service "VirusTotal Server" 8001 || ((failed_services++))
check_service "ServiceNow Server" 8002 || ((failed_services++))
check_service "CyberReason Server" 8003 || ((failed_services++))
check_service "Cloud IVX Server" 8005 || ((failed_services++))

# Check Nginx
echo -e "\n🌐 Web Server:"
check_service "Nginx Proxy" 80 "/health" || ((failed_services++))

# Check monitoring (if enabled)
echo -e "\n📊 Monitoring:"
if check_service "Prometheus" 9090 "/api/v1/status/config" 2>/dev/null; then
    echo -e "${GREEN}✓ Prometheus monitoring active${NC}"
else
    echo -e "${YELLOW}⚠ Prometheus monitoring not available${NC}"
fi

# System resources
echo -e "\n💾 System Resources:"
memory_usage=$(free | grep Mem | awk '{printf "%.1f", $3/$2 * 100.0}')
disk_usage=$(df / | tail -1 | awk '{print $5}' | sed 's/%//')

echo "Memory usage: ${memory_usage}%"
echo "Disk usage: ${disk_usage}%"

if (( $(echo "$memory_usage > 90" | bc -l) )); then
    echo -e "${RED}⚠ High memory usage detected${NC}"
    ((failed_services++))
fi

if (( disk_usage > 90 )); then
    echo -e "${RED}⚠ High disk usage detected${NC}"
    ((failed_services++))
fi

# Summary
echo -e "\n📋 Summary:"
if [ $failed_services -eq 0 ]; then
    echo -e "${GREEN}✓ All services are healthy${NC}"
    exit 0
else
    echo -e "${RED}✗ $failed_services service(s) failed health check${NC}"
    exit 1
fi
