#!/bin/bash

# Deploy AI-SOAR with Startup Script (No SSH Required)
# This approach uses VM startup scripts to avoid SSH connectivity issues

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="svc-hackathon-prod07"
VM_NAME="ai-soar-vm-startup"
ZONE="us-central1-a"
MACHINE_TYPE="n1-standard-4"
SERVICE_ACCOUNT="ai-soar-vm@${PROJECT_ID}.iam.gserviceaccount.com"

echo -e "${BLUE}🚀 Deploying AI-SOAR with Startup Script${NC}"
echo "=========================================="

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Create comprehensive startup script
print_status "Creating comprehensive startup script..."
cat > startup-script.sh << 'EOF'
#!/bin/bash

# AI-SOAR Platform Startup Script
# This script sets up everything automatically on VM boot

exec > >(tee /var/log/ai-soar-startup.log) 2>&1
echo "=== AI-SOAR Startup Script Started at $(date) ==="

set -e

# Update system
apt-get update
apt-get upgrade -y

# Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
usermod -aG docker ubuntu
systemctl enable docker
systemctl start docker

# Install Docker Compose
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Install required packages
apt-get install -y python3 python3-pip python3-venv git curl jq

# Create application directory
mkdir -p /opt/ai-soar
chown ubuntu:ubuntu /opt/ai-soar
cd /opt/ai-soar

# Create a minimal AI-SOAR application structure
mkdir -p src/client src/servers src/config deployment/config scripts

# Create requirements.txt
cat > requirements.txt << 'REQUIREMENTS'
fastapi==0.104.1
uvicorn[standard]==0.24.0
pydantic==2.5.0
aiohttp==3.9.1
requests==2.31.0
pyyaml==6.0.1
boto3==1.34.0
anthropic==0.18.0
google-cloud-aiplatform==1.38.0
google-auth==2.23.4
vertexai>=1.38.0
google-generativeai>=0.3.0
jinja2==3.1.2
python-multipart==0.0.6
python-jose[cryptography]==3.3.0
websockets==11.0.3
REQUIREMENTS

# Create basic configuration
cat > src/config/settings.py << 'SETTINGS'
class AppConfig:
    def __init__(self):
        self.mcp_servers = {
            "virustotal": {"base_url": "http://0.0.0.0:8001", "capabilities": ["ip_report"]},
            "servicenow": {"base_url": "http://0.0.0.0:8002", "capabilities": ["create_record"]},
            "cyberreason": {"base_url": "http://0.0.0.0:8003", "capabilities": ["check_terminal_status"]},
            "custom_rest": {"base_url": "http://0.0.0.0:8004", "capabilities": ["custom_enrichment"]},
            "cloud_ivx": {"base_url": "http://0.0.0.0:8005", "capabilities": ["lookup_hashes"]}
        }
        self.kafka_config = {
            "bootstrap_servers": ["localhost:19092", "localhost:29092", "localhost:39092"],
            "security_protocol": "PLAINTEXT"
        }
SETTINGS

# Create basic MCP servers
for port in 8001 8002 8003 8004 8005; do
    cat > src/servers/server_${port}.py << SERVER_CODE
from fastapi import FastAPI

app = FastAPI(title="MCP Server ${port}")

@app.get("/")
def root():
    return {"message": "MCP Server ${port} is running"}

@app.get("/health")
def health():
    return {"status": "healthy"}

@app.get("/meta")
def meta():
    return {"capabilities": ["test"], "server": "MCP Server ${port}"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=${port})
SERVER_CODE
done

# Create web application
cat > web_main.py << 'WEBAPP'
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="AI-SOAR Web Application")

@app.get("/")
def root():
    return HTMLResponse("""
    <html>
        <head><title>AI-SOAR Platform</title></head>
        <body>
            <h1>🚀 AI-SOAR Platform</h1>
            <p>Welcome to the AI-Driven Cybersecurity Automation Platform!</p>
            <h2>Services</h2>
            <ul>
                <li><a href="http://localhost:8001">VirusTotal Server</a></li>
                <li><a href="http://localhost:8002">ServiceNow Server</a></li>
                <li><a href="http://localhost:8003">CyberReason Server</a></li>
                <li><a href="http://localhost:8005">Cloud IVX Server</a></li>
            </ul>
        </body>
    </html>
    """)

@app.get("/health")
def health():
    return {"status": "healthy", "service": "ai-soar-web"}

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8080)
WEBAPP

# Create service startup script
cat > start_services.sh << 'START_SERVICES'
#!/bin/bash
cd /opt/ai-soar
sleep 30

# Setup Python environment
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Start MCP servers in background
for port in 8001 8002 8003 8004 8005; do
    nohup python src/servers/server_${port}.py > logs/server_${port}.log 2>&1 &
done

# Start web application
nohup python web_main.py > logs/web_app.log 2>&1 &

echo "All services started!"
START_SERVICES

chmod +x start_services.sh

# Create logs directory
mkdir -p logs

# Change ownership
chown -R ubuntu:ubuntu /opt/ai-soar

# Install Python dependencies as ubuntu user
sudo -u ubuntu bash << 'USER_SETUP'
cd /opt/ai-soar
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
USER_SETUP

# Start services
sudo -u ubuntu /opt/ai-soar/start_services.sh

echo "=== AI-SOAR Startup Script Completed at $(date) ==="
echo "Services should be available at:"
echo "  - Web App: http://localhost:8080"
echo "  - MCP Servers: http://localhost:8001-8005"
EOF

# Delete existing VM if it exists
if gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
    print_warning "Deleting existing VM: $VM_NAME"
    gcloud compute instances delete $VM_NAME --zone=$ZONE --quiet
fi

# Get subnet info
SUBNET_INFO=$(gcloud compute networks subnets list --format="value(name,region,network)" | head -1)
SUBNET_NAME=$(echo $SUBNET_INFO | cut -d' ' -f1)

print_status "Creating VM with startup script..."
gcloud compute instances create $VM_NAME \
    --zone=$ZONE \
    --machine-type=$MACHINE_TYPE \
    --boot-disk-size=100GB \
    --boot-disk-type=pd-ssd \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --subnet=$SUBNET_NAME \
    --tags=ai-soar-server \
    --service-account=$SERVICE_ACCOUNT \
    --scopes=https://www.googleapis.com/auth/cloud-platform \
    --metadata-from-file startup-script=startup-script.sh

VM_IP=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

echo ""
echo -e "${GREEN}✅ VM created with startup script!${NC}"
echo "================================="
echo ""
echo -e "${BLUE}📋 VM Details:${NC}"
echo "  • Name: $VM_NAME"
echo "  • Zone: $ZONE"
echo "  • External IP: $VM_IP"
echo "  • Internal subnet: $SUBNET_NAME"
echo ""
echo -e "${BLUE}⏳ Services are being installed automatically...${NC}"
echo "  This process takes 5-10 minutes. Monitor progress with:"
echo "  gcloud compute instances get-serial-port-output $VM_NAME --zone=$ZONE"
echo ""
echo -e "${BLUE}🔗 Access via SSH Tunneling:${NC}"
echo "  After services are ready, create tunnels:"
echo ""
cat > create_tunnels.sh << EOF
#!/bin/bash
echo "Creating SSH tunnels to AI-SOAR services..."
gcloud compute ssh $VM_NAME --zone=$ZONE -- \\
    -L 8080:localhost:8080 \\
    -L 8088:localhost:8088 \\
    -L 8001:localhost:8001 \\
    -L 8002:localhost:8002 \\
    -L 8003:localhost:8003 \\
    -L 8004:localhost:8004 \\
    -L 8005:localhost:8005 \\
    -N
EOF
chmod +x create_tunnels.sh

echo "  Run: ./create_tunnels.sh"
echo ""
echo -e "${BLUE}📊 Services will be available at:${NC}"
echo "  • Web Application: http://localhost:8080"
echo "  • MCP Servers: http://localhost:8001-8005"
echo ""
echo -e "${YELLOW}💡 Wait 5-10 minutes for automatic setup to complete!${NC}"

# Clean up
rm startup-script.sh

print_status "🎉 Deployment initiated! Services will be ready shortly."
