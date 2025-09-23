#!/bin/bash

# Unified GCP Deployment Script for AI-SOAR Platform
# Supports different deployment modes via command line arguments

set -e

# Get script directory for sourcing common functions
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

# Default mode
DEPLOYMENT_MODE="standard"
FORCE_DELETE=false

# Parse command line arguments
show_help() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Deployment modes:"
    echo "  --standard      Full deployment with firewall rules (default)"
    echo "  --restricted    Limited permissions, uses SSH tunneling"
    echo "  --minimal       Basic infrastructure only"
    echo "  --startup-only  Use startup script for everything"
    echo ""
    echo "Options:"
    echo "  --force         Delete existing VM if it exists"
    echo "  --project ID    Override project ID"
    echo "  --zone ZONE     Override zone"
    echo "  --vm-name NAME  Override VM name"
    echo "  -h, --help      Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 --minimal --force"
    echo "  $0 --restricted --project my-project"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        --standard)
            DEPLOYMENT_MODE="standard"
            shift
            ;;
        --restricted)
            DEPLOYMENT_MODE="restricted"
            shift
            ;;
        --minimal)
            DEPLOYMENT_MODE="minimal"
            shift
            ;;
        --startup-only)
            DEPLOYMENT_MODE="startup-only"
            shift
            ;;
        --force)
            FORCE_DELETE=true
            shift
            ;;
        --project)
            PROJECT_ID="$2"
            SERVICE_ACCOUNT="ai-soar-vm@${PROJECT_ID}.iam.gserviceaccount.com"
            shift 2
            ;;
        --zone)
            ZONE="$2"
            shift 2
            ;;
        --vm-name)
            VM_NAME="$2"
            shift 2
            ;;
        -h|--help)
            show_help
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            show_help
            exit 1
            ;;
    esac
done

echo -e "${BLUE}🚀 Deploying AI-SOAR Platform to GCP (${DEPLOYMENT_MODE} mode)${NC}"
echo "=============================================="

# Check requirements
check_requirements

# Setup GCP project and APIs
setup_gcp_project

# Create service account
create_service_account

# Handle existing VM
if gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
    if [[ "$FORCE_DELETE" == true ]]; then
        print_warning "Deleting existing VM: $VM_NAME"
        gcloud compute instances delete $VM_NAME --zone=$ZONE --quiet
    else
        VM_IP=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
        print_status "VM already exists with IP: $VM_IP"
        create_tunnel_script
        show_completion_info
        exit 0
    fi
fi

# Create firewall rules based on mode
create_firewall_rules() {
    case $DEPLOYMENT_MODE in
        "standard")
            print_status "Creating full firewall rules..."
            if ! gcloud compute firewall-rules describe allow-ai-soar-ports &>/dev/null; then
                gcloud compute firewall-rules create allow-ai-soar-ports \
                    --allow=tcp:80,tcp:443,tcp:8080,tcp:8088,tcp:8001-8005 \
                    --source-ranges=0.0.0.0/0 \
                    --target-tags=ai-soar-server \
                    --description="Allow AI-SOAR platform ports"
                print_status "Firewall rules created"
            else
                print_status "Firewall rules already exist"
            fi
            ;;
        "restricted"|"minimal"|"startup-only")
            print_warning "Skipping firewall rules - using SSH tunneling"
            ;;
    esac
}

# Create appropriate startup script based on mode
create_startup_script() {
    local script_name="startup-script-${DEPLOYMENT_MODE}.sh"

    case $DEPLOYMENT_MODE in
        "minimal")
            cat > "$script_name" << 'EOF'
#!/bin/bash
exec > >(tee /var/log/ai-soar-startup.log) 2>&1
echo "=== Minimal AI-SOAR Setup Started ==="

set -e
apt-get update && apt-get upgrade -y
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu
systemctl enable docker && systemctl start docker

curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

mkdir -p /opt/ai-soar
chown ubuntu:ubuntu /opt/ai-soar

mkdir -p /opt/ai-soar/html
echo '<h1>AI-SOAR Minimal Setup - Ready!</h1>' > /opt/ai-soar/html/index.html
chown -R ubuntu:ubuntu /opt/ai-soar

cd /opt/ai-soar
sudo -u ubuntu docker-compose up -d
echo "=== Minimal Setup Completed ==="
EOF
            ;;
        "startup-only")
            # Use the comprehensive startup script from deploy_with_startup.sh
            cat > "$script_name" << 'EOF'
#!/bin/bash
exec > >(tee /var/log/ai-soar-startup.log) 2>&1
echo "=== AI-SOAR Full Setup Started ==="

set -e
apt-get update && apt-get upgrade -y
curl -fsSL https://get.docker.com | sh
usermod -aG docker ubuntu
systemctl enable docker && systemctl start docker

curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

apt-get install -y python3 python3-pip python3-venv git curl jq
mkdir -p /opt/ai-soar/src/{client,servers,config} /opt/ai-soar/logs
chown -R ubuntu:ubuntu /opt/ai-soar

# Create minimal working application structure
cd /opt/ai-soar
cat > requirements.txt << 'REQS'
fastapi==0.104.1
uvicorn[standard]==0.24.0
requests==2.31.0
REQS

# Create basic MCP servers and web app
for port in 8001 8002 8003 8004 8005; do
cat > src/servers/server_${port}.py << PYCODE
from fastapi import FastAPI
import uvicorn
app = FastAPI(title="MCP Server ${port}")
@app.get("/")
def root(): return {"message": "MCP Server ${port} is running"}
@app.get("/health")
def health(): return {"status": "healthy"}
@app.get("/meta")
def meta(): return {"capabilities": ["test"], "server": "MCP Server ${port}"}
if __name__ == "__main__": uvicorn.run(app, host="0.0.0.0", port=${port})
PYCODE
done

cat > web_main.py << 'WEBAPP'
from fastapi import FastAPI
from fastapi.responses import HTMLResponse
app = FastAPI(title="AI-SOAR Web")
@app.get("/")
def root(): return HTMLResponse("<h1>AI-SOAR Platform Ready!</h1><p>Access services via SSH tunnels</p>")
if __name__ == "__main__":
    import uvicorn; uvicorn.run(app, host="0.0.0.0", port=8080)
WEBAPP

# Setup Python environment and start services
sudo -u ubuntu python3 -m venv venv
sudo -u ubuntu bash -c 'source venv/bin/activate && pip install -r requirements.txt'

sudo -u ubuntu docker-compose up -d

# Start Python services
for port in 8001 8002 8003 8004 8005; do
    sudo -u ubuntu bash -c "cd /opt/ai-soar && source venv/bin/activate && nohup python src/servers/server_${port}.py > logs/server_${port}.log 2>&1 &"
done
sudo -u ubuntu bash -c "cd /opt/ai-soar && source venv/bin/activate && nohup python web_main.py > logs/web.log 2>&1 &"

echo "=== Full Setup Completed ==="
EOF
            ;;
        *)
            # Standard/restricted use deployment/vm-setup.sh
            script_name="deployment/vm-setup.sh"
            ;;
    esac

    echo "$script_name"
}

# Create firewall rules
create_firewall_rules

# Create startup script
startup_script=$(create_startup_script)

# Create VM
print_status "Creating VM instance..."
create_vm "$startup_script"

# Wait for startup completion
wait_for_vm_startup

# Copy files if not using startup-only mode
if [[ "$DEPLOYMENT_MODE" != "startup-only" && "$DEPLOYMENT_MODE" != "minimal" ]]; then
    print_status "Copying application files to VM..."
    VM_IP=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(networkInterfaces[0].accessConfigs[0].natIP)')

    gcloud compute scp --recurse \
        ./src ./deployment ./requirements.txt ./scripts \
        ./main.py ./web_main.py ./launch_servers.py ./launch_web_app.py \
        $VM_NAME:/opt/ai-soar/ \
        --zone=$ZONE || print_warning "File copy failed - may need manual setup"
fi

# Create tunnel script and show completion info
create_tunnel_script
show_completion_info

# Clean up temporary files
rm -f startup-script-*.sh

print_status "🎉 AI-SOAR Platform deployment complete!"
