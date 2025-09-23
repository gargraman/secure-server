#!/bin/bash

# VM Setup Script for AI Cybersecurity Platform
# Project: svc-hackathon-prod07
# Usage: bash vm-setup.sh

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="svc-hackathon-prod07"
SERVICE_ACCOUNT_EMAIL="ai-soar-vm@${PROJECT_ID}.iam.gserviceaccount.com"
APP_DIR="/opt/ai-soar"
LOG_DIR="/var/log/ai-soar"

echo -e "${BLUE}🚀 Setting up AI Cybersecurity Platform on VM${NC}"
echo "=================================================="

# Function to print status
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if running as root
if [[ $EUID -eq 0 ]]; then
   print_error "This script should not be run as root for security reasons"
   exit 1
fi

# Update system packages
print_status "Updating system packages..."
sudo apt-get update && sudo apt-get upgrade -y

# Install required packages
print_status "Installing required packages..."
sudo apt-get install -y \
    curl \
    wget \
    git \
    unzip \
    apt-transport-https \
    ca-certificates \
    gnupg \
    lsb-release \
    python3 \
    python3-pip \
    python3-venv \
    nginx \
    ufw \
    htop \
    tree \
    jq

# Install Docker
print_status "Installing Docker..."
if ! command -v docker &> /dev/null; then
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" | sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
    sudo apt-get update
    sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    sudo usermod -aG docker $USER
    print_status "Docker installed successfully"
else
    print_status "Docker already installed"
fi

# Install Docker Compose
print_status "Installing Docker Compose..."
if ! command -v docker-compose &> /dev/null; then
    sudo curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
    sudo chmod +x /usr/local/bin/docker-compose
    print_status "Docker Compose installed successfully"
else
    print_status "Docker Compose already installed"
fi

# Install Google Cloud SDK
print_status "Installing Google Cloud SDK..."
if ! command -v gcloud &> /dev/null; then
    echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] https://packages.cloud.google.com/apt cloud-sdk main" | sudo tee -a /etc/apt/sources.list.d/google-cloud-sdk.list
    curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key --keyring /usr/share/keyrings/cloud.google.gpg add -
    sudo apt-get update && sudo apt-get install -y google-cloud-cli
    print_status "Google Cloud SDK installed successfully"
else
    print_status "Google Cloud SDK already installed"
fi

# Create application directory
print_status "Creating application directory..."
sudo mkdir -p $APP_DIR
sudo mkdir -p $LOG_DIR
sudo chown -R $USER:$USER $APP_DIR
sudo chown -R $USER:$USER $LOG_DIR

# Clone or setup application code
print_status "Setting up application code..."
cd $APP_DIR

if [[ ! -d ".git" ]]; then
    print_warning "Please manually copy your application code to $APP_DIR"
    print_warning "Or clone from your repository:"
    echo "  git clone <your-repo-url> ."
else
    print_status "Application code already present"
fi

# Setup Python virtual environment
print_status "Setting up Python virtual environment..."
python3 -m venv venv
source venv/bin/activate
pip install --upgrade pip

# Install Python dependencies (if requirements.txt exists)
if [[ -f "requirements.txt" ]]; then
    print_status "Installing Python dependencies..."
    pip install -r requirements.txt
else
    print_warning "requirements.txt not found. Please install dependencies manually."
fi

# Setup Google Cloud authentication
print_status "Setting up Google Cloud authentication..."
if [[ ! -f "/home/$USER/.config/gcloud/application_default_credentials.json" ]]; then
    print_warning "Please authenticate with Google Cloud:"
    echo "  gcloud auth login"
    echo "  gcloud config set project $PROJECT_ID"
    echo "  gcloud auth application-default login"
else
    print_status "Google Cloud authentication already configured"
fi

# Setup environment variables
print_status "Creating environment configuration..."
cat > $APP_DIR/.env << EOF
# Google Cloud Configuration
GOOGLE_CLOUD_PROJECT=$PROJECT_ID
GOOGLE_APPLICATION_CREDENTIALS=/home/$USER/.config/gcloud/application_default_credentials.json

# AI Configuration
AI_PROVIDER=google_vertex_gemini
VERTEX_AI_REGION=us-central1

# Application Configuration
ENVIRONMENT=production
LOG_LEVEL=INFO
LOG_DIR=$LOG_DIR

# Server Configuration
MCP_SERVER_HOST=0.0.0.0
VIRUSTOTAL_PORT=8001
SERVICENOW_PORT=8002
CYBERREASON_PORT=8003
CUSTOM_REST_PORT=8004
CLOUD_IVX_PORT=8005

# Security
ALLOWED_HOSTS=localhost,127.0.0.1,$(curl -s http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/ip -H "Metadata-Flavor: Google")
EOF

# Setup systemd service
print_status "Creating systemd service..."
sudo tee /etc/systemd/system/ai-soar.service > /dev/null << EOF
[Unit]
Description=AI SOAR Cybersecurity Platform
After=network.target docker.service
Requires=docker.service

[Service]
Type=forking
User=$USER
Group=$USER
WorkingDirectory=$APP_DIR
Environment=PATH=/usr/local/bin:/usr/bin:/bin
ExecStart=/usr/local/bin/docker-compose up -d
ExecStop=/usr/local/bin/docker-compose down
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# Configure firewall
print_status "Configuring firewall..."
sudo ufw --force enable
sudo ufw allow ssh
sudo ufw allow 80/tcp
sudo ufw allow 443/tcp
sudo ufw allow from 10.0.0.0/8 to any port 8001:8005  # Internal network only

# Setup log rotation
print_status "Setting up log rotation..."
sudo tee /etc/logrotate.d/ai-soar > /dev/null << EOF
$LOG_DIR/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    create 0644 $USER $USER
    postrotate
        systemctl reload ai-soar
    endscript
}
EOF

# Create startup script
print_status "Creating startup script..."
cat > $APP_DIR/start.sh << 'EOF'
#!/bin/bash
cd /opt/ai-soar
source venv/bin/activate
source .env

# Start services with Docker Compose
docker-compose up -d

# Check service status
sleep 10
docker-compose ps

echo "🎉 AI SOAR Platform started successfully!"
echo "Access the services at:"
echo "  - VirusTotal Server: http://localhost:8001"
echo "  - ServiceNow Server: http://localhost:8002"
echo "  - CyberReason Server: http://localhost:8003"
echo "  - Custom REST Server: http://localhost:8004"
echo "  - Cloud IVX Server: http://localhost:8005"
EOF

chmod +x $APP_DIR/start.sh

# Enable services
print_status "Enabling services..."
sudo systemctl daemon-reload
sudo systemctl enable ai-soar

print_status "✅ VM setup completed successfully!"
echo ""
echo "Next steps:"
echo "1. Copy your application code to $APP_DIR"
echo "2. Configure Google Cloud authentication:"
echo "   gcloud auth login"
echo "   gcloud config set project $PROJECT_ID"
echo "   gcloud auth application-default login"
echo "3. Update API keys and configuration in config/deployment/"
echo "4. Start the service:"
echo "   cd $APP_DIR && ./start.sh"
echo ""
echo "Monitor logs with:"
echo "   docker-compose logs -f"
echo "   journalctl -u ai-soar -f"
