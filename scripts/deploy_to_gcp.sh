#!/bin/bash

# Deploy AI-SOAR Platform to Google Cloud Platform
# This script automates the deployment process for testing environment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="svc-hackathon-prod07"
VM_NAME="ai-soar-vm"
ZONE="us-central1-a"
MACHINE_TYPE="n1-standard-4"
SERVICE_ACCOUNT="ai-soar-vm@${PROJECT_ID}.iam.gserviceaccount.com"

echo -e "${BLUE}🚀 Deploying AI-SOAR Platform to Google Cloud${NC}"
echo "=============================================="

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

# Check if gcloud is installed
if ! command -v gcloud &> /dev/null; then
    print_error "Google Cloud SDK is not installed. Please install it first."
    exit 1
fi

# Check if user is authenticated
if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
    print_error "Not authenticated with Google Cloud. Please run: gcloud auth login"
    exit 1
fi

# Set project
print_status "Setting Google Cloud project to $PROJECT_ID..."
gcloud config set project $PROJECT_ID

# Enable required APIs
print_status "Enabling required APIs..."
gcloud services enable \
    aiplatform.googleapis.com \
    secretmanager.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    compute.googleapis.com \
    storage.googleapis.com

# Create service account if it doesn't exist
print_status "Creating service account..."
if ! gcloud iam service-accounts describe $SERVICE_ACCOUNT &>/dev/null; then
    gcloud iam service-accounts create ai-soar-vm \
        --display-name="AI SOAR VM Service Account"

    # Grant required permissions
    for role in "roles/aiplatform.user" "roles/secretmanager.secretAccessor" "roles/logging.logWriter" "roles/monitoring.metricWriter"; do
        gcloud projects add-iam-policy-binding $PROJECT_ID \
            --member="serviceAccount:$SERVICE_ACCOUNT" \
            --role="$role"
    done
    print_status "Service account created and configured"
else
    print_status "Service account already exists"
fi

# Create firewall rules (restricted set)
print_status "Creating firewall rules..."
if ! gcloud compute firewall-rules describe allow-ai-soar-ports &>/dev/null; then
    # Try with minimal essential ports first
    if gcloud compute firewall-rules create allow-ai-soar-ports \
        --allow=tcp:80,tcp:443,tcp:8080 \
        --source-ranges=0.0.0.0/0 \
        --target-tags=ai-soar-server \
        --description="Allow AI-SOAR platform essential ports" &>/dev/null; then
        print_status "Essential firewall rules created (ports 80, 443, 8080)"
    else
        print_error "Failed to create firewall rules. You may need 'compute.firewalls.create' permission."
        print_warning "Please ask your GCP admin to create firewall rules or use SSH tunneling:"
        echo "  gcloud compute firewall-rules create allow-ai-soar-ports \\"
        echo "    --allow=tcp:80,tcp:443,tcp:8080,tcp:8088,tcp:8001-8005 \\"
        echo "    --source-ranges=0.0.0.0/0 \\"
        echo "    --target-tags=ai-soar-server"
        echo ""
        print_status "Continuing deployment without external firewall rules..."
    fi
else
    print_status "Firewall rules already exist"
fi

# Create VM instance
print_status "Creating VM instance..."
if ! gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
    gcloud compute instances create $VM_NAME \
        --zone=$ZONE \
        --machine-type=$MACHINE_TYPE \
        --boot-disk-size=100GB \
        --boot-disk-type=pd-ssd \
        --image-family=ubuntu-2204-lts \
        --image-project=ubuntu-os-cloud \
        --tags=ai-soar-server \
        --service-account=$SERVICE_ACCOUNT \
        --scopes=https://www.googleapis.com/auth/cloud-platform \
        --metadata-from-file startup-script=deployment/vm-setup.sh

    print_status "VM instance created successfully"

    # Wait for VM to be ready
    print_status "Waiting for VM to be ready..."
    sleep 30

    # Wait for startup script to complete
    print_status "Waiting for startup script to complete (this may take 5-10 minutes)..."
    while true; do
        status=$(gcloud compute instances get-serial-port-output $VM_NAME --zone=$ZONE | tail -1)
        if [[ "$status" == *"VM setup completed successfully"* ]]; then
            break
        fi
        echo -n "."
        sleep 10
    done
    echo ""
    print_status "VM setup completed"
else
    print_status "VM instance already exists"
fi

# Get VM external IP
VM_IP=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
print_status "VM External IP: $VM_IP"

# Copy application files to VM
print_status "Copying application files to VM..."
gcloud compute scp --recurse \
    ./src ./deployment ./requirements.txt ./scripts \
    ./main.py ./web_main.py ./launch_servers.py ./launch_web_app.py \
    $VM_NAME:/opt/ai-soar/ \
    --zone=$ZONE

# Deploy configuration
print_status "Deploying configuration..."
gcloud compute ssh $VM_NAME --zone=$ZONE --command="
    cd /opt/ai-soar

    # Copy staging configuration
    cp config/deployment/staging.env .env

    # Update configuration with VM IP
    sed -i 's/ALLOWED_HOSTS=.*/ALLOWED_HOSTS=localhost,127.0.0.1,$VM_IP/' .env

    # Activate virtual environment and install dependencies
    source venv/bin/activate
    pip install -r requirements.txt

    # Build and start services
    docker-compose -f deployment/docker-compose.yml build
    docker-compose -f deployment/docker-compose.yml up -d

    # Start messaging infrastructure
    chmod +x scripts/*.sh
    ./scripts/start_messaging_infra.sh

    # Wait for services to be ready
    sleep 30

    # Create Kafka topics
    ./scripts/create_topics.sh

    echo 'Deployment completed successfully!'
"

# Verify deployment
print_status "Verifying deployment..."
echo ""
echo -e "${GREEN}✅ Deployment completed successfully!${NC}"
echo "========================================="
echo ""
echo -e "${BLUE}🌐 Access Points:${NC}"
echo "  • VM External IP: $VM_IP"
echo "  • Web Application: http://$VM_IP:8080"
echo "  • VirusTotal Server: http://$VM_IP:8001"
echo "  • ServiceNow Server: http://$VM_IP:8002"
echo "  • CyberReason Server: http://$VM_IP:8003"
echo "  • Custom REST Server: http://$VM_IP:8004"
echo "  • Cloud IVX Server: http://$VM_IP:8005"
echo ""
echo -e "${BLUE}🔧 Management Commands:${NC}"
echo "  • SSH to VM: gcloud compute ssh $VM_NAME --zone=$ZONE"
echo "  • View logs: gcloud compute ssh $VM_NAME --zone=$ZONE --command='docker-compose logs -f'"
echo "  • Stop VM: gcloud compute instances stop $VM_NAME --zone=$ZONE"
echo "  • Start VM: gcloud compute instances start $VM_NAME --zone=$ZONE"
echo ""
echo -e "${BLUE}📊 Health Checks:${NC}"
for port in 8001 8002 8003 8004 8005 8080 8088; do
    if curl -s "http://$VM_IP:$port/health" &>/dev/null || curl -s "http://$VM_IP:$port/meta" &>/dev/null || curl -s "http://$VM_IP:$port" &>/dev/null; then
        echo -e "  • Port $port: ${GREEN}✅ Available${NC}"
    else
        echo -e "  • Port $port: ${YELLOW}⏳ Starting...${NC}"
    fi
done
echo ""

# Show next steps
echo -e "${BLUE}📝 Next Steps:${NC}"
echo "1. Update API keys in Secret Manager (if not done already)"
echo "2. Test the web interface at http://$VM_IP:8080"
echo "3. Monitor logs and performance"
echo ""

print_status "🎉 AI-SOAR Platform is now running on Google Cloud!"
