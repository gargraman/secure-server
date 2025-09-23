#!/bin/bash

# Common functions and configuration for AI-SOAR deployment scripts
# Source this file in other scripts: source scripts/common.sh

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Default configuration
PROJECT_ID="${PROJECT_ID:-svc-hackathon-prod07}"
VM_NAME="${VM_NAME:-ai-soar-vm}"
ZONE="${ZONE:-us-central1-a}"
MACHINE_TYPE="${MACHINE_TYPE:-n1-standard-4}"
SERVICE_ACCOUNT="${SERVICE_ACCOUNT:-ai-soar-vm@${PROJECT_ID}.iam.gserviceaccount.com}"

# Print functions
print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check requirements
check_requirements() {
    if ! command -v gcloud &> /dev/null; then
        print_error "Google Cloud SDK is not installed. Please install it first."
        exit 1
    fi

    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
        print_error "Not authenticated with Google Cloud. Please run: gcloud auth login"
        exit 1
    fi
}

# Setup GCP project and APIs
setup_gcp_project() {
    print_status "Setting Google Cloud project to $PROJECT_ID..."
    gcloud config set project $PROJECT_ID

    print_status "Enabling required APIs..."
    gcloud services enable \
        aiplatform.googleapis.com \
        secretmanager.googleapis.com \
        logging.googleapis.com \
        monitoring.googleapis.com \
        compute.googleapis.com \
        storage.googleapis.com || print_warning "Some APIs may already be enabled"
}

# Create service account
create_service_account() {
    print_status "Creating service account..."
    if ! gcloud iam service-accounts describe $SERVICE_ACCOUNT &>/dev/null; then
        gcloud iam service-accounts create ai-soar-vm \
            --display-name="AI SOAR VM Service Account"

        for role in "roles/aiplatform.user" "roles/secretmanager.secretAccessor" "roles/logging.logWriter" "roles/monitoring.metricWriter"; do
            gcloud projects add-iam-policy-binding $PROJECT_ID \
                --member="serviceAccount:$SERVICE_ACCOUNT" \
                --role="$role" || print_warning "Role $role may already be assigned"
        done
        print_status "Service account created and configured"
    else
        print_status "Service account already exists"
    fi
}

# Get subnet information
get_subnet_info() {
    SUBNET_INFO=$(gcloud compute networks subnets list --format="value(name,region,network)" | head -1)
    if [ -z "$SUBNET_INFO" ]; then
        print_error "No subnets available. Please ask admin to create a subnet."
        exit 1
    fi

    SUBNET_NAME=$(echo $SUBNET_INFO | cut -d' ' -f1)
    SUBNET_REGION=$(echo $SUBNET_INFO | cut -d' ' -f2)

    # Update zone to match subnet region if needed
    if [[ "$ZONE" != "$SUBNET_REGION"* ]]; then
        ZONE="$SUBNET_REGION-a"
        print_status "Updated zone to: $ZONE to match subnet region"
    fi
}

# Create SSH tunnel script
create_tunnel_script() {
    local script_name="${1:-ssh_tunnel.sh}"
    cat > "$script_name" << EOF
#!/bin/bash
# SSH Tunnel Script for AI-SOAR Platform
VM_NAME="$VM_NAME"
ZONE="$ZONE"

echo "🔗 Creating SSH tunnels to AI-SOAR services..."
pkill -f "ssh.*\$VM_NAME.*-L" 2>/dev/null || true

gcloud compute ssh \$VM_NAME --zone=\$ZONE -- \\
    -L 8080:localhost:8080 \\
    -L 8001:localhost:8001 \\
    -L 8002:localhost:8002 \\
    -L 8003:localhost:8003 \\
    -L 8004:localhost:8004 \\
    -L 8005:localhost:8005 \\
    -L 8088:localhost:8088 \\
    -L 19092:localhost:19092 \\
    -N
EOF
    chmod +x "$script_name"
}

# Wait for VM startup
wait_for_vm_startup() {
    local timeout=${1:-300}
    print_status "Waiting for startup script to complete (up to $((timeout/60)) minutes)..."

    local elapsed=0
    while [ $elapsed -lt $timeout ]; do
        if gcloud compute instances get-serial-port-output $VM_NAME --zone=$ZONE 2>/dev/null | grep -q "VM setup completed successfully\|Startup script completed\|Setup completed"; then
            break
        fi
        echo -n "."
        sleep 10
        elapsed=$((elapsed + 10))
    done
    echo ""

    if [ $elapsed -ge $timeout ]; then
        print_warning "Startup script may still be running. Check manually with:"
        echo "  gcloud compute instances get-serial-port-output $VM_NAME --zone=$ZONE"
    else
        print_status "VM setup completed"
    fi
}

# Common VM creation function
create_vm() {
    local startup_script="$1"

    if gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
        print_warning "VM $VM_NAME already exists. Delete it first if you want to recreate."
        return 1
    fi

    get_subnet_info

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
        ${startup_script:+--metadata-from-file startup-script="$startup_script"}
}

# Display completion info
show_completion_info() {
    local vm_ip=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(networkInterfaces[0].accessConfigs[0].natIP)' 2>/dev/null)

    echo ""
    echo -e "${GREEN}✅ Deployment completed successfully!${NC}"
    echo "========================================="
    echo ""
    echo -e "${BLUE}📋 VM Details:${NC}"
    echo "  • Name: $VM_NAME"
    echo "  • Zone: $ZONE"
    echo "  • External IP: ${vm_ip:-N/A}"
    echo ""
    echo -e "${BLUE}🔗 Access Services:${NC}"
    echo "  1. Run tunnel script: ./ssh_tunnel.sh"
    echo "  2. Open web app: http://localhost:8080"
    echo "  3. API Servers: http://localhost:8001-8005"
    echo ""
    echo -e "${BLUE}🔧 Management:${NC}"
    echo "  • SSH: gcloud compute ssh $VM_NAME --zone=$ZONE"
    echo "  • Logs: gcloud compute ssh $VM_NAME --zone=$ZONE --command='docker-compose logs -f'"
    echo "  • Stop: gcloud compute instances stop $VM_NAME --zone=$ZONE"
    echo ""
}
