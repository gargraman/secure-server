#!/bin/bash

# Cleanup AI-SOAR Platform resources from Google Cloud Platform
# This script removes all resources created during deployment

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
SERVICE_ACCOUNT="ai-soar-vm@${PROJECT_ID}.iam.gserviceaccount.com"

echo -e "${BLUE}🧹 Cleaning up AI-SOAR Platform from Google Cloud${NC}"
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

# Parse command line arguments
FORCE_DELETE=false
DELETE_SECRETS=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --force)
            FORCE_DELETE=true
            shift
            ;;
        --delete-secrets)
            DELETE_SECRETS=true
            shift
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force           Skip confirmation prompts"
            echo "  --delete-secrets  Also delete secrets from Secret Manager"
            echo "  -h, --help        Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Confirmation
if [[ "$FORCE_DELETE" != true ]]; then
    echo -e "${YELLOW}⚠️  This will delete the following resources:${NC}"
    echo "  • VM instance: $VM_NAME"
    echo "  • Firewall rules: allow-ai-soar-ports"
    echo "  • Service account: $SERVICE_ACCOUNT"
    if [[ "$DELETE_SECRETS" == true ]]; then
        echo "  • All test API secrets from Secret Manager"
    fi
    echo ""
    echo -e "${YELLOW}Are you sure you want to continue? (y/N)${NC}"
    read -r response
    if [[ ! "$response" =~ ^[Yy]$ ]]; then
        echo -e "${BLUE}ℹ️  Cleanup cancelled.${NC}"
        exit 0
    fi
fi

# Check if gcloud is installed and authenticated
if ! command -v gcloud &> /dev/null; then
    print_error "Google Cloud SDK is not installed."
    exit 1
fi

if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
    print_error "Not authenticated with Google Cloud. Please run: gcloud auth login"
    exit 1
fi

# Set project
print_status "Setting Google Cloud project to $PROJECT_ID..."
gcloud config set project $PROJECT_ID

# Stop and delete VM instance
print_status "Deleting VM instance..."
if gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
    # Stop VM first
    print_status "Stopping VM instance..."
    gcloud compute instances stop $VM_NAME --zone=$ZONE --quiet

    # Delete VM
    gcloud compute instances delete $VM_NAME --zone=$ZONE --quiet
    print_status "VM instance deleted"
else
    print_status "VM instance not found"
fi

# Delete firewall rules
print_status "Deleting firewall rules..."
if gcloud compute firewall-rules describe allow-ai-soar-ports &>/dev/null; then
    gcloud compute firewall-rules delete allow-ai-soar-ports --quiet
    print_status "Firewall rules deleted"
else
    print_status "Firewall rules not found"
fi

# Delete service account
print_status "Deleting service account..."
if gcloud iam service-accounts describe $SERVICE_ACCOUNT &>/dev/null; then
    # Remove IAM policy bindings first
    for role in "roles/aiplatform.user" "roles/secretmanager.secretAccessor" "roles/logging.logWriter" "roles/monitoring.metricWriter"; do
        gcloud projects remove-iam-policy-binding $PROJECT_ID \
            --member="serviceAccount:$SERVICE_ACCOUNT" \
            --role="$role" --quiet 2>/dev/null || true
    done

    # Delete service account
    gcloud iam service-accounts delete $SERVICE_ACCOUNT --quiet
    print_status "Service account deleted"
else
    print_status "Service account not found"
fi

# Delete secrets if requested
if [[ "$DELETE_SECRETS" == true ]]; then
    print_status "Deleting secrets from Secret Manager..."

    secrets=("virustotal-api-key-test" "servicenow-auth-test" "cyberreason-token-test" "trellix-api-key-test")

    for secret in "${secrets[@]}"; do
        if gcloud secrets describe $secret &>/dev/null; then
            gcloud secrets delete $secret --quiet
            print_status "Secret $secret deleted"
        else
            print_status "Secret $secret not found"
        fi
    done
fi

# Clean up any orphaned resources
print_status "Cleaning up orphaned resources..."

# Remove any remaining disk snapshots
print_status "Checking for disk snapshots..."
snapshots=$(gcloud compute snapshots list --filter="name~ai-soar" --format="value(name)" 2>/dev/null || true)
if [[ -n "$snapshots" ]]; then
    for snapshot in $snapshots; do
        gcloud compute snapshots delete $snapshot --quiet
        print_status "Deleted snapshot: $snapshot"
    done
else
    print_status "No orphaned snapshots found"
fi

# Remove any remaining disks
print_status "Checking for orphaned disks..."
disks=$(gcloud compute disks list --filter="name~ai-soar" --format="value(name)" 2>/dev/null || true)
if [[ -n "$disks" ]]; then
    for disk in $disks; do
        gcloud compute disks delete $disk --zone=$ZONE --quiet
        print_status "Deleted disk: $disk"
    done
else
    print_status "No orphaned disks found"
fi

# Show remaining resources (if any)
print_status "Checking for any remaining AI-SOAR resources..."
echo ""
echo -e "${BLUE}🔍 Remaining resources check:${NC}"

# Check instances
remaining_instances=$(gcloud compute instances list --filter="name~ai-soar" --format="value(name)" 2>/dev/null || true)
if [[ -n "$remaining_instances" ]]; then
    echo -e "${YELLOW}  • Instances: $remaining_instances${NC}"
else
    echo -e "${GREEN}  • Instances: None${NC}"
fi

# Check firewall rules
remaining_firewall=$(gcloud compute firewall-rules list --filter="name~ai-soar" --format="value(name)" 2>/dev/null || true)
if [[ -n "$remaining_firewall" ]]; then
    echo -e "${YELLOW}  • Firewall rules: $remaining_firewall${NC}"
else
    echo -e "${GREEN}  • Firewall rules: None${NC}"
fi

# Check service accounts
remaining_sa=$(gcloud iam service-accounts list --filter="name~ai-soar" --format="value(email)" 2>/dev/null || true)
if [[ -n "$remaining_sa" ]]; then
    echo -e "${YELLOW}  • Service accounts: $remaining_sa${NC}"
else
    echo -e "${GREEN}  • Service accounts: None${NC}"
fi

# Check secrets
if [[ "$DELETE_SECRETS" == true ]]; then
    remaining_secrets=$(gcloud secrets list --filter="name~test" --format="value(name)" 2>/dev/null || true)
    if [[ -n "$remaining_secrets" ]]; then
        echo -e "${YELLOW}  • Secrets: $remaining_secrets${NC}"
    else
        echo -e "${GREEN}  • Secrets: None${NC}"
    fi
fi

echo ""
echo -e "${GREEN}✅ Cleanup completed successfully!${NC}"
echo "================================="

if [[ "$DELETE_SECRETS" != true ]]; then
    echo -e "${BLUE}ℹ️  Note: API secrets were preserved. Use --delete-secrets to remove them.${NC}"
fi

echo -e "${BLUE}💡 To disable APIs (optional):${NC}"
echo "  gcloud services disable aiplatform.googleapis.com"
echo "  gcloud services disable secretmanager.googleapis.com"
echo "  gcloud services disable logging.googleapis.com"
echo "  gcloud services disable monitoring.googleapis.com"
echo ""

print_status "🎉 All AI-SOAR resources have been cleaned up!"
