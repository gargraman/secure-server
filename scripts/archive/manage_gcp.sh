#!/bin/bash

# GCP Management Script for AI-SOAR Platform
# Unified script for cleanup, status, and maintenance operations

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/common.sh"

OPERATION=""
FORCE=false
DELETE_SECRETS=false

show_help() {
    echo "Usage: $0 OPERATION [OPTIONS]"
    echo ""
    echo "Operations:"
    echo "  cleanup         Delete all AI-SOAR resources"
    echo "  status          Show current deployment status"
    echo "  restart         Restart VM and services"
    echo "  logs            Show VM logs"
    echo "  tunnel          Create SSH tunnels"
    echo "  connect         SSH to VM"
    echo ""
    echo "Options:"
    echo "  --force         Skip confirmations"
    echo "  --delete-secrets Delete API secrets too"
    echo "  --project ID    Override project ID"
    echo "  --vm-name NAME  Override VM name"
    echo "  --zone ZONE     Override zone"
    echo "  -h, --help      Show this help"
}

while [[ $# -gt 0 ]]; do
    case $1 in
        cleanup|status|restart|logs|tunnel|connect)
            OPERATION="$1"
            shift
            ;;
        --force)
            FORCE=true
            shift
            ;;
        --delete-secrets)
            DELETE_SECRETS=true
            shift
            ;;
        --project)
            PROJECT_ID="$2"
            SERVICE_ACCOUNT="ai-soar-vm@${PROJECT_ID}.iam.gserviceaccount.com"
            shift 2
            ;;
        --vm-name)
            VM_NAME="$2"
            shift 2
            ;;
        --zone)
            ZONE="$2"
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

if [[ -z "$OPERATION" ]]; then
    echo -e "${RED}❌ Operation required${NC}"
    show_help
    exit 1
fi

case $OPERATION in
    "cleanup")
        echo -e "${BLUE}🧹 Cleaning up AI-SOAR Platform${NC}"

        if [[ "$FORCE" != true ]]; then
            echo -e "${YELLOW}⚠️  This will delete:${NC}"
            echo "  • VM: $VM_NAME"
            echo "  • Firewall rules: allow-ai-soar-ports"
            echo "  • Service account: $SERVICE_ACCOUNT"
            [[ "$DELETE_SECRETS" == true ]] && echo "  • API secrets"
            echo ""
            echo -e "${YELLOW}Continue? (y/N)${NC}"
            read -r response
            [[ ! "$response" =~ ^[Yy]$ ]] && exit 0
        fi

        check_requirements
        gcloud config set project $PROJECT_ID

        # Delete VM
        if gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
            print_status "Deleting VM..."
            gcloud compute instances delete $VM_NAME --zone=$ZONE --quiet
        fi

        # Delete firewall rules
        if gcloud compute firewall-rules describe allow-ai-soar-ports &>/dev/null; then
            print_status "Deleting firewall rules..."
            gcloud compute firewall-rules delete allow-ai-soar-ports --quiet
        fi

        # Delete service account
        if gcloud iam service-accounts describe $SERVICE_ACCOUNT &>/dev/null; then
            print_status "Removing IAM bindings..."
            for role in "roles/aiplatform.user" "roles/secretmanager.secretAccessor" "roles/logging.logWriter" "roles/monitoring.metricWriter"; do
                gcloud projects remove-iam-policy-binding $PROJECT_ID \
                    --member="serviceAccount:$SERVICE_ACCOUNT" \
                    --role="$role" --quiet 2>/dev/null || true
            done

            print_status "Deleting service account..."
            gcloud iam service-accounts delete $SERVICE_ACCOUNT --quiet
        fi

        # Delete secrets if requested
        if [[ "$DELETE_SECRETS" == true ]]; then
            print_status "Deleting secrets..."
            for secret in "virustotal-api-key-test" "servicenow-auth-test" "cyberreason-token-test" "trellix-api-key-test"; do
                gcloud secrets delete $secret --quiet 2>/dev/null || true
            done
        fi

        print_status "✅ Cleanup completed"
        ;;

    "status")
        echo -e "${BLUE}📊 AI-SOAR Platform Status${NC}"

        check_requirements
        gcloud config set project $PROJECT_ID

        # VM status
        if gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
            VM_STATUS=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(status)')
            VM_IP=$(gcloud compute instances describe $VM_NAME --zone=$ZONE --format='get(networkInterfaces[0].accessConfigs[0].natIP)')
            echo -e "${GREEN}✅ VM: $VM_NAME ($VM_STATUS, IP: $VM_IP)${NC}"
        else
            echo -e "${RED}❌ VM: $VM_NAME (Not Found)${NC}"
        fi

        # Firewall status
        if gcloud compute firewall-rules describe allow-ai-soar-ports &>/dev/null; then
            echo -e "${GREEN}✅ Firewall: allow-ai-soar-ports${NC}"
        else
            echo -e "${YELLOW}⚠️  Firewall: Not configured (SSH tunneling required)${NC}"
        fi

        # Service account status
        if gcloud iam service-accounts describe $SERVICE_ACCOUNT &>/dev/null; then
            echo -e "${GREEN}✅ Service Account: $SERVICE_ACCOUNT${NC}"
        else
            echo -e "${RED}❌ Service Account: Not Found${NC}"
        fi

        # Secret status
        echo -e "${BLUE}🔐 API Secrets:${NC}"
        for secret in "virustotal-api-key-test" "servicenow-auth-test" "cyberreason-token-test" "trellix-api-key-test"; do
            if gcloud secrets describe $secret &>/dev/null; then
                echo -e "${GREEN}  ✅ $secret${NC}"
            else
                echo -e "${YELLOW}  ⚠️  $secret (not configured)${NC}"
            fi
        done
        ;;

    "restart")
        echo -e "${BLUE}🔄 Restarting AI-SOAR Platform${NC}"

        check_requirements
        gcloud config set project $PROJECT_ID

        if gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
            print_status "Restarting VM..."
            gcloud compute instances stop $VM_NAME --zone=$ZONE
            sleep 10
            gcloud compute instances start $VM_NAME --zone=$ZONE
            print_status "VM restarted"
        else
            print_error "VM not found"
            exit 1
        fi
        ;;

    "logs")
        check_requirements
        gcloud config set project $PROJECT_ID

        print_status "Fetching VM logs..."
        gcloud compute instances get-serial-port-output $VM_NAME --zone=$ZONE
        ;;

    "tunnel")
        check_requirements

        if ! gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
            print_error "VM not found"
            exit 1
        fi

        create_tunnel_script "ssh_tunnel.sh"
        print_status "Created tunnel script: ssh_tunnel.sh"
        echo "Run: ./ssh_tunnel.sh"
        ;;

    "connect")
        check_requirements

        if ! gcloud compute instances describe $VM_NAME --zone=$ZONE &>/dev/null; then
            print_error "VM not found"
            exit 1
        fi

        print_status "Connecting to VM..."
        gcloud compute ssh $VM_NAME --zone=$ZONE
        ;;

    *)
        echo -e "${RED}❌ Unknown operation: $OPERATION${NC}"
        show_help
        exit 1
        ;;
esac
