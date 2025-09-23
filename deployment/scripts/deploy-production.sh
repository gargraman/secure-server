#!/bin/bash

# AI-SOAR Platform Production Deployment Script for Google Cloud
# This script deploys the platform to Google Cloud Run with all necessary infrastructure

set -e  # Exit on any error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
PROJECT_ID="${GOOGLE_CLOUD_PROJECT:-svc-hackathon-prod07}"
REGION="${DEPLOY_REGION:-us-central1}"
SERVICE_NAME="ai-soar-platform"
SERVICE_ACCOUNT="aisoar-service-account@${PROJECT_ID}.iam.gserviceaccount.com"
VPC_CONNECTOR="aisoar-vpc-connector"

# Script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"
DEPLOYMENT_DIR="$PROJECT_ROOT/deployment"

echo -e "${BLUE}🚀 AI-SOAR Platform Production Deployment${NC}"
echo -e "${BLUE}=========================================${NC}"

# Parse command line arguments
FORCE_REBUILD=false
SKIP_TESTS=false
DRY_RUN=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --force-rebuild)
            FORCE_REBUILD=true
            shift
            ;;
        --skip-tests)
            SKIP_TESTS=true
            shift
            ;;
        --dry-run)
            DRY_RUN=true
            shift
            ;;
        --project-id)
            PROJECT_ID="$2"
            shift 2
            ;;
        --region)
            REGION="$2"
            shift 2
            ;;
        -h|--help)
            echo "Usage: $0 [OPTIONS]"
            echo ""
            echo "Options:"
            echo "  --force-rebuild     Force rebuild of Docker image"
            echo "  --skip-tests       Skip running tests before deployment"
            echo "  --dry-run          Show what would be deployed without actually deploying"
            echo "  --project-id       Google Cloud Project ID"
            echo "  --region           Deployment region (default: us-central1)"
            echo "  -h, --help         Show this help message"
            exit 0
            ;;
        *)
            echo -e "${RED}❌ Unknown option: $1${NC}"
            exit 1
            ;;
    esac
done

# Check prerequisites
check_prerequisites() {
    echo -e "${YELLOW}📋 Checking prerequisites...${NC}"

    # Check gcloud CLI
    if ! command -v gcloud &> /dev/null; then
        echo -e "${RED}❌ gcloud CLI is not installed. Please install it first.${NC}"
        exit 1
    fi

    # Check Docker
    if ! command -v docker &> /dev/null; then
        echo -e "${RED}❌ Docker is not installed. Please install Docker first.${NC}"
        exit 1
    fi

    # Check authentication
    if ! gcloud auth list --filter=status:ACTIVE --format="value(account)" | grep -q "@"; then
        echo -e "${RED}❌ Not authenticated with gcloud. Run 'gcloud auth login' first.${NC}"
        exit 1
    fi

    # Set project
    gcloud config set project "$PROJECT_ID"

    echo -e "${GREEN}✅ Prerequisites checked${NC}"
}

# Enable required APIs
enable_apis() {
    echo -e "${YELLOW}🔧 Enabling required Google Cloud APIs...${NC}"

    local apis=(
        "run.googleapis.com"
        "cloudbuild.googleapis.com"
        "containerregistry.googleapis.com"
        "secretmanager.googleapis.com"
        "aiplatform.googleapis.com"
        "logging.googleapis.com"
        "monitoring.googleapis.com"
        "vpcaccess.googleapis.com"
    )

    for api in "${apis[@]}"; do
        echo -e "${YELLOW}  Enabling $api...${NC}"
        gcloud services enable "$api" --project="$PROJECT_ID"
    done

    echo -e "${GREEN}✅ APIs enabled${NC}"
}

# Create service account if it doesn't exist
create_service_account() {
    echo -e "${YELLOW}👤 Setting up service account...${NC}"

    # Check if service account exists
    if gcloud iam service-accounts describe "$SERVICE_ACCOUNT" --project="$PROJECT_ID" &>/dev/null; then
        echo -e "${YELLOW}📁 Service account already exists${NC}"
    else
        gcloud iam service-accounts create "aisoar-service-account" \
            --description="AI-SOAR Platform Service Account" \
            --display-name="AI-SOAR Service Account" \
            --project="$PROJECT_ID"

        echo -e "${GREEN}✅ Service account created${NC}"
    fi

    # Grant necessary roles
    local roles=(
        "roles/secretmanager.secretAccessor"
        "roles/aiplatform.user"
        "roles/logging.logWriter"
        "roles/monitoring.metricWriter"
        "roles/cloudsql.client"
    )

    for role in "${roles[@]}"; do
        gcloud projects add-iam-policy-binding "$PROJECT_ID" \
            --member="serviceAccount:$SERVICE_ACCOUNT" \
            --role="$role" \
            --quiet
    done

    echo -e "${GREEN}✅ Service account configured${NC}"
}

# Create secrets in Secret Manager
create_secrets() {
    echo -e "${YELLOW}🔐 Setting up secrets in Secret Manager...${NC}"

    local secrets=(
        "neo4j-uri"
        "neo4j-username"
        "neo4j-password"
        "virustotal-api-key"
        "servicenow-auth"
        "cyberreason-token"
        "trellix-api-key"
    )

    for secret in "${secrets[@]}"; do
        if gcloud secrets describe "$secret" --project="$PROJECT_ID" &>/dev/null; then
            echo -e "${YELLOW}  Secret $secret already exists${NC}"
        else
            echo -e "${BLUE}  Creating secret: $secret${NC}"
            echo "REPLACE_WITH_ACTUAL_VALUE" | gcloud secrets create "$secret" \
                --data-file=- \
                --project="$PROJECT_ID"
            echo -e "${YELLOW}⚠️  Please update secret '$secret' with actual value${NC}"
        fi
    done

    echo -e "${GREEN}✅ Secrets configured${NC}"
    echo -e "${YELLOW}⚠️  Remember to update all secrets with actual values!${NC}"
}

# Create VPC connector for private networking
create_vpc_connector() {
    echo -e "${YELLOW}🌐 Setting up VPC connector...${NC}"

    # Check if VPC connector exists
    if gcloud compute networks vpc-access connectors describe "$VPC_CONNECTOR" \
        --region="$REGION" --project="$PROJECT_ID" &>/dev/null; then
        echo -e "${YELLOW}📁 VPC connector already exists${NC}"
    else
        gcloud compute networks vpc-access connectors create "$VPC_CONNECTOR" \
            --region="$REGION" \
            --subnet-project="$PROJECT_ID" \
            --subnet="default" \
            --min-instances=2 \
            --max-instances=3 \
            --machine-type="e2-micro" \
            --project="$PROJECT_ID"

        echo -e "${GREEN}✅ VPC connector created${NC}"
    fi
}

# Run tests if not skipped
run_tests() {
    if [ "$SKIP_TESTS" = true ]; then
        echo -e "${YELLOW}⏭️  Skipping tests as requested${NC}"
        return
    fi

    echo -e "${YELLOW}🧪 Running tests...${NC}"

    cd "$PROJECT_ROOT"

    # Set up test environment
    export ENVIRONMENT=test
    export NEO4J_URI=neo4j://localhost:7687
    export NEO4J_USERNAME=neo4j
    export NEO4J_PASSWORD=test123
    export VERTEX_AI_ENABLED=false

    # Start test Neo4j instance
    docker run -d --name test-neo4j \
        -p 7687:7687 \
        -e NEO4J_AUTH=neo4j/test123 \
        neo4j:5.15-community

    # Wait for Neo4j to start
    sleep 30

    # Run tests
    if command -v pytest &> /dev/null; then
        python -m pytest src/ --cov=src -v
    else
        echo -e "${YELLOW}⚠️  pytest not found, skipping tests${NC}"
    fi

    # Clean up test Neo4j
    docker stop test-neo4j
    docker rm test-neo4j

    echo -e "${GREEN}✅ Tests completed${NC}"
}

# Build and push Docker image
build_and_push_image() {
    echo -e "${YELLOW}🐳 Building and pushing Docker image...${NC}"

    cd "$PROJECT_ROOT"

    local image_tag="gcr.io/$PROJECT_ID/$SERVICE_NAME:$(git rev-parse --short HEAD)"
    local latest_tag="gcr.io/$PROJECT_ID/$SERVICE_NAME:latest"

    # Configure Docker for GCR
    gcloud auth configure-docker --quiet

    # Build image
    docker build \
        --target production \
        --tag "$image_tag" \
        --tag "$latest_tag" \
        --file "$DEPLOYMENT_DIR/Dockerfile" \
        .

    # Push images
    docker push "$image_tag"
    docker push "$latest_tag"

    echo -e "${GREEN}✅ Image built and pushed: $image_tag${NC}"
    export IMAGE_TAG="$image_tag"
}

# Deploy to Cloud Run
deploy_to_cloud_run() {
    echo -e "${YELLOW}🚀 Deploying to Cloud Run...${NC}"

    if [ "$DRY_RUN" = true ]; then
        echo -e "${BLUE}🔍 DRY RUN - Would deploy with the following configuration:${NC}"
        echo "  Project: $PROJECT_ID"
        echo "  Region: $REGION"
        echo "  Service: $SERVICE_NAME"
        echo "  Image: $IMAGE_TAG"
        echo "  Service Account: $SERVICE_ACCOUNT"
        echo "  VPC Connector: $VPC_CONNECTOR"
        return
    fi

    gcloud run deploy "$SERVICE_NAME" \
        --image="$IMAGE_TAG" \
        --region="$REGION" \
        --platform=managed \
        --allow-unauthenticated \
        --memory=4Gi \
        --cpu=2 \
        --max-instances=10 \
        --min-instances=1 \
        --port=8080 \
        --timeout=300s \
        --concurrency=100 \
        --execution-environment=gen2 \
        --service-account="$SERVICE_ACCOUNT" \
        --vpc-connector="$VPC_CONNECTOR" \
        --vpc-egress=private-ranges-only \
        --set-env-vars="ENVIRONMENT=production,GOOGLE_CLOUD_PROJECT=$PROJECT_ID,VERTEX_AI_LOCATION=$REGION,VERTEX_AI_ENABLED=true,SECRET_MANAGER_ENABLED=true,LOG_LEVEL=INFO,METRICS_ENABLED=true" \
        --project="$PROJECT_ID"

    echo -e "${GREEN}✅ Deployed to Cloud Run${NC}"
}

# Run post-deployment tests
run_post_deployment_tests() {
    if [ "$DRY_RUN" = true ]; then
        echo -e "${BLUE}🔍 DRY RUN - Would run post-deployment tests${NC}"
        return
    fi

    echo -e "${YELLOW}🧪 Running post-deployment tests...${NC}"

    # Get service URL
    local service_url=$(gcloud run services describe "$SERVICE_NAME" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format="value(status.url)")

    echo -e "${BLUE}Service URL: $service_url${NC}"

    # Wait for service to be ready
    sleep 30

    # Test health endpoints
    if curl -f "$service_url/health" &>/dev/null; then
        echo -e "${GREEN}✅ Health check passed${NC}"
    else
        echo -e "${RED}❌ Health check failed${NC}"
        exit 1
    fi

    # Test API endpoints
    if curl -f "$service_url/api/health/detailed" &>/dev/null; then
        echo -e "${GREEN}✅ Detailed health check passed${NC}"
    else
        echo -e "${RED}❌ Detailed health check failed${NC}"
        exit 1
    fi

    # Test meta endpoint
    if curl -f "$service_url/meta" &>/dev/null; then
        echo -e "${GREEN}✅ Meta endpoint check passed${NC}"
    else
        echo -e "${RED}❌ Meta endpoint check failed${NC}"
        exit 1
    fi

    echo -e "${GREEN}✅ Post-deployment tests completed${NC}"
}

# Display deployment information
display_deployment_info() {
    echo -e "${BLUE}🎉 Deployment Complete!${NC}"
    echo -e "${BLUE}======================${NC}"
    echo ""

    if [ "$DRY_RUN" = true ]; then
        echo -e "${YELLOW}This was a dry run. No actual deployment was performed.${NC}"
        return
    fi

    local service_url=$(gcloud run services describe "$SERVICE_NAME" \
        --region="$REGION" \
        --project="$PROJECT_ID" \
        --format="value(status.url)")

    echo -e "${GREEN}🌐 Service Information:${NC}"
    echo -e "  • Service URL:         ${YELLOW}$service_url${NC}"
    echo -e "  • API Documentation:   ${YELLOW}$service_url/docs${NC}"
    echo -e "  • Health Check:        ${YELLOW}$service_url/health${NC}"
    echo -e "  • Service Meta:        ${YELLOW}$service_url/meta${NC}"
    echo ""
    echo -e "${GREEN}🔧 Management Commands:${NC}"
    echo -e "  • View logs:           ${YELLOW}gcloud run services logs read $SERVICE_NAME --region=$REGION${NC}"
    echo -e "  • Update service:      ${YELLOW}gcloud run services update $SERVICE_NAME --region=$REGION${NC}"
    echo -e "  • Scale service:       ${YELLOW}gcloud run services update $SERVICE_NAME --max-instances=20 --region=$REGION${NC}"
    echo ""
    echo -e "${GREEN}📊 Monitoring:${NC}"
    echo -e "  • Cloud Run Console:   ${YELLOW}https://console.cloud.google.com/run/detail/$REGION/$SERVICE_NAME${NC}"
    echo -e "  • Cloud Logging:       ${YELLOW}https://console.cloud.google.com/logs/query${NC}"
    echo ""
    echo -e "${BLUE}🎯 Next Steps:${NC}"
    echo -e "  1. Update secrets in Secret Manager with actual values"
    echo -e "  2. Configure Neo4j AuraDB connection"
    echo -e "  3. Set up monitoring and alerting"
    echo -e "  4. Configure domain and SSL certificate"
    echo -e "  5. Set up backup and disaster recovery"
    echo ""
    echo -e "${GREEN}Deployment successful! 🚀${NC}"
}

# Cleanup function
cleanup_on_error() {
    echo -e "${RED}❌ Deployment failed. Check the logs above for details.${NC}"
    exit 1
}

# Set trap for cleanup on error
trap cleanup_on_error ERR

# Main execution
main() {
    echo -e "${BLUE}Project ID: $PROJECT_ID${NC}"
    echo -e "${BLUE}Region: $REGION${NC}"
    echo -e "${BLUE}Service: $SERVICE_NAME${NC}"
    echo ""

    check_prerequisites
    enable_apis
    create_service_account
    create_secrets
    create_vpc_connector
    run_tests
    build_and_push_image
    deploy_to_cloud_run
    run_post_deployment_tests
    display_deployment_info
}

# Run main function
main "$@"
