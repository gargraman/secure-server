# VM Deployment Guide - AI Cybersecurity Platform

## Prerequisites

- Google Cloud Project: `svc-hackathon-prod07`
- Vertex AI API enabled with required models
- Service account with appropriate IAM permissions
- VM instance with recommended specifications

## Step-by-Step Deployment

### 1. Create Google Cloud VM Instance

```bash
# Create VM instance
gcloud compute instances create ai-soar-vm \
    --project=svc-hackathon-prod07 \
    --zone=us-central1-a \
    --machine-type=n1-standard-4 \
    --boot-disk-size=100GB \
    --boot-disk-type=pd-ssd \
    --image-family=ubuntu-2204-lts \
    --image-project=ubuntu-os-cloud \
    --tags=http-server,https-server \
    --service-account=ai-soar-vm@svc-hackathon-prod07.iam.gserviceaccount.com \
    --scopes=https://www.googleapis.com/auth/cloud-platform

# Configure firewall rules
gcloud compute firewall-rules create allow-ai-soar-ports \
    --project=svc-hackathon-prod07 \
    --allow=tcp:80,tcp:443,tcp:8001-8005 \
    --source-ranges=0.0.0.0/0 \
    --target-tags=http-server
```

### 2. Setup Service Account & IAM

```bash
# Create service account
gcloud iam service-accounts create ai-soar-vm \
    --project=svc-hackathon-prod07 \
    --display-name="AI SOAR VM Service Account"

# Grant required permissions
gcloud projects add-iam-policy-binding svc-hackathon-prod07 \
    --member="serviceAccount:ai-soar-vm@svc-hackathon-prod07.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"

gcloud projects add-iam-policy-binding svc-hackathon-prod07 \
    --member="serviceAccount:ai-soar-vm@svc-hackathon-prod07.iam.gserviceaccount.com" \
    --role="roles/secretmanager.secretAccessor"

gcloud projects add-iam-policy-binding svc-hackathon-prod07 \
    --member="serviceAccount:ai-soar-vm@svc-hackathon-prod07.iam.gserviceaccount.com" \
    --role="roles/logging.logWriter"

gcloud projects add-iam-policy-binding svc-hackathon-prod07 \
    --member="serviceAccount:ai-soar-vm@svc-hackathon-prod07.iam.gserviceaccount.com" \
    --role="roles/monitoring.metricWriter"
```

### 3. Enable Required APIs

```bash
# Enable required Google Cloud APIs
gcloud services enable aiplatform.googleapis.com \
    secretmanager.googleapis.com \
    logging.googleapis.com \
    monitoring.googleapis.com \
    --project=svc-hackathon-prod07
```

### 4. SSH into VM and Setup Environment

```bash
# SSH into the VM
gcloud compute ssh ai-soar-vm \
    --project=svc-hackathon-prod07 \
    --zone=us-central1-a

# Download and run setup script
curl -O https://raw.githubusercontent.com/your-repo/ai-soar/main/deployment/vm-setup.sh
chmod +x vm-setup.sh
./vm-setup.sh
```

### 5. Deploy Application Code

```bash
# Navigate to application directory
cd /opt/ai-soar

# Clone your repository (replace with actual repo URL)
git clone https://github.com/your-org/ai-soar.git .

# Or copy files manually
# scp -r ./src ./deployment ./requirements.txt user@vm-ip:/opt/ai-soar/
```

### 6. Configure Secrets and Environment

```bash
# Create secrets in Secret Manager
echo "your-virustotal-api-key" | gcloud secrets create virustotal-api-key \
    --project=svc-hackathon-prod07 \
    --data-file=-

echo "your-servicenow-auth" | gcloud secrets create servicenow-auth \
    --project=svc-hackathon-prod07 \
    --data-file=-

echo "your-cyberreason-token" | gcloud secrets create cyberreason-token \
    --project=svc-hackathon-prod07 \
    --data-file=-

echo "your-trellix-api-key" | gcloud secrets create trellix-api-key \
    --project=svc-hackathon-prod07 \
    --data-file=-

# Update environment configuration
cp deployment/config/production.env .env
# Edit .env file with your specific configuration
```

### 7. Build and Start Services

```bash
# Build Docker containers
docker-compose -f deployment/docker-compose.yml build

# Start services
docker-compose -f deployment/docker-compose.yml up -d

# Check service status
docker-compose -f deployment/docker-compose.yml ps
```

### 8. Verify Deployment

```bash
# Check service health
curl http://localhost:8001/meta  # VirusTotal server
curl http://localhost:8002/meta  # ServiceNow server
curl http://localhost:8003/meta  # CyberReason server
curl http://localhost:8004/meta  # Custom REST server
curl http://localhost:8005/meta  # Cloud IVX server

# Check via external IP
curl http://$(gcloud compute instances describe ai-soar-vm --zone=us-central1-a --format='get(networkInterfaces[0].accessConfigs[0].natIP)')/health

# Check logs
docker-compose -f deployment/docker-compose.yml logs -f
```

### 9. Configure Monitoring (Optional)

```bash
# Start monitoring stack
docker-compose -f deployment/docker-compose.yml up -d prometheus

# Access Prometheus dashboard
# http://VM_EXTERNAL_IP:9090
```

## Configuration Management

### Environment Variables
Key environment variables are configured in `deployment/config/production.env`:

- `GOOGLE_CLOUD_PROJECT`: Your GCP project ID
- `AI_PROVIDER`: Set to `google_vertex_gemini`
- `VERTEX_AI_REGION`: Region for Vertex AI (us-central1)
- API keys retrieved from Secret Manager

### Vertex AI Configuration
Configure Vertex AI models in `deployment/config/vertex-ai-config.json`:

```json
{
  "project_id": "svc-hackathon-prod07",
  "location": "us-central1",
  "models": {
    "gemini": {
      "model_name": "gemini-1.5-pro",
      "parameters": {
        "max_output_tokens": 2000,
        "temperature": 0.1
      }
    }
  }
}
```

## Troubleshooting

### Common Issues

1. **Service Account Permissions**
   ```bash
   # Check service account permissions
   gcloud projects get-iam-policy svc-hackathon-prod07 \
       --flatten="bindings[].members" \
       --filter="bindings.members:ai-soar-vm@svc-hackathon-prod07.iam.gserviceaccount.com"
   ```

2. **Vertex AI API Access**
   ```bash
   # Test Vertex AI access
   gcloud ai models list --region=us-central1 --project=svc-hackathon-prod07
   ```

3. **Docker Issues**
   ```bash
   # Check Docker status
   systemctl status docker

   # Restart Docker service
   sudo systemctl restart docker

   # Check container logs
   docker-compose logs mcp-servers
   ```

4. **Port Connectivity**
   ```bash
   # Check if ports are listening
   netstat -tlnp | grep -E ':(8001|8002|8003|8004|8005)'

   # Test internal connectivity
   curl -v http://localhost:8001/meta
   ```

### Log Locations

- Application logs: `/opt/ai-soar/logs/`
- Docker logs: `docker-compose logs`
- System logs: `journalctl -u ai-soar`
- Nginx logs: `/var/log/nginx/`

### Monitoring Endpoints

- Health check: `http://VM_IP/health`
- Prometheus metrics: `http://VM_IP:9090`
- Individual service status: `http://VM_IP:800X/meta`

## Maintenance

### Regular Tasks

1. **Update Dependencies**
   ```bash
   cd /opt/ai-soar
   git pull
   pip install -r requirements.txt --upgrade
   docker-compose build --no-cache
   docker-compose up -d
   ```

2. **Backup Configuration**
   ```bash
   # Backup to Cloud Storage
   gsutil cp -r /opt/ai-soar/deployment/config gs://ai-soar-backups-prod07/config/$(date +%Y%m%d)/
   ```

3. **Log Rotation**
   ```bash
   # Logs are automatically rotated via logrotate
   # Manual log cleanup if needed
   find /opt/ai-soar/logs -name "*.log" -mtime +30 -delete
   ```

### Security Updates

1. **Update System Packages**
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Rotate API Keys**
   - Update secrets in Secret Manager
   - Restart services: `docker-compose restart`

3. **SSL Certificate Renewal** (if using HTTPS)
   ```bash
   # Renew Let's Encrypt certificates
   certbot renew
   systemctl reload nginx
   ```

## Performance Tuning

### Resource Optimization

1. **VM Scaling**
   ```bash
   # Scale up VM if needed
   gcloud compute instances stop ai-soar-vm --zone=us-central1-a
   gcloud compute instances set-machine-type ai-soar-vm \
       --machine-type=n1-standard-8 --zone=us-central1-a
   gcloud compute instances start ai-soar-vm --zone=us-central1-a
   ```

2. **Container Resources**
   - Adjust memory limits in `docker-compose.yml`
   - Monitor resource usage with `docker stats`

3. **Database Optimization** (if using Cloud SQL)
   - Monitor query performance
   - Adjust connection pooling settings

This deployment guide provides a comprehensive approach to deploying the AI cybersecurity platform on a Google Cloud VM with Vertex AI integration.
