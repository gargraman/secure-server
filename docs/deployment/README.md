# AI SOAR Platform - Web Application Deployment

This directory contains all the necessary files and scripts to deploy the AI-driven cybersecurity automation platform as a containerized web application with Google Cloud Vertex AI integration.

## 📁 Directory Structure

```
deployment/
├── README.md                    # This file
├── VM_DEPLOYMENT_STRATEGY.md    # Architecture and deployment strategy
├── DEPLOYMENT_GUIDE.md          # Step-by-step deployment guide
├── Dockerfile                   # Multi-stage Docker build (web app + MCP servers)
├── docker-compose.yml           # Service orchestration
├── docker-compose.dev.yml       # Development environment overrides
├── docker-run.sh                # Automated deployment script
├── start_servers.py             # Container startup script
├── vm-setup.sh                  # VM environment setup script
├── WEB_DEPLOYMENT_GUIDE.md      # Comprehensive web deployment guide
├── config/                      # Configuration files
│   ├── production.env           # Production environment variables
│   └── vertex-ai-config.json    # Vertex AI model configuration
├── nginx/                       # Nginx reverse proxy configuration
│   ├── nginx.conf               # Main nginx configuration
│   └── proxy_params             # Proxy parameter includes
├── monitoring/                  # Monitoring and metrics
│   └── prometheus.yml           # Prometheus configuration
├── logging/                     # Log management
│   ├── Dockerfile               # Fluentd image build
│   └── fluent.conf              # Log aggregation configuration
└── scripts/                     # Utility scripts
    ├── health-check.sh          # Service health monitoring
    └── backup.sh                # Automated backup script
```

## 🚀 Quick Start

1. **Prerequisites**:
   - Docker Engine 20.10+ and Docker Compose 2.0+
   - Google Cloud credentials configured
   - 4GB+ RAM and 2+ CPU cores

2. **One-Command Deployment**:
   ```bash
   # Make script executable and deploy
   chmod +x deployment/docker-run.sh
   ./deployment/docker-run.sh
   ```

3. **Access Web Application**:
   - **Web Interface**: http://localhost
   - **Direct Access**: http://localhost:8080
   - **API Docs**: http://localhost:8001/docs

4. **Development Mode**:
   ```bash
   # Deploy with live reload and debugging
   ./deployment/docker-run.sh --dev --logs
   ```

## 🔧 Configuration

### Environment Variables
Copy `.env.template` to `.env` and update with your specific values:
- Google Cloud project details
- API keys and authentication tokens
- Server ports and networking configuration

### Vertex AI Setup
Update `config/vertex-ai-config.json` with your model preferences:
- Gemini 1.5 Pro (primary)
- Claude 3.5 Sonnet (backup)
- Regional endpoints and quotas

## 📊 Monitoring

### Health Checks
- Automated health monitoring: `scripts/health-check.sh`
- Service endpoints: `http://VM_IP:800X/meta`
- Nginx status: `http://VM_IP/health`

### Metrics Collection
- Prometheus metrics: `http://VM_IP:9090`
- Google Cloud Logging integration
- Container and system metrics

## 🔒 Security

### Authentication
- Google Cloud service account authentication
- API keys stored in Secret Manager
- Firewall rules for controlled access

### Network Security
- Nginx reverse proxy with rate limiting
- VPC networking for internal services
- SSL/TLS support ready

## 🛠️ Maintenance

### Regular Tasks
- Health monitoring: `./scripts/health-check.sh`
- Automated backups: `./scripts/backup.sh`
- Log rotation via logrotate
- System updates and security patches

### Troubleshooting
- Check service logs: `docker-compose logs`
- Monitor system resources: `htop`, `df -h`
- Validate configuration: `docker-compose config`

## 📋 Services Overview

| Service | Port | Description |
|---------|------|-------------|
| **Web Application** | 8080 | FastAPI web interface |
| VirusTotal Server | 8001 | IP/domain reputation lookups |
| ServiceNow Server | 8002 | Incident and task management |
| CyberReason Server | 8003 | Endpoint status and threat detection |
| Custom REST Server | 8004 | Generic REST API wrapper |
| Cloud IVX Server | 8005 | Trellix threat intelligence |
| Nginx Proxy | 80/443 | Reverse proxy and load balancer |
| Prometheus | 9090 | Metrics collection (optional) |

## 🔄 CI/CD Integration

The deployment is designed to support:
- Automated testing with GitHub Actions
- Blue-green deployments
- Configuration management
- Monitoring and alerting

## 📞 Support

For deployment issues:
1. Check the DEPLOYMENT_GUIDE.md for troubleshooting
2. Review service logs and health checks
3. Validate Google Cloud permissions and quotas
4. Ensure Vertex AI models are enabled and accessible

## 🏷️ Version

- **Platform Version**: 1.0.0
- **Docker Compose Version**: 3.8
- **Target Environment**: Google Cloud VM with Vertex AI
- **Project**: svc-hackathon-prod07
