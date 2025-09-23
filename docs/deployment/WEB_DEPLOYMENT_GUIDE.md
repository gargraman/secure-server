# AI SOAR Platform - Web Application Deployment Guide

This guide covers deploying the AI-driven cybersecurity automation platform as a web application using Docker containers.

## Overview

The deployment consists of the following services:
- **MCP Servers**: Five FastAPI servers providing cybersecurity services (ports 8001-8005)
- **Web Application**: FastAPI web interface (port 8080)
- **Nginx Proxy**: Reverse proxy and load balancer (ports 80/443)
- **Monitoring**: Prometheus metrics collection (port 9090)
- **Logging**: Fluentd log aggregation (port 24224)

## Prerequisites

- Docker Engine 20.10+ and Docker Compose 2.0+
- Minimum 4GB RAM and 2 CPU cores
- Google Cloud credentials (for AI providers)
- API keys for external services (VirusTotal, ServiceNow, etc.)

## Quick Start

### 1. Build and Deploy

```bash
# Make the deployment script executable
chmod +x deployment/docker-run.sh

# Build and start all services
./deployment/docker-run.sh

# Or with options
./deployment/docker-run.sh --dev --logs
```

### 2. Access the Application

- **Web Interface**: http://localhost
- **Direct Web App**: http://localhost:8080
- **API Documentation**: http://localhost:8001/docs (and 8002-8005)
- **Monitoring**: http://localhost:9090

## Deployment Options

### Production Deployment

```bash
cd deployment/
docker-compose up -d
```

This uses the production configuration with:
- AI Provider: Google Vertex AI Gemini
- Environment: production
- Debug: false
- Health checks enabled
- Log aggregation via Fluentd

### Development Deployment

```bash
cd deployment/
docker-compose -f docker-compose.yml -f docker-compose.dev.yml up -d
```

Development mode includes:
- Live code reload
- Debug logging enabled
- Development database (PostgreSQL)
- Development cache (Redis)
- More permissive CORS settings

### Staging Deployment

```bash
cd deployment/
docker-compose --env-file config/staging.env up -d
```

## Configuration

### Environment Files

- `config/production.env`: Production settings
- `config/staging.env`: Staging/testing settings
- `config/vertex-ai-config.json`: Google Cloud AI configuration

### Key Configuration Options

```bash
# AI Provider Selection
AI_PROVIDER=google_vertex_gemini  # or aws_bedrock, google_vertex

# Google Cloud Settings
GOOGLE_CLOUD_PROJECT=your-project-id
VERTEX_AI_REGION=us-central1

# Application Settings
ENVIRONMENT=production
DEBUG=false
LOG_LEVEL=INFO
```

### Secrets Management

Store sensitive data in Docker secrets or volume mounts:

```bash
# Create secrets directory
mkdir -p deployment/secrets

# Add API keys (never commit these!)
echo "your-virustotal-key" > deployment/secrets/virustotal-api-key
echo "your-servicenow-token" > deployment/secrets/servicenow-auth
```

## Service Architecture

```
Internet → Nginx (80/443) → Web App (8080)
                          ↓
                     MCP Servers (8001-8005)
                          ↓
              External APIs (VirusTotal, ServiceNow, etc.)
```

### Container Details

| Service | Container | Ports | Purpose |
|---------|-----------|-------|---------|
| nginx | nginx-proxy | 80, 443 | Reverse proxy, SSL termination |
| web-app | web-app | 8080 | FastAPI web interface |
| mcp-servers | mcp-servers | 8001-8005 | Cybersecurity API services |
| prometheus | prometheus | 9090 | Metrics collection |
| fluentd | fluentd | 24224 | Log aggregation |

## Health Checks

All services include comprehensive health checks:

```bash
# Check individual service health
curl http://localhost:8080/health      # Web application
curl http://localhost:8001/meta        # VirusTotal server
curl http://localhost/health           # Nginx proxy

# View all container status
docker-compose ps
```

## Monitoring and Logging

### Prometheus Metrics

Access metrics at http://localhost:9090

Key metrics:
- Request counts and latencies
- Error rates by service
- System resource usage
- External API response times

### Log Aggregation

Logs are collected by Fluentd and can be forwarded to external systems:

```bash
# View aggregated logs
docker-compose logs -f

# View specific service logs
docker-compose logs web-app
docker-compose logs mcp-servers
```

## Scaling and Performance

### Horizontal Scaling

Scale individual services:

```bash
# Scale MCP servers
docker-compose up -d --scale mcp-servers=3

# Scale with load balancing
docker-compose -f docker-compose.yml -f docker-compose.scale.yml up -d
```

### Resource Limits

Configure resource limits in docker-compose.yml:

```yaml
services:
  web-app:
    deploy:
      resources:
        limits:
          cpus: '2.0'
          memory: 2G
        reservations:
          cpus: '1.0'
          memory: 1G
```

## Troubleshooting

### Common Issues

1. **Services not starting**
   ```bash
   # Check container logs
   docker-compose logs <service-name>

   # Verify resource availability
   docker system df
   docker system prune -f
   ```

2. **Health check failures**
   ```bash
   # Test health endpoints directly
   curl -v http://localhost:8080/health

   # Check service dependencies
   docker-compose ps
   ```

3. **Google Cloud authentication**
   ```bash
   # Verify service account key
   cat deployment/config/service-account.json

   # Test credentials
   docker-compose exec web-app gcloud auth list
   ```

### Performance Tuning

1. **Nginx Configuration**
   - Edit `deployment/nginx/nginx.conf`
   - Adjust worker processes and connections
   - Configure caching and compression

2. **Database Optimization**
   - Use connection pooling
   - Configure appropriate buffer sizes
   - Enable query optimization

3. **Resource Monitoring**
   ```bash
   # Monitor resource usage
   docker stats

   # Check system metrics
   curl http://localhost:9090/metrics
   ```

## Security Considerations

### Network Security

- Services communicate via internal Docker network
- External access only through Nginx proxy
- API rate limiting configured
- CORS policies enforced

### Secrets Management

- Never commit sensitive data to repository
- Use Docker secrets or external secret management
- Rotate API keys regularly
- Monitor access logs

### SSL/TLS Configuration

Enable HTTPS in production:

```bash
# Generate SSL certificates
./deployment/scripts/generate-ssl.sh

# Update nginx configuration
# Uncomment HTTPS server block in nginx.conf
```

## Backup and Recovery

### Automated Backups

Configure automated backups in production.env:

```bash
BACKUP_ENABLED=true
BACKUP_BUCKET=your-backup-bucket
BACKUP_SCHEDULE="0 2 * * *"  # Daily at 2 AM
```

### Manual Backup

```bash
# Create application data backup
./deployment/scripts/backup.sh

# Backup configuration
tar -czf config-backup.tar.gz deployment/config/ deployment/secrets/
```

### Recovery Process

```bash
# Stop services
docker-compose down

# Restore data
./deployment/scripts/restore.sh backup-file.tar.gz

# Restart services
docker-compose up -d
```

## Maintenance

### Updates and Patches

```bash
# Pull latest images
docker-compose pull

# Rebuild with updates
./deployment/docker-run.sh --no-cache

# Zero-downtime update (advanced)
./deployment/scripts/rolling-update.sh
```

### Database Maintenance

```bash
# Database backup
docker-compose exec dev-db pg_dump -U soar_user ai_soar_dev > backup.sql

# Database optimization
docker-compose exec dev-db psql -U soar_user -d ai_soar_dev -c "VACUUM ANALYZE;"
```

## Support and Documentation

- **API Documentation**: Available at each service's `/docs` endpoint
- **Health Status**: Monitor via `/health` and `/meta` endpoints
- **Logs**: Centralized logging via Fluentd
- **Metrics**: Prometheus metrics for monitoring

For additional support, check the main project documentation and GitHub issues.
