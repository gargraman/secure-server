# VM Deployment Strategy for AI Cybersecurity Platform

## Overview
Deploy the MCP-based cybersecurity platform on Google Cloud VM with Vertex AI integration.

**Project ID**: `svc-hackathon-prod07`
**Region**: `us-central1`

## VM Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Google Cloud VM                          │
│                                                             │
│  ┌─────────────────┐  ┌─────────────────┐                  │
│  │   Docker        │  │   Vertex AI     │                  │
│  │   Containers    │  │   Integration   │                  │
│  │                 │  │                 │                  │
│  │ ┌─────────────┐ │  │ • Claude 3.5    │                  │
│  │ │ MCP Servers │ │  │ • Gemini 1.5    │                  │
│  │ │   :8001-5   │ │  │ • API Gateway   │                  │
│  │ └─────────────┘ │  │                 │                  │
│  │ ┌─────────────┐ │  └─────────────────┘                  │
│  │ │ Desktop App │ │                                       │
│  │ │   :3000     │ │  ┌─────────────────┐                  │
│  │ └─────────────┘ │  │   Data Storage  │                  │
│  │ ┌─────────────┐ │  │                 │                  │
│  │ │   Nginx     │ │  │ • Local Files   │                  │
│  │ │   :80/443   │ │  │ • SQLite/JSON   │                  │
│  │ └─────────────┘ │  │ • Event Logs    │                  │
│  └─────────────────┘  └─────────────────┘                  │
└─────────────────────────────────────────────────────────────┘
```

## VM Specifications

### Recommended VM Configuration
- **Machine Type**: `n1-standard-4` (4 vCPUs, 15 GB memory)
- **Boot Disk**: 100 GB SSD persistent disk
- **OS**: Ubuntu 22.04 LTS
- **Network**: Allow HTTP/HTTPS traffic
- **Service Account**: With Vertex AI access

### Minimum Requirements
- **Machine Type**: `e2-standard-2` (2 vCPUs, 8 GB memory)
- **Boot Disk**: 50 GB SSD persistent disk

## Deployment Components

### 1. MCP Servers (Docker Containers)
- VirusTotal Server (Port 8001)
- ServiceNow Server (Port 8002)
- CyberReason Server (Port 8003)
- Custom REST Server (Port 8004)
- Cloud IVX Server (Port 8005)

### 2. Web Interface
- Nginx reverse proxy (Port 80/443)
- SSL/TLS termination
- Static file serving

### 3. AI Integration
- Vertex AI Python SDK
- Service account authentication
- Regional endpoint configuration

### 4. Data Persistence
- Local SQLite database for audit logs
- JSON files for configuration
- File-based event storage
- Automatic backups to Cloud Storage

## Security Configuration

### Firewall Rules
- SSH (Port 22): Admin access only
- HTTP (Port 80): Public access
- HTTPS (Port 443): Public access
- Custom ports (8001-8005): Internal only

### Authentication
- Service account with minimal required permissions
- API keys stored in environment variables
- SSL certificates for HTTPS

### Required IAM Permissions
```
- aiplatform.endpoints.predict
- aiplatform.models.predict
- storage.objects.create
- storage.objects.get
- secretmanager.versions.access
```
