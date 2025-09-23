## Monitoring and Management

### Health Checks

```bash
# Check node status
docker compose -p ai-soar-messaging ps

```

### Performance Monitoring

Access metrics through:
- Admin API: http://localhost:19644/metrics
- Prometheus metrics endpoint available

## Troubleshooting

### Common Issues

1. **Cluster not starting**
   ```bash
   # Check Docker daemon
   docker info

   # Check port conflicts
   netstat -tuln | grep -E '(19092|29092|39092|8088)'

   # Clean start
   ./scripts/stop_messaging_infra.sh --clean
   ./scripts/start_messaging_infra.sh
   ```

## Production Considerations

For production deployment:
- Use external load balancer for broker access
- Configure authentication and SSL/TLS
- Set up monitoring with Prometheus/Grafana
- Configure proper retention policies
- Use dedicated storage volumes
- Set resource limits and requests

## VM Deployment

For VM deployment, ensure:
- Docker and Docker Compose installed
- Sufficient resources (minimum 4GB RAM, 2 CPU cores)
- Ports 8088, 19092, 29092, 39092 accessible
- Firewall rules configured appropriately
