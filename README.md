# Stellar Security Scanner Backend

A Kubernetes-based backend service for running isolated, ephemeral security scans of Stellar smart contracts.

## Architecture Overview

This backend provides a secure, scalable platform for running security scans in isolated Kubernetes pods, preventing cross-tenant data leakage and ensuring resource isolation.

## Key Features

### 🔒 **Security & Isolation**
- **Ephemeral Pods**: Each scan runs in a dedicated, temporary namespace
- **Resource Quotas**: Strict CPU/RAM limits prevent "greedy" contracts
- **Network Policies**: All egress traffic blocked from scanner pods
- **Encrypted Volumes**: All data-at-rest is encrypted
- **Pod Cleanup**: Automatic cleanup after scan completion or timeout

### 📊 **Scalability & Performance**
- **Auto-scaling**: Handles sudden spikes in scan requests
- **Queue Management**: Priority-based scan queue with metrics
- **Real-time Logs**: Sidecar containers stream logs to main API
- **Monitoring**: Comprehensive Prometheus metrics and health checks

### 🛠️ **Developer Experience**
- **REST API**: Clean, well-documented API endpoints
- **Authentication**: JWT-based authentication system
- **Docker Support**: Containerized deployment
- **Helm Charts**: Easy Kubernetes deployment

## Quick Start

### Prerequisites

- Kubernetes cluster (v1.28+)
- Helm 3.x
- Docker
- Rust 1.70+ (for development)

### Installation

1. **Clone the repository**
   ```bash
   git clone https://github.com/frankosakwe/soroban-security-scanner
   cd stellar-security-scanner-backend
   ```

2. **Build and push Docker image**
   ```bash
   docker build -t stellar-security-scanner-backend:latest .
   docker push stellar-security-scanner-backend:latest
   ```

3. **Install via Helm**
   ```bash
   helm install stellar-scanner ./helm \
     --namespace stellar-scanner \
     --create-namespace \
     --set secrets.encryptionKey="your-32-char-encryption-key" \
     --set secrets.jwtSecret="your-jwt-secret" \
     --set secrets.databaseUrl="postgresql://user:pass@db/stellar_scanner" \
     --set secrets.redisUrl="redis://pass@redis/stellar_scanner"
   ```

4. **Verify installation**
   ```bash
   kubectl get pods -n stellar-scanner
   kubectl port-forward svc/stellar-scanner-backend 8080:80 -n stellar-scanner
   curl http://localhost:8080/health
   ```

## API Documentation

### Authentication

All API endpoints (except `/health` and `/metrics`) require authentication.

**Login**
```bash
curl -X POST http://localhost:8080/auth/login \
  -H "Content-Type: application/json" \
  -d '{
    "email": "admin@stellar-scanner.io",
    "password": "admin123"
  }'
```

### Scan Management

**Create Scan**
```bash
curl -X POST http://localhost:8080/api/v1/scans \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "repository_url": "https://github.com/user/soroban-contract",
    "branch": "main",
    "scan_types": ["Security", "Invariants"],
    "resource_limits": {
      "cpu_millis": 1000,
      "memory_mb": 2048,
      "storage_mb": 1024
    },
    "timeout_minutes": 30
  }'
```

**Get Scan Status**
```bash
curl -X GET http://localhost:8080/api/v1/scans/{scan_id} \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Get Scan Logs**
```bash
curl -X GET "http://localhost:8080/api/v1/scans/{scan_id}/logs?lines=100" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Get Scan Results**
```bash
curl -X GET http://localhost:8080/api/v1/scans/{scan_id}/results \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**List Scans**
```bash
curl -X GET "http://localhost:8080/api/v1/scans?limit=50&offset=0" \
  -H "Authorization: Bearer YOUR_TOKEN"
```

### Monitoring

**Queue Metrics**
```bash
curl -X GET http://localhost:8080/api/v1/queue/metrics \
  -H "Authorization: Bearer YOUR_TOKEN"
```

**Prometheus Metrics**
```bash
curl http://localhost:8080/metrics
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SERVER_PORT` | Server port | `8080` |
| `KUBERNETES_NAMESPACE` | Kubernetes namespace | `stellar-scanner` |
| `SCANNER_IMAGE` | Scanner container image | `stellar-security-scanner:latest` |
| `DEFAULT_CPU_MILLIS` | Default CPU limit (millis) | `1000` |
| `DEFAULT_MEMORY_MB` | Default memory limit (MB) | `2048` |
| `DEFAULT_STORAGE_MB` | Default storage limit (MB) | `1024` |
| `MAX_CONCURRENT_SCANS` | Maximum concurrent scans | `10` |
| `CLEANUP_INTERVAL_MINUTES` | Cleanup interval (minutes) | `5` |
| `AUTO_SCALE_ENABLED` | Enable auto-scaling | `true` |
| `ENCRYPTION_KEY` | 32-char encryption key | Required |
| `JWT_SECRET` | JWT signing secret | Required |
| `DATABASE_URL` | PostgreSQL connection string | Required |
| `REDIS_URL` | Redis connection string | Required |

### Helm Values

See `helm/values.yaml` for complete configuration options.

## Security Features

### Namespace Isolation

Each scan runs in its own namespace with:
- Unique namespace name: `scan-{uuid}`
- Resource quotas preventing resource abuse
- Network policies blocking all egress traffic
- Encrypted persistent volumes

### Resource Quotas

```yaml
hard:
  requests.cpu: "1000m"
  requests.memory: "2048Mi"
  limits.cpu: "1000m"
  limits.memory: "2048Mi"
  pods: "1"
  requests.storage: "1024Mi"
  persistentvolumeclaims: "1"
```

### Network Policies

```yaml
spec:
  podSelector: {}
  policyTypes: ["Egress"]
  egress: []  # No egress allowed
```

### Encrypted Storage

All scan data is stored on encrypted volumes using:
- AWS EBS with encryption enabled
- Kubernetes StorageClass with encrypted parameter
- Application-level encryption for sensitive data

## Monitoring & Observability

### Prometheus Metrics

- `stellar_scanner_scan_requests_total` - Total scan requests
- `stellar_scanner_scan_duration_seconds` - Scan duration histogram
- `stellar_scanner_active_scans` - Currently active scans
- `stellar_scanner_queued_scans` - Queued scans
- `stellar_scanner_kubernetes_api_requests_total` - K8s API requests
- `stellar_scanner_scan_errors_total` - Scan errors
- `stellar_scanner_memory_usage_bytes` - Memory usage
- `stellar_scanner_cpu_usage_percent` - CPU usage

### Health Checks

- `/health` - Application health status
- Kubernetes liveness and readiness probes
- Database and Redis connection health
- Kubernetes API connectivity

### Logging

- Structured logging with tracing
- Log streaming via sidecar containers
- Centralized log collection
- Request/response logging middleware

## Development

### Local Development

1. **Install dependencies**
   ```bash
   cargo build
   ```

2. **Run tests**
   ```bash
   cargo test
   ```

3. **Run locally**
   ```bash
   export KUBECONFIG=~/.kube/config
   export ENCRYPTION_KEY="dev-32-char-encryption-key"
   export JWT_SECRET="dev-jwt-secret"
   export DATABASE_URL="postgresql://localhost/stellar_scanner"
   export REDIS_URL="redis://localhost"
   
   cargo run
   ```

### Project Structure

```
src/
├── main.rs              # Application entry point
├── config.rs            # Configuration management
├── k8s.rs               # Kubernetes client and operations
├── models.rs            # Data models and API types
├── scanner.rs           # Scan queue and management
├── auth.rs              # Authentication middleware
├── metrics.rs           # Metrics and monitoring
└── lib.rs               # Library exports

k8s/
├── manifests.yaml       # Kubernetes manifests
└── helm/                # Helm charts
    ├── Chart.yaml
    ├── values.yaml
    └── templates/
```

## Deployment

### Production Deployment

1. **Configure secrets**
   ```bash
   kubectl create secret generic scanner-secrets \
     --from-literal=encryption-key=$(openssl rand -hex 16) \
     --from-literal=jwt-secret=$(openssl rand -hex 16) \
     --from-literal=database-url="postgresql://..." \
     --from-literal=redis-url="redis://..." \
     -n stellar-scanner
   ```

2. **Deploy with production values**
   ```bash
   helm install stellar-scanner ./helm \
     --namespace stellar-scanner \
     --values helm/values-prod.yaml \
     --wait
   ```

3. **Verify deployment**
   ```bash
   kubectl get pods -n stellar-scanner
   kubectl get hpa -n stellar-scanner
   ```

### Scaling

- **Horizontal Pod Autoscaler** automatically scales backend pods
- **Queue-based auto-scaling** adjusts scan capacity based on load
- **Resource quotas** ensure fair resource allocation

## Troubleshooting

### Common Issues

1. **Pod stuck in Pending**
   - Check resource quotas: `kubectl describe resourcequota -n scan-{id}`
   - Verify node resources: `kubectl top nodes`

2. **Scan timeouts**
   - Check timeout configuration
   - Verify scanner image is available
   - Review resource limits

3. **Authentication failures**
   - Verify JWT secret is set correctly
   - Check token expiration
   - Review authentication logs

### Debug Commands

```bash
# Check scan namespace
kubectl get ns | grep scan-

# Check scan pod
kubectl get pods -n scan-{scan-id}

# Check scan logs
kubectl logs -n scan-{scan-id} scan-{scan-id} -c scanner

# Check resource usage
kubectl top pods -n stellar-scanner

# Check metrics
kubectl port-forward svc/stellar-scanner-backend 8080:80 -n stellar-scanner
curl http://localhost:8080/metrics
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- **Issues**: [GitHub Issues](https://github.com/frankosakwe/soroban-security-scanner/issues)
- **Discord**: [Community Server](https://discord.gg/stellar-security)
- **Email**: support@stellar-scanner.io
