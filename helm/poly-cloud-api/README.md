# ☸️ Poly Cloud API Helm Chart

Production-ready Kubernetes Helm Chart for **Poly Cloud API** — high-throughput, pluggable remote cache server and ROI analytics engine for Poly and Turborepo.

---

## ⚡ Features

- **Horizontal Pod Autoscaling (HPA)**: Auto-scales across CPU and Memory utilization targets.
- **Ingress & TLS**: Seamless Ingress configuration with automatic cert-manager Let's Encrypt certificates and large-body streaming support (`2048m`).
- **Prometheus ServiceMonitor**: Turnkey integration with Prometheus Operator for `/api/v1/metrics`.
- **Pluggable Object Storage**: Complete ConfigMaps & Secrets for **AWS S3**, **Cloudflare R2**, and **MinIO**.
- **Non-Root Security Hardened**: Runs unprivileged with `runAsNonRoot: true`, read-only root filesystems, and dropped Linux capabilities.
- **High-Availability Resilience**: PodAntiAffinity and RollingUpdate zero-downtime deployment strategy.

---

## 🚀 Quickstart

### 1. Add Repository & Install Chart

```bash
# Add repo or clone
git clone https://github.com/RitualDev-Lab/poly-cloud-api.git
cd poly-cloud-api

# Install chart into 'poly-cache' namespace
helm install poly-cache ./charts/poly-cloud-api \
  --namespace poly-cache \
  --create-namespace \
  --values ./charts/poly-cloud-api/values.yaml
```

### 2. Retrieve Admin Token

```bash
kubectl get secret --namespace poly-cache poly-cache-poly-cloud-api-secrets \
  -o jsonpath="{.data.DEFAULT_ADMIN_TOKEN}" | base64 --decode
```

### 3. Connect Poly CLI

```bash
poly login --url https://cache.example.com --token <ADMIN_TOKEN> --workspace default
poly cache status
```

---

## 🛠️ Storage Backend Configurations

### Option A: AWS S3 with EKS IAM Roles for Service Accounts (IRSA)

```yaml
# values-aws.yaml
serviceAccount:
  create: true
  annotations:
    eks.amazonaws.com/role-arn: "arn:aws:iam::123456789012:role/PolyCloudCacheRole"

config:
  storageBackend: "s3"
  s3:
    bucket: "my-company-poly-cache"
    region: "us-east-1"
```

### Option B: Cloudflare R2

```yaml
# values-r2.yaml
config:
  storageBackend: "s3"
  s3:
    bucket: "poly-cache-bucket"
    region: "auto"
    endpoint: "https://<account_id>.r2.cloudflarestorage.com"
    accessKeyId: "CLOUDFLARE_R2_ACCESS_KEY_ID"
    secretAccessKey: "CLOUDFLARE_R2_SECRET_ACCESS_KEY"
```

### Option C: MinIO (On-Premises or Kubernetes-Native)

```yaml
# values-minio.yaml
config:
  storageBackend: "s3"
  s3:
    bucket: "poly-artifacts"
    region: "us-east-1"
    endpoint: "http://minio.minio.svc.cluster.local:9000"
    forcePathStyle: true
    accessKeyId: "minioadmin"
    secretAccessKey: "minioadmin"
```

### Option D: Local Disk Storage with PersistentVolumeClaim (PVC)

```yaml
# values-local.yaml
config:
  storageBackend: "local"

persistence:
  enabled: true
  storageClass: "gp3" # or local-path, ebs-sc
  size: 100Gi
  mountPath: /app/data
```

---

## ⚙️ Parameters Reference

| Parameter | Default | Description |
|:---|:---|:---|
| `replicaCount` | `2` | Number of pod replicas for High Availability |
| `image.repository` | `ghcr.io/ritualdev-lab/poly-cloud-api` | Container image repository |
| `image.tag` | `""` (Chart appVersion) | Container image tag |
| `service.type` | `ClusterIP` | Kubernetes Service type |
| `service.port` | `8080` | Internal HTTP service port |
| `ingress.enabled` | `true` | Enable Kubernetes Ingress controller |
| `ingress.className` | `"nginx"` | Ingress class name |
| `ingress.hosts` | `[cache.example.com]` | Ingress routing hostnames |
| `ingress.tls` | `[poly-cloud-tls]` | TLS certificate secrets |
| `autoscaling.enabled` | `true` | Enable Horizontal Pod Autoscaler (HPA v2) |
| `autoscaling.minReplicas` | `2` | Minimum pod replicas |
| `autoscaling.maxReplicas` | `10` | Maximum pod replicas |
| `autoscaling.targetCPUUtilizationPercentage` | `75` | Target CPU utilization percentage |
| `serviceMonitor.enabled` | `true` | Enable Prometheus Operator ServiceMonitor |
| `serviceMonitor.interval` | `15s` | Prometheus scrape interval |
| `config.storageBackend` | `"s3"` | Storage backend (`s3`, `local`, `memory`) |
| `config.s3.bucket` | `"poly-remote-cache"` | S3 / R2 Bucket name |
| `config.s3.region` | `"us-east-1"` | S3 region |
| `config.s3.endpoint` | `""` | S3 endpoint URL (for R2 / MinIO) |
| `config.presignedUrls.enabled` | `true` | Enable direct-to-storage presigned S3/R2 URLs |
| `config.oidc.enabled` | `true` | Enable GitHub Actions OIDC zero-secret auth |
| `config.optimizer.autoEvictionEnabled` | `true` | Enable LRU auto-eviction daemon |
| `config.optimizer.deduplicationEnabled` | `true` | Enable cross-branch CAS layer deduplication |
| `persistence.enabled` | `false` | Enable PersistentVolumeClaim (for local disk backend) |
| `persistence.size` | `50Gi` | Size of persistent volume |

---

## 📜 License

Licensed under the [Apache License, Version 2.0](https://github.com/RitualDev-Lab/poly-cloud-api/blob/main/LICENSE).
