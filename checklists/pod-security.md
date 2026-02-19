# Pod Security Checklist

Based on CIS Kubernetes Benchmark v1.8.0 - Section 5.2 and Kubernetes Pod Security Standards (PSS).

---

## Pod Security Standards (PSS)

Kubernetes defines three built-in policy levels enforced via Pod Security Admission (PSA):

| Profile | Use Case | Key Restrictions |
|---------|----------|-----------------|
| Privileged | System components only | No restrictions |
| Baseline | General workloads | Blocks known privilege escalations |
| Restricted | High-security workloads | Follows hardening best practices |

### Namespace PSA Labels

```yaml
# Apply Restricted profile to a namespace
apiVersion: v1
kind: Namespace
metadata:
  name: production
  labels:
    pod-security.kubernetes.io/enforce: restricted
    pod-security.kubernetes.io/enforce-version: v1.28
    pod-security.kubernetes.io/warn: restricted
    pod-security.kubernetes.io/audit: restricted
```

---

## Checklist

### 1. Pod Security Admission (PSA)

| Check | CIS Ref | Command | Status |
|-------|---------|---------|--------|
| PSA is enabled (v1.23+ default) | 5.2.1 | `kubectl get --raw /api/v1` | [ ] |
| Production namespaces enforce Restricted or Baseline | 5.2.1 | `kubectl get ns -o json \| jq '.items[].metadata.labels'` | [ ] |
| Warn and audit modes enabled alongside enforce | - | `kubectl describe ns <name>` | [ ] |
| Default namespace not left at Privileged level | 5.2.1 | `kubectl get ns default -o yaml` | [ ] |

**Audit command:**
```bash
kubectl get namespaces -o json | jq -r '
  .items[] |
  [.metadata.name,
   (.metadata.labels["pod-security.kubernetes.io/enforce"] // "none")] |
  @tsv'
```

---

### 2. Security Contexts

#### Non-Root Execution

| Check | CIS Ref | Status |
|-------|---------|--------|
| `runAsNonRoot: true` set at pod or container level | 5.2.6 | [ ] |
| `runAsUser` explicitly set (not 0) | 5.2.6 | [ ] |
| `runAsGroup` set to non-zero GID | - | [ ] |
| `fsGroup` configured for shared volume access | - | [ ] |

```yaml
# Example: Hardened security context
spec:
  securityContext:
    runAsNonRoot: true
    runAsUser: 1000
    runAsGroup: 3000
    fsGroup: 2000
    seccompProfile:
      type: RuntimeDefault
  containers:
  - name: app
    securityContext:
      allowPrivilegeEscalation: false
      readOnlyRootFilesystem: true
      capabilities:
        drop:
          - ALL
```

**Audit command:**
```bash
# Find containers running as root
kubectl get pods -A -o json | jq -r '
  .items[] |
  .metadata.namespace + "/" + .metadata.name + " -> " +
  (.spec.containers[].securityContext.runAsUser // "NOT SET" | tostring)'
```

---

#### Privilege Escalation

| Check | CIS Ref | Status |
|-------|---------|--------|
| `allowPrivilegeEscalation: false` on all containers | 5.2.5 | [ ] |
| No containers with `privileged: true` (outside kube-system) | 5.2.2 | [ ] |
| `hostPID: false` (not sharing host PID namespace) | 5.2.3 | [ ] |
| `hostIPC: false` (not sharing host IPC namespace) | 5.2.4 | [ ] |
| `hostNetwork: false` (not using host network) | 5.2.4 | [ ] |

**Audit command:**
```bash
# Find privileged containers
kubectl get pods -A -o json | jq -r '
  .items[] | . as $pod |
  .spec.containers[] |
  select(.securityContext.privileged == true) |
  $pod.metadata.namespace + "/" + $pod.metadata.name + "/" + .name'
```

---

### 3. Capability Management

| Check | CIS Ref | Status |
|-------|---------|--------|
| `capabilities.drop: [ALL]` on all containers | 5.2.7 | [ ] |
| Only necessary capabilities added back via `capabilities.add` | 5.2.8 | [ ] |
| No containers with `NET_RAW` capability (unless required) | 5.2.7 | [ ] |
| No containers with `SYS_ADMIN` capability | - | [ ] |

```yaml
# Minimal capability example
securityContext:
  capabilities:
    drop:
      - ALL
    add:
      - NET_BIND_SERVICE   # Only if binding port < 1024
```

---

### 4. Filesystem Hardening

| Check | CIS Ref | Status |
|-------|---------|--------|
| `readOnlyRootFilesystem: true` on all containers | 5.2.4 | [ ] |
| Writable mounts limited to specific paths via `emptyDir` or `volumeMounts` | - | [ ] |
| No `hostPath` volume mounts (unless absolutely required) | 5.2.14 | [ ] |
| Sensitive host paths not mounted (`/etc`, `/proc`, `/sys`) | - | [ ] |

```yaml
# Read-only root with specific writable mount
containers:
- name: app
  securityContext:
    readOnlyRootFilesystem: true
  volumeMounts:
  - name: tmp-dir
    mountPath: /tmp
  - name: cache-dir
    mountPath: /var/cache/app
volumes:
- name: tmp-dir
  emptyDir: {}
- name: cache-dir
  emptyDir: {}
```

---

### 5. Resource Limits

| Check | CIS Ref | Status |
|-------|---------|--------|
| CPU `requests` set on all containers | - | [ ] |
| Memory `requests` set on all containers | - | [ ] |
| CPU `limits` set on all containers | - | [ ] |
| Memory `limits` set on all containers | - | [ ] |
| LimitRange applied to namespaces for defaults | - | [ ] |

```yaml
# Resource configuration example
resources:
  requests:
    cpu: "100m"
    memory: "128Mi"
  limits:
    cpu: "500m"
    memory: "256Mi"
```

**Audit command:**
```bash
# Find containers without resource limits
kubectl get pods -A -o json | jq -r '
  .items[] | . as $pod |
  .spec.containers[] |
  select(.resources.limits == null) |
  $pod.metadata.namespace + "/" + $pod.metadata.name + "/" + .name + " - NO LIMITS"'
```

---

### 6. Image Security

| Check | Status |
|-------|--------|
| Container images pinned to specific digest or tag (not `latest`) | [ ] |
| Images scanned with Trivy before deployment | [ ] |
| Only images from trusted registries (private registry or signed) | [ ] |
| No images with known critical/high CVEs in production | [ ] |
| Image pull policy set to `Always` for mutable tags | [ ] |

```yaml
# Image security example
containers:
- name: app
  image: my-registry.example.com/app:v1.2.3@sha256:abc123...
  imagePullPolicy: Always
```

**Trivy scan command:**
```bash
trivy image --severity HIGH,CRITICAL my-registry.example.com/app:v1.2.3
```

---

### 7. Admission Controller Validation

| Check | Status |
|-------|--------|
| PodSecurity admission controller enabled | [ ] |
| OPA/Gatekeeper or Kyverno policies enforcing security standards | [ ] |
| Admission webhooks configured to block non-compliant pods | [ ] |
| ValidatingWebhookConfiguration present for security policies | [ ] |

```bash
# Verify admission controllers
kubectl -n kube-system get pod -l component=kube-apiserver -o yaml | \
  grep enable-admission-plugins
```

---

## Quick Audit Script

```bash
#!/bin/bash
# Quick pod security audit
echo "=== Privileged Containers ==="
kubectl get pods -A -o json | jq -r '
  .items[] | . as $pod |
  .spec.containers[] |
  select(.securityContext.privileged == true) |
  "PRIVILEGED: " + $pod.metadata.namespace + "/" + $pod.metadata.name'

echo ""
echo "=== Containers Running as Root ==="
kubectl get pods -A -o json | jq -r '
  .items[] | . as $pod |
  .spec.containers[] |
  select((.securityContext.runAsNonRoot != true) and
         (.securityContext.runAsUser == null or .securityContext.runAsUser == 0)) |
  "ROOT: " + $pod.metadata.namespace + "/" + $pod.metadata.name + "/" + .name'

echo ""
echo "=== Containers Without Resource Limits ==="
kubectl get pods -A -o json | jq -r '
  .items[] | . as $pod |
  .spec.containers[] |
  select(.resources.limits == null) |
  "NO LIMITS: " + $pod.metadata.namespace + "/" + $pod.metadata.name + "/" + .name'
```

---

## References

- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Pod Security Admission](https://kubernetes.io/docs/concepts/security/pod-security-admission/)
- [CIS Kubernetes Benchmark v1.8.0](https://www.cisecurity.org/benchmark/kubernetes)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- See also: [../templates/rbac-hardened.yaml](../templates/rbac-hardened.yaml) for working examples
