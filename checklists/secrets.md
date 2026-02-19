# Secrets Management Checklist

Kubernetes Secrets are base64-encoded (not encrypted) by default. This checklist covers
hardening secrets at rest, in transit, and throughout the application lifecycle.

---

## Core Principles

1. **Encrypt at rest** - etcd stores secrets; enable EncryptionConfiguration
2. **Least privilege access** - RBAC restricts who can `get`/`list` secrets
3. **Avoid env vars** - Prefer volume mounts; env vars appear in pod specs and logs
4. **Rotate regularly** - Automate rotation; avoid long-lived static credentials
5. **External management** - Use External Secrets Operator or Vault for production

---

## Checklist

### 1. Encryption at Rest (etcd)

| Check | CIS Ref | Status |
|-------|---------|--------|
| EncryptionConfiguration applied to kube-apiserver | 1.2.33 | [ ] |
| AES-GCM or AES-CBC provider configured (not `identity`) | 1.2.33 | [ ] |
| All existing secrets re-encrypted after enabling | - | [ ] |
| Encryption provider key stored securely (not in plain text on disk) | - | [ ] |
| etcd data directory permissions restricted (700) | 2.1 | [ ] |

**EncryptionConfiguration example:**
```yaml
# /etc/kubernetes/encryption-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: EncryptionConfiguration
resources:
  - resources:
      - secrets
    providers:
      - aescbc:
          keys:
            - name: key1
              secret: <base64-encoded-32-byte-key>   # Generate: head -c 32 /dev/urandom | base64
      - identity: {}   # Fallback for unencrypted reads during migration
```

**Apply to kube-apiserver:**
```bash
# Add to kube-apiserver manifest
--encryption-provider-config=/etc/kubernetes/encryption-config.yaml
```

**Verify encryption is active:**
```bash
# Write a test secret, then read from etcd directly to confirm it's encrypted
kubectl create secret generic test-encryption --from-literal=key=value
ETCDCTL_API=3 etcdctl get /registry/secrets/default/test-encryption \
  --endpoints=https://127.0.0.1:2379 \
  --cacert=/etc/kubernetes/pki/etcd/ca.crt \
  --cert=/etc/kubernetes/pki/etcd/server.crt \
  --key=/etc/kubernetes/pki/etcd/server.key | hexdump -C | head
# Output should show 'k8s:enc:aescbc' prefix, not readable secret data
```

---

### 2. RBAC Access Controls

| Check | CIS Ref | Status |
|-------|---------|--------|
| No wildcard `*` verbs on `secrets` resource | 5.1.2 | [ ] |
| `list` verb on secrets restricted (exposes all secret values) | 5.1.2 | [ ] |
| Application service accounts cannot `get` secrets they don't need | 5.1.3 | [ ] |
| No ClusterRole granting broad secret access to non-admin subjects | - | [ ] |
| Secret access audited via Kubernetes audit logging | - | [ ] |

```yaml
# Minimal secret access - read only specific secret
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: app-secret-reader
  namespace: production
rules:
- apiGroups: [""]
  resources: ["secrets"]
  resourceNames: ["app-database-credentials"]  # Restrict to named secret
  verbs: ["get"]
```

**Audit command:**
```bash
# Find roles with broad secret access
kubectl get clusterroles,roles -A -o json | jq -r '
  .items[] |
  . as $role |
  .rules[]? |
  select(
    (.resources // [] | map(select(. == "*" or . == "secrets")) | length > 0) and
    (.verbs | map(select(. == "*" or . == "get" or . == "list")) | length > 0)
  ) |
  "BROAD ACCESS: " + $role.metadata.namespace + "/" + $role.metadata.name'
```

---

### 3. Avoiding Secrets in Environment Variables

| Check | Status |
|-------|--------|
| Secrets mounted as files (volume), not injected as env vars | [ ] |
| No hardcoded credentials in pod specs or ConfigMaps | [ ] |
| No secrets in container image layers (check with `docker history`) | [ ] |
| No secrets committed to Git (use pre-commit hooks) | [ ] |
| CI/CD pipelines use secret stores, not environment variables | [ ] |

```yaml
# Preferred: Mount secret as a file (not exposed in `kubectl describe pod`)
spec:
  volumes:
  - name: db-credentials
    secret:
      secretName: database-credentials
      defaultMode: 0400    # Read-only for owner only
  containers:
  - name: app
    volumeMounts:
    - name: db-credentials
      mountPath: /run/secrets/db
      readOnly: true
```

```yaml
# Avoid: Secret as environment variable (appears in `kubectl describe pod`)
env:
- name: DB_PASSWORD
  valueFrom:
    secretKeyRef:
      name: database-credentials
      key: password
```

---

### 4. External Secrets Operator (ESO)

External Secrets Operator syncs secrets from external providers (Azure Key Vault, AWS Secrets Manager, HashiCorp Vault) into Kubernetes Secrets.

| Check | Status |
|-------|--------|
| ESO installed and configured in the cluster | [ ] |
| SecretStore or ClusterSecretStore configured for external provider | [ ] |
| ExternalSecret resources used instead of manually created Secrets | [ ] |
| Automatic refresh interval configured for secret rotation | [ ] |
| ESO service account has least-privilege access to the secret backend | [ ] |

**Azure Key Vault integration example:**
```yaml
# SecretStore pointing to Azure Key Vault
apiVersion: external-secrets.io/v1beta1
kind: SecretStore
metadata:
  name: azure-key-vault
  namespace: production
spec:
  provider:
    azurekv:
      tenantId: "<your-tenant-id>"
      vaultUrl: "https://my-vault.vault.azure.net"
      authType: WorkloadIdentity
```

```yaml
# ExternalSecret: syncs a Key Vault secret into a Kubernetes Secret
apiVersion: external-secrets.io/v1beta1
kind: ExternalSecret
metadata:
  name: database-credentials
  namespace: production
spec:
  refreshInterval: 1h
  secretStoreRef:
    name: azure-key-vault
    kind: SecretStore
  target:
    name: database-credentials
    creationPolicy: Owner
  data:
  - secretKey: password
    remoteRef:
      key: prod-db-password
```

---

### 5. Secret Rotation

| Check | Status |
|-------|--------|
| Secret rotation schedule defined and documented | [ ] |
| Rotation automated (ESO refresh interval, Vault TTL, AWS rotation) | [ ] |
| Applications handle secret rotation without downtime (re-read on mount change) | [ ] |
| Old/revoked secrets cleaned up from Kubernetes after rotation | [ ] |
| Database credentials use dynamic secrets (Vault dynamic secrets) where possible | [ ] |

**Monitor secret age with a simple script:**
```bash
#!/bin/bash
# List secrets and their creation timestamps
kubectl get secrets -A -o json | jq -r '
  .items[] |
  select(.type != "kubernetes.io/service-account-token") |
  .metadata.namespace + "/" + .metadata.name + " created: " +
  .metadata.creationTimestamp'
```

---

### 6. CI/CD Pipeline Secret Handling

| Check | Status |
|-------|--------|
| CI/CD secrets stored in pipeline secret store (GitHub Secrets, Vault) | [ ] |
| Secrets never logged or echoed in pipeline output | [ ] |
| Container images scanned for embedded secrets (Trivy secret scanning) | [ ] |
| Secret detection pre-commit hooks installed (detect-secrets, gitleaks) | [ ] |
| Pipeline service account has minimal Kubernetes RBAC permissions | [ ] |

**Trivy secret scanning:**
```bash
# Scan image for embedded secrets
trivy image --scanners secret my-registry.example.com/app:latest

# Scan filesystem for secrets before building
trivy fs --scanners secret .
```

**GitHub Actions - secrets best practices:**
```yaml
# Use GitHub Secrets, mask output, never echo
- name: Deploy
  env:
    KUBECONFIG_DATA: ${{ secrets.KUBECONFIG_DATA }}
  run: |
    echo "$KUBECONFIG_DATA" | base64 -d > /tmp/kubeconfig
    # kubeconfig value is masked in logs
    kubectl --kubeconfig=/tmp/kubeconfig apply -f manifests/
    rm /tmp/kubeconfig   # Clean up after use
```

---

### 7. Monitoring and Alerting

| Check | Status |
|-------|--------|
| Kubernetes audit logging captures `secrets` resource access | [ ] |
| Alerts configured for unusual secret access patterns | [ ] |
| Failed secret access attempts logged and alerted | [ ] |
| Secret creation/deletion events monitored | [ ] |

**Audit policy for secrets:**
```yaml
# /etc/kubernetes/audit-policy.yaml
apiVersion: audit.k8s.io/v1
kind: Policy
rules:
- level: Metadata
  resources:
  - group: ""
    resources: ["secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- level: None
  users: ["system:kube-proxy"]
  verbs: ["watch"]
  resources:
  - group: ""
    resources: ["endpoints", "services"]
```

---

## Quick Audit

```bash
#!/bin/bash
echo "=== Secrets Encryption Status ==="
kubectl get --raw /api/v1/namespaces/default/secrets/test-secret 2>/dev/null | \
  jq '.data | keys' 2>/dev/null || echo "No test secret found"

echo ""
echo "=== Secrets with Broad RBAC Access ==="
kubectl auth can-i list secrets --as=system:serviceaccount:default:default 2>&1

echo ""
echo "=== Pods Using Secret Environment Variables ==="
kubectl get pods -A -o json | jq -r '
  .items[] | . as $pod |
  .spec.containers[] |
  select(.env != null) |
  .env[] |
  select(.valueFrom.secretKeyRef != null) |
  $pod.metadata.namespace + "/" + $pod.metadata.name + " uses secret env: " + .name'
```

---

## References

- [Kubernetes Secrets Documentation](https://kubernetes.io/docs/concepts/configuration/secret/)
- [Encrypting Secret Data at Rest](https://kubernetes.io/docs/tasks/administer-cluster/encrypt-data/)
- [External Secrets Operator](https://external-secrets.io/)
- [CIS Kubernetes Benchmark v1.8.0 - Sections 1.2.33, 5.1](https://www.cisecurity.org/benchmark/kubernetes)
- [OWASP Kubernetes Security Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Kubernetes_Security_Cheat_Sheet.html)
