# Kubernetes Policies Security Checklist

Based on CIS Kubernetes Benchmark v1.8.0 - Section 5

## 1. RBAC and Service Accounts

### 1.1 Cluster-wide Policies

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| 5.1.1 | Ensure cluster-admin role is only used where required | [ ] | Audit ClusterRoleBindings |
| 5.1.2 | Minimize access to secrets | [ ] | Restrict secret access by namespace |
| 5.1.3 | Minimize wildcard use in Roles and ClusterRoles | [ ] | Avoid * in resources/verbs |
| 5.1.4 | Minimize access to create pods | [ ] | Limit pod creation permissions |
| 5.1.5 | Ensure default service account is not actively used | [ ] | Create dedicated SAs |
| 5.1.6 | Ensure service account tokens are only mounted where necessary | [ ] | `automountServiceAccountToken: false` |

## 2. Pod Security Standards

### 2.1 Pod Security Admission

| Level | Namespace Label | Use Case |
|-------|-----------------|----------|
| Privileged | `pod-security.kubernetes.io/enforce: privileged` | System namespaces |
| Baseline | `pod-security.kubernetes.io/enforce: baseline` | Default workloads |
| Restricted | `pod-security.kubernetes.io/enforce: restricted` | Secure workloads |

### 2.2 Security Context Checklist

| ID | Check | Status | Recommendation |
|----|-------|--------|----------------|
| 5.2.1 | Minimize privileged containers | [ ] | `privileged: false` |
| 5.2.2 | Minimize containers with hostPID | [ ] | `hostPID: false` |
| 5.2.3 | Minimize containers with hostIPC | [ ] | `hostIPC: false` |
| 5.2.4 | Minimize containers with hostNetwork | [ ] | `hostNetwork: false` |
| 5.2.5 | Minimize allowPrivilegeEscalation | [ ] | `allowPrivilegeEscalation: false` |
| 5.2.6 | Minimize root containers | [ ] | `runAsNonRoot: true` |

## 3. Network Policies

### 3.1 Default Deny Policies

| Check | Status | Description |
|-------|--------|-------------|
| Default deny ingress | [ ] | Block all incoming traffic by default |
| Default deny egress | [ ] | Block all outgoing traffic by default |
| Namespace isolation | [ ] | Isolate namespaces from each other |

## 4. Secrets Management

| ID | Check | Status | Notes |
|----|-------|--------|-------|
| 5.4.1 | Prefer using Secrets as files | [ ] | Mount as volumes, not env vars |
| 5.4.2 | Consider external secret storage | [ ] | Vault, AWS Secrets Manager |
| 5.4.3 | Enable encryption at rest | [ ] | Configure EncryptionConfiguration |

## Quick Audit Commands

```bash
# List cluster-admin bindings
kubectl get clusterrolebindings -o json | jq '.items[] | select(.roleRef.name=="cluster-admin")'

# Find pods with default service account
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.serviceAccountName=="default")'

# Check for privileged pods
kubectl get pods --all-namespaces -o json | jq '.items[] | select(.spec.containers[].securityContext.privileged==true)'

# List network policies
kubectl get networkpolicies --all-namespaces
```

## References

- [CIS Kubernetes Benchmark v1.8.0](https://www.cisecurity.org/benchmark/kubernetes)
- [Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
