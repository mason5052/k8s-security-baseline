# Control Plane Security Checklist

Based on CIS Kubernetes Benchmark v1.8.0 - Section 1 & 3

## 1. API Server

### 1.1 Authentication

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 1.2.1 | Ensure anonymous-auth is disabled | [ ] | `--anonymous-auth=false` |
| 1.2.2 | Ensure basic-auth-file is not set | [ ] | Verify not present |
| 1.2.3 | Ensure token-auth-file is not set | [ ] | Verify not present |
| 1.2.4 | Use HTTPS for kubelet connections | [ ] | `--kubelet-https=true` |

### 1.2 Authorization

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 1.2.5 | Ensure authorization-mode includes RBAC | [ ] | `--authorization-mode=Node,RBAC` |
| 1.2.6 | Ensure authorization-mode does not include AlwaysAllow | [ ] | Verify not present |
| 1.2.7 | Enable Node authorization | [ ] | `--authorization-mode=Node,RBAC` |

### 1.3 Admission Controllers

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 1.2.11 | Enable AlwaysPullImages | [ ] | `--enable-admission-plugins=AlwaysPullImages` |
| 1.2.12 | Enable PodSecurityAdmission | [ ] | `--enable-admission-plugins=PodSecurity` |
| 1.2.13 | Enable NodeRestriction | [ ] | `--enable-admission-plugins=NodeRestriction` |

### 1.4 Audit Logging

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 1.2.19 | Enable audit logging | [ ] | `--audit-log-path=/var/log/apiserver/audit.log` |
| 1.2.20 | Set audit log maxage | [ ] | `--audit-log-maxage=30` |
| 1.2.21 | Set audit log maxbackup | [ ] | `--audit-log-maxbackup=10` |
| 1.2.22 | Set audit log maxsize | [ ] | `--audit-log-maxsize=100` |

### 1.5 TLS Configuration

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 1.2.26 | Ensure etcd-certfile and etcd-keyfile are set | [ ] | Verify TLS to etcd |
| 1.2.27 | Ensure TLS cert and key are set | [ ] | `--tls-cert-file`, `--tls-private-key-file` |
| 1.2.28 | Ensure client-ca-file is set | [ ] | `--client-ca-file` |

## 2. Controller Manager

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 1.3.1 | Ensure terminated-pod-gc-threshold is set | [ ] | `--terminated-pod-gc-threshold=10` |
| 1.3.2 | Ensure profiling is disabled | [ ] | `--profiling=false` |
| 1.3.3 | Ensure use-service-account-credentials is enabled | [ ] | `--use-service-account-credentials=true` |
| 1.3.4 | Ensure service-account-private-key-file is set | [ ] | `--service-account-private-key-file` |
| 1.3.5 | Ensure root-ca-file is set | [ ] | `--root-ca-file` |
| 1.3.6 | Enable RotateKubeletServerCertificate | [ ] | `--feature-gates=RotateKubeletServerCertificate=true` |
| 1.3.7 | Ensure bind-address is 127.0.0.1 | [ ] | `--bind-address=127.0.0.1` |

## 3. Scheduler

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 1.4.1 | Ensure profiling is disabled | [ ] | `--profiling=false` |
| 1.4.2 | Ensure bind-address is 127.0.0.1 | [ ] | `--bind-address=127.0.0.1` |

## Quick Audit Commands

```bash
# Check API server configuration
ps -ef | grep kube-apiserver

# Check controller manager configuration
ps -ef | grep kube-controller-manager

# Check scheduler configuration
ps -ef | grep kube-scheduler

# Verify RBAC is enabled
kubectl api-versions | grep rbac

# Check admission controllers
kubectl get pods -n kube-system -o yaml | grep admission
```

## References

- [CIS Kubernetes Benchmark v1.8.0](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes API Server Documentation](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/)
- [Kubernetes Hardening Guide](https://kubernetes.io/docs/concepts/security/)
