# Worker Node Security Checklist

Based on CIS Kubernetes Benchmark v1.8.0 - Section 4

## 1. Kubelet Configuration

### 1.1 Authentication and Authorization

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 4.2.1 | Ensure anonymous-auth is false | [ ] | `--anonymous-auth=false` |
| 4.2.2 | Ensure authorization-mode is not AlwaysAllow | [ ] | `--authorization-mode=Webhook` |
| 4.2.3 | Ensure client-ca-file is set | [ ] | `--client-ca-file=/etc/kubernetes/pki/ca.crt` |

### 1.2 TLS Configuration

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 4.2.4 | Verify kubelet HTTPS | [ ] | Default enabled |
| 4.2.5 | Ensure TLS cert and key configured | [ ] | `--tls-cert-file`, `--tls-private-key-file` |
| 4.2.6 | Ensure rotate certificates enabled | [ ] | `--rotate-certificates=true` |

### 1.3 Security Settings

| ID | Check | Status | Command |
|----|-------|--------|---------|
| 4.2.7 | Ensure read-only-port is disabled | [ ] | `--read-only-port=0` |
| 4.2.8 | Ensure streaming connection timeout | [ ] | `--streaming-connection-idle-timeout` |
| 4.2.9 | Ensure protect-kernel-defaults enabled | [ ] | `--protect-kernel-defaults=true` |
| 4.2.10 | Ensure make-iptables-util-chains enabled | [ ] | `--make-iptables-util-chains=true` |

## 2. Kubelet Configuration File

| ID | Check | Status | Path |
|----|-------|--------|------|
| 4.2.14 | Ensure kubelet config file permissions | [ ] | `chmod 600 /var/lib/kubelet/config.yaml` |
| 4.2.15 | Ensure kubelet config file ownership | [ ] | `chown root:root /var/lib/kubelet/config.yaml` |

## 3. File Permissions

| File/Directory | Expected Permissions | Owner |
|----------------|---------------------|-------|
| `/etc/kubernetes/kubelet.conf` | 600 | root:root |
| `/var/lib/kubelet/config.yaml` | 600 | root:root |
| `/etc/kubernetes/pki/` | 600 | root:root |

## Quick Audit Commands

```bash
# Check kubelet configuration
ps -ef | grep kubelet

# View kubelet config file
cat /var/lib/kubelet/config.yaml

# Check file permissions
stat -c %a /etc/kubernetes/kubelet.conf

# Check read-only port
ss -tlnp | grep 10255
```

## References

- [CIS Kubernetes Benchmark v1.8.0](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubelet Configuration](https://kubernetes.io/docs/reference/config-api/kubelet-config.v1beta1/)
