# Network Security Checklist

Based on CIS Kubernetes Benchmark v1.8.0 - Section 5.3 and Kubernetes Network Policy documentation.

---

## Overview

Kubernetes networking is flat by default - every pod can reach every other pod. Network Policies
are the primary mechanism to enforce traffic segmentation between workloads.

**Core principle:** Default deny everything, then explicitly allow only required traffic.

---

## Checklist

### 1. Default Deny Policies

| Check | CIS Ref | Status |
|-------|---------|--------|
| Default deny ingress NetworkPolicy exists in every namespace | 5.3.2 | [ ] |
| Default deny egress NetworkPolicy exists in every namespace | 5.3.2 | [ ] |
| kube-system namespace has appropriate network isolation | - | [ ] |
| No namespace left with unrestricted pod-to-pod communication | 5.3.1 | [ ] |

**Audit command:**
```bash
# Find namespaces without any NetworkPolicy
NAMESPACES=$(kubectl get ns -o jsonpath='{.items[*].metadata.name}')
for ns in $NAMESPACES; do
  COUNT=$(kubectl get networkpolicy -n $ns --no-headers 2>/dev/null | wc -l)
  if [ "$COUNT" -eq 0 ]; then
    echo "NO POLICY: $ns"
  fi
done
```

**Default deny template:**
```yaml
# See: ../templates/network-policy-default-deny.yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress
```

---

### 2. Explicit Allow Policies

| Check | Status |
|-------|--------|
| Ingress allowed only from specific namespaces/pods (not 0.0.0.0/0) | [ ] |
| Egress restricted to required destinations (DNS, databases, external APIs) | [ ] |
| DNS egress always explicitly allowed (port 53 UDP/TCP) | [ ] |
| Inter-service communication uses label selectors, not IP ranges | [ ] |
| Pod-to-pod policies use `podSelector` and `namespaceSelector` | [ ] |

**DNS egress policy (required for all namespaces with default-deny-egress):**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: production
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - ports:
    - port: 53
      protocol: UDP
    - port: 53
      protocol: TCP
```

**Allow specific service ingress:**
```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-frontend-to-backend
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: backend
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: frontend
    ports:
    - protocol: TCP
      port: 8080
```

---

### 3. Namespace Isolation

| Check | CIS Ref | Status |
|-------|---------|--------|
| Namespaces used to isolate application environments (dev/staging/prod) | - | [ ] |
| Cross-namespace traffic explicitly allowed where needed | - | [ ] |
| Monitoring namespace access to app namespaces controlled | - | [ ] |
| `namespaceSelector` used instead of allowing all namespace access | - | [ ] |

```yaml
# Allow monitoring namespace to scrape metrics
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-monitoring-ingress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: my-service
  policyTypes:
  - Ingress
  ingress:
  - from:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: monitoring
    ports:
    - protocol: TCP
      port: 9090
```

---

### 4. Ingress TLS Configuration

| Check | Status |
|-------|--------|
| All Ingress resources configured with TLS (HTTPS) | [ ] |
| TLS certificates managed by cert-manager or equivalent | [ ] |
| HTTP-to-HTTPS redirect configured at Ingress level | [ ] |
| Minimum TLS version set to 1.2 (TLS 1.3 preferred) | [ ] |
| Weak cipher suites disabled in Ingress controller config | [ ] |

```yaml
# TLS-enabled Ingress example
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: secure-ingress
  namespace: production
  annotations:
    nginx.ingress.kubernetes.io/force-ssl-redirect: "true"
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    cert-manager.io/cluster-issuer: "letsencrypt-prod"
spec:
  tls:
  - hosts:
    - app.example.com
    secretName: app-tls-cert
  rules:
  - host: app.example.com
    http:
      paths:
      - path: /
        pathType: Prefix
        backend:
          service:
            name: my-service
            port:
              number: 80
```

---

### 5. Egress Controls

| Check | Status |
|-------|--------|
| Egress to public internet restricted to required endpoints | [ ] |
| Database egress scoped to specific CIDR and port | [ ] |
| Sensitive workloads have no unrestricted egress | [ ] |
| External API access uses specific IP/CIDR allowlists | [ ] |

```yaml
# Restrict egress to specific external API
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-external-api-egress
  namespace: production
spec:
  podSelector:
    matchLabels:
      app: api-consumer
  policyTypes:
  - Egress
  egress:
  - to:
    - ipBlock:
        cidr: 203.0.113.0/24   # Example: external API IP range (RFC 5737 documentation range)
    ports:
    - protocol: TCP
      port: 443
```

---

### 6. CNI and Network Plugin

| Check | Status |
|-------|--------|
| CNI plugin supports NetworkPolicy enforcement (Calico, Cilium, Weave) | [ ] |
| CNI plugin is up to date with security patches | [ ] |
| Node-to-node communication encrypted (Cilium WireGuard or IPsec) | [ ] |
| CNI plugin logs available for audit | [ ] |

**Verify NetworkPolicy is enforced by CNI:**
```bash
# Test: create two pods and verify deny policy blocks communication
kubectl run test-sender --image=busybox --rm -it -- wget -O- http://test-receiver:80 --timeout=3
# Should fail if default-deny policy is in place
```

---

### 7. Service Mesh (Optional but Recommended)

| Check | Status |
|-------|--------|
| mTLS enabled between all services (Istio/Linkerd) | [ ] |
| PeerAuthentication policy set to STRICT mTLS mode | [ ] |
| AuthorizationPolicy configured for service-to-service calls | [ ] |
| Ingress gateway configured as the only external entry point | [ ] |

```yaml
# Istio: Enforce strict mTLS namespace-wide
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT
```

---

## Audit Commands

```bash
# List all NetworkPolicies across all namespaces
kubectl get networkpolicy -A

# Describe a specific policy to review rules
kubectl describe networkpolicy default-deny-all -n production

# Check if a pod can reach another (requires netcat in container)
kubectl exec -n production deploy/my-app -- nc -zv my-service 8080

# Find pods with hostNetwork: true
kubectl get pods -A -o json | jq -r '
  .items[] |
  select(.spec.hostNetwork == true) |
  "HOST_NETWORK: " + .metadata.namespace + "/" + .metadata.name'
```

---

## References

- [Kubernetes Network Policies](https://kubernetes.io/docs/concepts/services-networking/network-policies/)
- [CIS Kubernetes Benchmark v1.8.0 - Section 5.3](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Ingress TLS](https://kubernetes.io/docs/concepts/services-networking/ingress/#tls)
- [Cilium Network Policy](https://docs.cilium.io/en/stable/security/policy/)
- See also: [../templates/network-policy-default-deny.yaml](../templates/network-policy-default-deny.yaml) for working templates
