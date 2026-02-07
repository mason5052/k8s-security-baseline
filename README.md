# Kubernetes Security Baseline

Production-tested security hardening checklist and audit scripts based on CIS Kubernetes Benchmarks. Built from real-world experience managing 43+ production workloads with 99.9%+ availability.

## Overview

This repository provides practical security configurations for enterprise Kubernetes clusters, including:

- CIS Kubernetes Benchmark checklists
- Security audit automation scripts
- RBAC hardening templates
- Pod Security Standards (PSS) examples
- Network policy templates

## Quick Start

```bash
# Clone the repository
git clone https://github.com/mason5052/k8s-security-baseline.git
cd k8s-security-baseline

# Run security audit
./scripts/audit-cluster.sh
```

## CIS Benchmark Coverage

Based on CIS Kubernetes Benchmark v1.8.0

| Section | Area | Coverage |
|---------|------|----------|
| 1 | Control Plane Components | Partial |
| 2 | etcd | Partial |
| 3 | Control Plane Configuration | Partial |
| 4 | Worker Nodes | Partial |
| 5 | Policies | Full |

## Repository Structure

```
k8s-security-baseline/
|-- checklists/
|   |-- control-plane.md
|   |-- worker-nodes.md
|   |-- policies.md
|-- scripts/
|   |-- audit-cluster.sh
|   |-- check-rbac.sh
|   |-- scan-pods.sh
|-- templates/
|   |-- rbac/
|   |-- network-policies/
|   |-- pod-security/
|-- examples/
|   |-- secure-deployment.yaml
|   |-- restricted-namespace.yaml
```

## Key Security Areas

### 1. Control Plane Hardening

- API Server authentication and authorization
- etcd encryption at rest
- Audit logging configuration
- TLS certificate management

### 2. Worker Node Security

- kubelet authentication
- Read-only ports disabled
- Protect kernel defaults
- Container runtime security

### 3. Pod Security Standards

Implementing Kubernetes Pod Security Standards (PSS):

| Level | Use Case |
|-------|----------|
| Privileged | System workloads requiring full access |
| Baseline | Standard workloads with minimal restrictions |
| Restricted | Security-sensitive workloads |

### 4. RBAC Best Practices

- Principle of least privilege
- Service account token management
- Role and ClusterRole design patterns
- Audit RBAC permissions

### 5. Network Policies

- Default deny ingress/egress
- Namespace isolation
- Pod-to-pod communication rules
- External traffic control

## Production Experience

These configurations are derived from managing:

- 43+ production RPA workloads
- HA control plane across multiple AWS AZs
- 99.9%+ availability SLA
- Enterprise compliance requirements

## Tools Integration

| Tool | Purpose |
|------|---------|
| Trivy | Container vulnerability scanning |
| kube-bench | CIS Benchmark compliance checking |
| Falco | Runtime security monitoring |
| OPA/Gatekeeper | Policy enforcement |

## Getting Started

1. Review the checklists for your cluster type
2. Run the audit scripts to identify gaps
3. Apply templates appropriate for your environment
4. Implement continuous monitoring

## Contributing

Contributions are welcome. Please read the contributing guidelines before submitting pull requests.

## References

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [NIST Container Security Guide](https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-190.pdf)

## Author

**Mason Kim**
- GitHub: [@mason5052](https://github.com/mason5052)
- LinkedIn: [junkukkim](https://www.linkedin.com/in/junkukkim/)

## License

MIT License - see [LICENSE](LICENSE) for details.
