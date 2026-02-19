# k8s-security-baseline

[![Security Audit](https://github.com/mason5052/k8s-security-baseline/actions/workflows/security-audit.yml/badge.svg)](https://github.com/mason5052/k8s-security-baseline/actions/workflows/security-audit.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Kubernetes](https://img.shields.io/badge/Kubernetes-1.28+-326CE5?logo=kubernetes&logoColor=white)](https://kubernetes.io/)
[![CIS Benchmark](https://img.shields.io/badge/CIS-Kubernetes%20v1.8.0-blue)](https://www.cisecurity.org/benchmark/kubernetes)

Kubernetes security hardening checklist and audit automation based on CIS Benchmarks and production experience.

---

## Overview

This repository provides a practical security baseline for Kubernetes clusters:

- **Audit scripts** to identify security gaps across six domains
- **HTML/JSON report generation** from audit results
- **Checklists** aligned to CIS Kubernetes Benchmark v1.8.0
- **Hardened templates** for NetworkPolicy, RBAC, and Pod security
- **CI/CD integration** via GitHub Actions with Trivy and secret detection

Developed from experience managing 43+ production workloads at 99.9%+ availability.

---

## Quick Start

```bash
# Clone the repository
git clone https://github.com/mason5052/k8s-security-baseline.git
cd k8s-security-baseline

# Run the security audit against your cluster (requires kubectl context)
./scripts/audit-cluster.sh

# Generate an HTML report from audit output
./scripts/audit-cluster.sh | python3 scripts/generate-report.py \
  --format html \
  --output report.html

# Filter report to high and critical findings only
./scripts/audit-cluster.sh | python3 scripts/generate-report.py \
  --format html \
  --output report-high-critical.html \
  --severity high,critical

# Generate JSON report for automation/SIEM integration
./scripts/audit-cluster.sh | python3 scripts/generate-report.py \
  --format json \
  --output report.json

# Run in demo mode (no cluster required)
python3 scripts/generate-report.py --format html --output demo-report.html
```

---

## Repository Structure

```
k8s-security-baseline/
├── scripts/
│   ├── audit-cluster.sh          # Automated bash audit across 6 security domains
│   └── generate-report.py        # HTML/JSON report generator (--format, --severity)
├── checklists/
│   ├── control-plane.md          # API server, etcd, audit logging, TLS (CIS 1.x, 3.x)
│   ├── worker-nodes.md           # kubelet hardening, node security (CIS 4.x)
│   ├── pod-security.md           # PSA enforcement, security contexts, capabilities
│   ├── network-security.md       # NetworkPolicy, namespace isolation, Ingress TLS
│   ├── secrets.md                # etcd encryption, ESO, Azure Key Vault, RBAC
│   └── policies.md               # RBAC, Pod Security Standards, combined reference
├── templates/
│   ├── network-policy-default-deny.yaml   # Default deny + explicit allow templates
│   └── rbac-hardened.yaml                 # Least-privilege RBAC + pod hardening
└── .github/
    └── workflows/
        └── security-audit.yml    # CI: validate, Trivy scan, report generation, secret detection
```

---

## Security Domains

### Control Plane (`checklists/control-plane.md`)
API server authentication, etcd encryption at rest, audit logging configuration,
TLS certificate management, admission controllers.

### Worker Nodes (`checklists/worker-nodes.md`)
kubelet authentication/authorization, read-only port hardening, node restriction,
kernel security, file permission hardening.

### Pod Security (`checklists/pod-security.md`)
Pod Security Admission (PSA) enforcement, `runAsNonRoot`, capability dropping (`drop: ALL`),
`readOnlyRootFilesystem`, resource limits, image scanning with Trivy.

### Network Security (`checklists/network-security.md`)
Default deny NetworkPolicy (ingress + egress), namespace isolation, Ingress TLS termination,
egress controls, service mesh mTLS (Istio/Linkerd).

### Secrets Management (`checklists/secrets.md`)
etcd EncryptionConfiguration, External Secrets Operator + Azure Key Vault integration,
RBAC restrictions on secret access, secret rotation, CI/CD secret detection.

### RBAC & Policies (`checklists/policies.md`)
Least-privilege roles, service account restrictions, `automountServiceAccountToken: false`,
namespace isolation, wildcard permission auditing.

---

## Audit Script

`scripts/audit-cluster.sh` checks all six domains automatically:

```
[PASS] API server anonymous auth is disabled
[PASS] Audit logging is configured
[FAIL] [HIGH] etcd is not encrypted at rest
[WARN] [MEDIUM] No NetworkPolicy found in namespace: staging
[PASS] Default deny NetworkPolicy in namespace: production
...
Summary: 14 passed, 2 failed, 3 warnings
```

Output format is structured for piping to `generate-report.py`.

---

## Report Generator

`scripts/generate-report.py` produces formatted reports from audit output:

| Flag | Default | Description |
|------|---------|-------------|
| `--input` | stdin | Audit output file (use `-` for stdin) |
| `--output` | `security-report.html` | Output file path |
| `--format` | `html` | Output format: `html` or `json` |
| `--severity` | all | Filter: `critical`, `high`, `medium`, `low` |
| `--title` | default | Custom report title |

HTML reports include a graded summary card (A/B/C/F) and a color-coded findings table.

---

## CI/CD Integration

The included GitHub Actions workflow (`.github/workflows/security-audit.yml`) runs on every push and PR:

| Job | What it does |
|-----|-------------|
| `validate` | shellcheck, Python syntax, YAML validation |
| `trivy-scan` | IaC misconfiguration + secret scanning (SARIF to Security tab) |
| `generate-report` | Produces HTML/JSON artifact (downloadable from Actions) |
| `secret-detection` | gitleaks + detect-secrets across full commit history |

---

## Templates

### NetworkPolicy (`templates/network-policy-default-deny.yaml`)
Ready-to-apply NetworkPolicy manifests:
- Default deny all ingress and egress
- DNS egress allow (required for cluster DNS)
- Same-namespace pod communication
- Monitoring namespace scraping
- Controlled external egress

### RBAC Hardening (`templates/rbac-hardened.yaml`)
- Namespace with `pod-security.kubernetes.io/enforce: restricted` label
- Service account with `automountServiceAccountToken: false`
- Role with least-privilege resource access
- Pod spec with all security hardening applied

---

## CIS Benchmark Coverage

| CIS Section | Checklist | Coverage |
|------------|-----------|---------|
| 1.x - Control Plane Components | `control-plane.md` | API Server, etcd, Controller Manager, Scheduler |
| 2.x - etcd | `control-plane.md` | Encryption, access controls |
| 3.x - Control Plane Config | `control-plane.md` | Audit logging, certificates |
| 4.x - Worker Nodes | `worker-nodes.md` | kubelet, node hardening |
| 5.1 - RBAC | `policies.md` | Least privilege, service accounts |
| 5.2 - Pod Security | `pod-security.md` | PSA, security contexts, capabilities |
| 5.3 - Network Policies | `network-security.md` | Default deny, namespace isolation |
| 5.4 - Secrets Management | `secrets.md` | Encryption at rest, ESO, RBAC |

---

## Author

**Mason Kim** - DevSecOps Engineer
- MS Cybersecurity @ Georgia Institute of Technology
- Certified Ethical Hacker (CEH) | HashiCorp Terraform Associate
- [github.com/mason5052](https://github.com/mason5052)

---

## License

MIT License - see [LICENSE](./LICENSE) for details.

---

## References

- [CIS Kubernetes Benchmark](https://www.cisecurity.org/benchmark/kubernetes)
- [Kubernetes Pod Security Standards](https://kubernetes.io/docs/concepts/security/pod-security-standards/)
- [NSA/CISA Kubernetes Hardening Guide](https://media.defense.gov/2022/Aug/29/2003066362/-1/-1/0/CTR_KUBERNETES_HARDENING_GUIDANCE_1.2_20220829.PDF)
- [External Secrets Operator](https://external-secrets.io/)
- [Trivy](https://trivy.dev/)
