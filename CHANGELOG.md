# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [0.3.0] - 2026-02-19

### Added
- SOC 2 Trust Services Criteria mapping in README
- GitHub Actions CI workflow (validate, Trivy scan, report generation, secret detection)
- .gitignore for Python artifacts and generated reports
- requirements.txt with project dependencies

## [0.2.0] - 2026-02-19

### Added
- Dedicated checklists: pod-security.md, network-security.md, secrets.md
- HTML/JSON report generator (generate-report.py) with severity filtering
- Updated README with repository structure, report flags, and CIS coverage matrix

## [0.1.0] - 2026-02-07

### Added
- Initial release with CIS Kubernetes Benchmark v1.8.0 coverage
- Automated audit script (audit-cluster.sh) covering 6 security domains
- Control plane and worker node security checklists
- RBAC and policies checklist
- NetworkPolicy default deny templates
- RBAC hardened configuration templates
- MIT License
