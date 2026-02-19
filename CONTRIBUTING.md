# Contributing

Contributions are welcome. This document outlines how to participate.

## How to Contribute

1. **Fork** the repository
2. **Create a branch** from `main` (`git checkout -b feature/your-change`)
3. **Make your changes** following the guidelines below
4. **Test** your changes (run `shellcheck` on scripts, validate YAML)
5. **Commit** with a clear message
6. **Open a Pull Request** against `main`

## Guidelines

### Checklists
- Reference CIS Kubernetes Benchmark v1.8.0 section numbers
- Include severity level (CRITICAL, HIGH, MEDIUM, LOW)
- Provide remediation commands where applicable

### Scripts
- Shell scripts must pass `shellcheck`
- Python scripts must be compatible with Python 3.8+
- Include `--help` output for new CLI flags

### Templates
- YAML manifests must pass `kubectl --dry-run=client` validation
- Include comments explaining security rationale for each setting

### Commit Messages
- Use present tense ("Add feature" not "Added feature")
- Reference CIS section numbers when applicable (e.g., "Add CIS 5.2.6 check")

## Reporting Issues

- Use GitHub Issues for bugs and feature requests
- Include Kubernetes version and cluster type (managed/self-managed)
- For security vulnerabilities, email directly instead of opening a public issue

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
