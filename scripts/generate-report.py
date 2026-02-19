#!/usr/bin/env python3
"""
Kubernetes Security Audit Report Generator
Parses audit-cluster.sh output and generates a formatted HTML or JSON report.

Usage:
    ./scripts/audit-cluster.sh | python3 scripts/generate-report.py --format html --output report.html
    python3 scripts/generate-report.py --input audit.log --format html --output report.html --severity high,critical
    python3 scripts/generate-report.py --format json --output report.json
"""

import argparse
import sys
import re
import json
from datetime import datetime, timezone
from pathlib import Path


SEVERITY_WEIGHTS = {"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}

SEVERITY_COLORS = {
    "critical": "#d32f2f",
    "high":     "#f57c00",
    "medium":   "#fbc02d",
    "low":      "#388e3c",
    "info":     "#0288d1",
    "pass":     "#2e7d32",
    "warning":  "#f57c00",
    "fail":     "#c62828",
}

CHECK_CATEGORIES = [
    "Control Plane",
    "Worker Nodes",
    "Pod Security",
    "RBAC",
    "Network Policies",
    "Secrets Management",
]


def parse_args():
    parser = argparse.ArgumentParser(
        description="Generate security audit report from audit-cluster.sh output"
    )
    parser.add_argument(
        "--input", "-i",
        default="-",
        help="Input file (audit-cluster.sh output). Use '-' for stdin (default: stdin)",
    )
    parser.add_argument(
        "--output", "-o",
        default="security-report.html",
        help="Output file path (default: security-report.html)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["html", "json"],
        default="html",
        help="Output format: html or json (default: html)",
    )
    parser.add_argument(
        "--severity", "-s",
        default=None,
        help="Comma-separated severity filter, e.g. high,critical (default: all)",
    )
    parser.add_argument(
        "--title",
        default="Kubernetes Security Audit Report",
        help="Report title",
    )
    return parser.parse_args()


def parse_audit_output(lines):
    """
    Parse structured output from audit-cluster.sh.
    Supported line formats:
        [PASS] API server authentication enabled
        [FAIL] [HIGH] etcd not encrypted at rest
        [WARN] [MEDIUM] Pod Security Standards not enforced on namespace: default
        [INFO] Checking control plane...
    """
    results = []
    category = "General"

    category_patterns = {cat: re.compile(re.escape(cat), re.IGNORECASE) for cat in CHECK_CATEGORIES}

    for line in lines:
        line = line.strip()
        if not line:
            continue

        # Detect category context from header lines
        for cat, pattern in category_patterns.items():
            if pattern.search(line) and not line.startswith("["):
                category = cat
                break

        pass_match = re.match(r"\[PASS\]\s+(.*)", line, re.IGNORECASE)
        fail_match = re.match(r"\[FAIL\]\s+(?:\[([A-Z]+)\]\s+)?(.*)", line, re.IGNORECASE)
        warn_match = re.match(r"\[WARN(?:ING)?\]\s+(?:\[([A-Z]+)\]\s+)?(.*)", line, re.IGNORECASE)
        info_match = re.match(r"\[INFO\]\s+(.*)", line, re.IGNORECASE)

        if pass_match:
            results.append({
                "status":   "pass",
                "severity": "low",
                "message":  pass_match.group(1),
                "category": category,
            })
        elif fail_match:
            sev = (fail_match.group(1) or "high").lower()
            results.append({
                "status":   "fail",
                "severity": sev if sev in SEVERITY_WEIGHTS else "high",
                "message":  fail_match.group(2),
                "category": category,
            })
        elif warn_match:
            sev = (warn_match.group(1) or "medium").lower()
            results.append({
                "status":   "warning",
                "severity": sev if sev in SEVERITY_WEIGHTS else "medium",
                "message":  warn_match.group(2),
                "category": category,
            })
        elif info_match:
            results.append({
                "status":   "info",
                "severity": "info",
                "message":  info_match.group(1),
                "category": category,
            })

    # Fallback: return example results when no structured input is provided
    if not results:
        results = _example_results()

    return results


def _example_results():
    """
    Example findings representing a typical cluster audit.
    Used when no stdin/file input is provided (demo mode).
    """
    return [
        # Control Plane
        {"status": "pass",    "severity": "low",    "category": "Control Plane",       "message": "API server authentication is enabled (--anonymous-auth=false)"},
        {"status": "pass",    "severity": "low",    "category": "Control Plane",       "message": "Audit logging is configured and writing to /var/log/audit"},
        {"status": "pass",    "severity": "low",    "category": "Control Plane",       "message": "TLS certificates are valid; rotation policy is configured"},
        {"status": "fail",    "severity": "high",   "category": "Control Plane",       "message": "etcd is not encrypted at rest - EncryptionConfiguration not applied"},
        {"status": "pass",    "severity": "low",    "category": "Control Plane",       "message": "RBAC authorization mode is enabled"},
        # Worker Nodes
        {"status": "pass",    "severity": "low",    "category": "Worker Nodes",        "message": "kubelet anonymous authentication is disabled"},
        {"status": "pass",    "severity": "low",    "category": "Worker Nodes",        "message": "Read-only port (10255) is disabled on all nodes"},
        {"status": "warning", "severity": "medium", "category": "Worker Nodes",        "message": "NodeRestriction admission plugin not confirmed active"},
        {"status": "pass",    "severity": "low",    "category": "Worker Nodes",        "message": "kubelet webhook authorization mode is configured"},
        # Pod Security
        {"status": "pass",    "severity": "low",    "category": "Pod Security",        "message": "Pod Security Admission labels applied to production namespace"},
        {"status": "fail",    "severity": "high",   "category": "Pod Security",        "message": "Containers running as root (UID 0) detected in namespace: default"},
        {"status": "warning", "severity": "medium", "category": "Pod Security",        "message": "Resource limits not set on 3 deployments in namespace: staging"},
        {"status": "pass",    "severity": "low",    "category": "Pod Security",        "message": "No privileged containers found outside kube-system"},
        # RBAC
        {"status": "pass",    "severity": "low",    "category": "RBAC",               "message": "No wildcard resource permissions in ClusterRoles (excluding system roles)"},
        {"status": "pass",    "severity": "low",    "category": "RBAC",               "message": "automountServiceAccountToken: false on application service accounts"},
        {"status": "warning", "severity": "medium", "category": "RBAC",               "message": "Default service account has RoleBindings in 2 non-system namespaces"},
        {"status": "pass",    "severity": "low",    "category": "RBAC",               "message": "No cluster-admin bindings to non-system subjects found"},
        # Network Policies
        {"status": "pass",    "severity": "low",    "category": "Network Policies",   "message": "Default deny NetworkPolicy present in namespace: production"},
        {"status": "fail",    "severity": "medium", "category": "Network Policies",   "message": "No NetworkPolicy found in namespace: staging - traffic unrestricted"},
        {"status": "pass",    "severity": "low",    "category": "Network Policies",   "message": "Egress to external IPs is restricted by NetworkPolicy"},
        # Secrets Management
        {"status": "pass",    "severity": "low",    "category": "Secrets Management", "message": "No plaintext secrets detected in pod environment variables"},
        {"status": "warning", "severity": "high",   "category": "Secrets Management", "message": "Secrets accessible to overly broad service accounts in namespace: dev"},
        {"status": "pass",    "severity": "low",    "category": "Secrets Management", "message": "External Secrets Operator is managing production secrets"},
    ]


def filter_by_severity(results, severity_filter):
    if not severity_filter:
        return results
    allowed = {s.strip().lower() for s in severity_filter.split(",")}
    return [
        r for r in results
        if r["severity"] in allowed or r["status"] == "pass"
    ]


def compute_summary(results):
    summary = {
        "total":    len(results),
        "pass":     sum(1 for r in results if r["status"] == "pass"),
        "fail":     sum(1 for r in results if r["status"] == "fail"),
        "warning":  sum(1 for r in results if r["status"] == "warning"),
        "critical": sum(1 for r in results if r["severity"] == "critical" and r["status"] == "fail"),
        "high":     sum(1 for r in results if r["severity"] == "high" and r["status"] in ("fail", "warning")),
        "medium":   sum(1 for r in results if r["severity"] == "medium" and r["status"] in ("fail", "warning")),
    }
    if summary["fail"] == 0 and summary["warning"] == 0:
        summary["grade"] = "A"
    elif summary["critical"] > 0 or summary["high"] > 2:
        summary["grade"] = "F"
    elif summary["high"] > 0:
        summary["grade"] = "C"
    elif summary["warning"] > 3:
        summary["grade"] = "B"
    else:
        summary["grade"] = "B+"
    return summary


def render_html(results, summary, title, severity_filter):
    generated_at = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    severity_note = f" (filter: {severity_filter})" if severity_filter else ""

    rows_html = ""
    for r in results:
        status_color = SEVERITY_COLORS.get(r["status"], "#555")
        sev_color    = SEVERITY_COLORS.get(r["severity"], "#555")
        rows_html += f"""
        <tr>
          <td><span class="badge" style="background:{status_color}">{r['status'].upper()}</span></td>
          <td><span class="badge" style="background:{sev_color}">{r['severity'].upper()}</span></td>
          <td>{r['category']}</td>
          <td>{r['message']}</td>
        </tr>"""

    grade_color = {
        "A": "#2e7d32", "B+": "#388e3c", "B": "#558b2f",
        "C": "#f57c00", "F": "#c62828",
    }.get(summary["grade"], "#555")

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         margin: 0; background: #f5f5f5; color: #212121; }}
  .header {{ background: #1a237e; color: white; padding: 24px 32px; }}
  .header h1 {{ margin: 0; font-size: 22px; }}
  .header small {{ opacity: .7; font-size: 12px; }}
  .container {{ max-width: 1100px; margin: 24px auto; padding: 0 16px; }}
  .summary {{ display: flex; gap: 16px; flex-wrap: wrap; margin-bottom: 24px; }}
  .card {{ background: white; border-radius: 8px; padding: 16px 24px;
           flex: 1; min-width: 110px; box-shadow: 0 1px 4px rgba(0,0,0,.12); text-align: center; }}
  .card .value {{ font-size: 32px; font-weight: 700; }}
  .card .label {{ font-size: 12px; color: #757575; margin-top: 4px; }}
  .grade {{ font-size: 40px; font-weight: 900; color: {grade_color}; }}
  table {{ width: 100%; border-collapse: collapse; background: white;
           box-shadow: 0 1px 4px rgba(0,0,0,.12); border-radius: 8px; overflow: hidden; }}
  th {{ background: #1a237e; color: white; padding: 10px 14px;
        text-align: left; font-size: 13px; }}
  td {{ padding: 9px 14px; font-size: 13px; border-bottom: 1px solid #f0f0f0; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #fafafa; }}
  .badge {{ display: inline-block; padding: 2px 8px; border-radius: 12px;
            color: white; font-size: 11px; font-weight: 600; }}
  .footer {{ text-align: center; color: #9e9e9e; font-size: 11px; margin: 24px 0; }}
</style>
</head>
<body>
<div class="header">
  <h1>{title}{severity_note}</h1>
  <small>Generated: {generated_at} | Based on CIS Kubernetes Benchmark v1.8.0</small>
</div>
<div class="container">
  <div class="summary">
    <div class="card"><div class="value grade">{summary['grade']}</div>
      <div class="label">Overall Grade</div></div>
    <div class="card"><div class="value" style="color:#2e7d32">{summary['pass']}</div>
      <div class="label">Passed</div></div>
    <div class="card"><div class="value" style="color:#c62828">{summary['fail']}</div>
      <div class="label">Failed</div></div>
    <div class="card"><div class="value" style="color:#f57c00">{summary['warning']}</div>
      <div class="label">Warnings</div></div>
    <div class="card"><div class="value" style="color:#d32f2f">{summary['critical']}</div>
      <div class="label">Critical</div></div>
    <div class="card"><div class="value" style="color:#f57c00">{summary['high']}</div>
      <div class="label">High</div></div>
    <div class="card"><div class="value">{summary['total']}</div>
      <div class="label">Total Checks</div></div>
  </div>
  <table>
    <thead>
      <tr>
        <th style="width:80px">Status</th>
        <th style="width:90px">Severity</th>
        <th style="width:160px">Category</th>
        <th>Finding</th>
      </tr>
    </thead>
    <tbody>{rows_html}
    </tbody>
  </table>
  <div class="footer">
    k8s-security-baseline &mdash;
    <a href="https://github.com/mason5052/k8s-security-baseline" style="color:#9e9e9e">
      github.com/mason5052/k8s-security-baseline
    </a>
  </div>
</div>
</body>
</html>"""


def render_json(results, summary):
    return json.dumps({
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "summary": summary,
        "findings": results,
    }, indent=2)


def main():
    args = parse_args()

    # Read input
    if args.input == "-":
        if sys.stdin.isatty():
            # No piped input - run in demo mode
            print("[INFO] No input provided. Running in demo mode with example findings.", file=sys.stderr)
            lines = []
        else:
            lines = sys.stdin.readlines()
    else:
        lines = Path(args.input).read_text().splitlines()

    results = parse_audit_output(lines)
    results = filter_by_severity(results, args.severity)

    # Sort: fail > warning > pass, then by severity weight descending
    results.sort(key=lambda r: (
        0 if r["status"] == "fail" else 1 if r["status"] == "warning" else 2,
        -SEVERITY_WEIGHTS.get(r["severity"], 0),
    ))

    summary = compute_summary(results)

    if args.format == "json":
        output = render_json(results, summary)
    else:
        output = render_html(results, summary, args.title, args.severity)

    if args.output == "-":
        print(output)
    else:
        Path(args.output).write_text(output)
        print(f"Report written to: {args.output}", file=sys.stderr)
        print(
            f"Summary: {summary['pass']} passed, {summary['fail']} failed, "
            f"{summary['warning']} warnings | Grade: {summary['grade']}",
            file=sys.stderr,
        )


if __name__ == "__main__":
    main()
