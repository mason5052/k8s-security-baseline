#!/bin/bash
#
# Kubernetes Security Audit Script
# Based on CIS Kubernetes Benchmark v1.8.0
#
# Author: Mason Kim
# Repository: https://github.com/mason5052/k8s-security-baseline
#

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Counters
PASS=0
FAIL=0
WARN=0

print_header() {
    echo ""
    echo "========================================"
    echo " $1"
    echo "========================================"
}

check_pass() {
    echo -e "${GREEN}[PASS]${NC} $1"
    ((PASS++))
}

check_fail() {
    echo -e "${RED}[FAIL]${NC} $1"
    ((FAIL++))
}

check_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
    ((WARN++))
}

# Check if running with kubectl access
check_prerequisites() {
    print_header "Prerequisites Check"
    
    if ! command -v kubectl &> /dev/null; then
        check_fail "kubectl not found in PATH"
        exit 1
    fi
    
    if ! kubectl cluster-info &> /dev/null; then
        check_fail "Cannot connect to Kubernetes cluster"
        exit 1
    fi
    
    check_pass "kubectl configured and cluster accessible"
}

# 1. Control Plane Security
audit_control_plane() {
    print_header "1. Control Plane Security"
    
    # Check API Server anonymous auth
    echo "Checking API Server configuration..."
    
    # Check for anonymous authentication
    if kubectl get pods -n kube-system -l component=kube-apiserver -o yaml 2>/dev/null | grep -q "anonymous-auth=false"; then
        check_pass "Anonymous authentication disabled"
    else
        check_warn "Verify anonymous-auth=false in API server"
    fi
    
    # Check for RBAC authorization mode
    if kubectl get pods -n kube-system -l component=kube-apiserver -o yaml 2>/dev/null | grep -q "authorization-mode.*RBAC"; then
        check_pass "RBAC authorization enabled"
    else
        check_warn "Verify RBAC authorization mode"
    fi
    
    # Check audit logging
    if kubectl get pods -n kube-system -l component=kube-apiserver -o yaml 2>/dev/null | grep -q "audit-log-path"; then
        check_pass "Audit logging configured"
    else
        check_warn "Audit logging may not be configured"
    fi
}

# 2. Worker Node Security
audit_worker_nodes() {
    print_header "2. Worker Node Security"
    
    # Check kubelet authentication
    echo "Checking kubelet configurations..."
    
    # Get nodes
    NODES=$(kubectl get nodes -o jsonpath='{.items[*].metadata.name}')
    
    for node in $NODES; do
        echo "  Checking node: $node"
        
        # Check node conditions
        READY=$(kubectl get node "$node" -o jsonpath='{.status.conditions[?(@.type=="Ready")].status}')
        if [ "$READY" == "True" ]; then
            check_pass "Node $node is Ready"
        else
            check_fail "Node $node is not Ready"
        fi
    done
}

# 3. Pod Security
audit_pod_security() {
    print_header "3. Pod Security"
    
    echo "Checking for privileged containers..."
    
    # Find privileged containers
    PRIV_PODS=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] | select(.spec.containers[].securityContext.privileged==true) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || echo "")
    
    if [ -z "$PRIV_PODS" ]; then
        check_pass "No privileged containers found"
    else
        check_warn "Privileged containers found:"
        echo "$PRIV_PODS" | while read -r pod; do
            echo "    - $pod"
        done
    fi
    
    # Check for containers running as root
    echo "Checking for containers running as root..."
    
    ROOT_PODS=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] | select(.spec.containers[].securityContext.runAsNonRoot!=true) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null | head -10 || echo "")
    
    if [ -z "$ROOT_PODS" ]; then
        check_pass "All containers configured with runAsNonRoot"
    else
        check_warn "Some containers may run as root (showing first 10)"
    fi
    
    # Check for host network usage
    echo "Checking for hostNetwork usage..."
    
    HOSTNET_PODS=$(kubectl get pods --all-namespaces -o json | \
        jq -r '.items[] | select(.spec.hostNetwork==true) | "\(.metadata.namespace)/\(.metadata.name)"' 2>/dev/null || echo "")
    
    if [ -z "$HOSTNET_PODS" ]; then
        check_pass "No pods using hostNetwork"
    else
        check_warn "Pods using hostNetwork found"
    fi
}

# 4. RBAC Security
audit_rbac() {
    print_header "4. RBAC Security"
    
    # Check cluster-admin bindings
    echo "Checking cluster-admin role bindings..."
    
    CLUSTER_ADMINS=$(kubectl get clusterrolebindings -o json | \
        jq -r '.items[] | select(.roleRef.name=="cluster-admin") | .metadata.name' 2>/dev/null || echo "")
    
    echo "Cluster-admin bindings:"
    echo "$CLUSTER_ADMINS" | while read -r binding; do
        if [ -n "$binding" ]; then
            echo "    - $binding"
        fi
    done
    
    # Check for default service account usage
    echo "Checking for pods using default service account..."
    
    DEFAULT_SA_COUNT=$(kubectl get pods --all-namespaces -o json | \
        jq '[.items[] | select(.spec.serviceAccountName=="default" or .spec.serviceAccountName==null)] | length' 2>/dev/null || echo "0")
    
    if [ "$DEFAULT_SA_COUNT" -eq 0 ]; then
        check_pass "No pods using default service account"
    else
        check_warn "$DEFAULT_SA_COUNT pods using default service account"
    fi
}

# 5. Network Policies
audit_network_policies() {
    print_header "5. Network Policies"
    
    # Check for namespaces without network policies
    echo "Checking network policy coverage..."
    
    NAMESPACES=$(kubectl get namespaces -o jsonpath='{.items[*].metadata.name}')
    
    for ns in $NAMESPACES; do
        # Skip system namespaces for this check
        if [[ "$ns" == "kube-system" || "$ns" == "kube-public" || "$ns" == "kube-node-lease" ]]; then
            continue
        fi
        
        NP_COUNT=$(kubectl get networkpolicies -n "$ns" --no-headers 2>/dev/null | wc -l)
        
        if [ "$NP_COUNT" -gt 0 ]; then
            check_pass "Namespace '$ns' has $NP_COUNT network policy(ies)"
        else
            check_warn "Namespace '$ns' has no network policies"
        fi
    done
}

# 6. Secrets Management
audit_secrets() {
    print_header "6. Secrets Management"
    
    # Check for secrets in environment variables
    echo "Checking for secrets exposed as environment variables..."
    
    SECRET_ENV_COUNT=$(kubectl get pods --all-namespaces -o json | \
        jq '[.items[].spec.containers[].env[]? | select(.valueFrom.secretKeyRef != null)] | length' 2>/dev/null || echo "0")
    
    if [ "$SECRET_ENV_COUNT" -gt 0 ]; then
        check_warn "$SECRET_ENV_COUNT secrets exposed via environment variables"
        echo "    Consider using volume mounts for sensitive data"
    else
        check_pass "No secrets exposed via environment variables"
    fi
    
    # Check for encryption at rest
    echo "Checking encryption configuration..."
    check_warn "Manually verify encryption at rest configuration"
}

# Print summary
print_summary() {
    print_header "Audit Summary"
    echo ""
    echo -e "  ${GREEN}Passed:${NC}   $PASS"
    echo -e "  ${RED}Failed:${NC}   $FAIL"
    echo -e "  ${YELLOW}Warnings:${NC} $WARN"
    echo ""
    echo "Total checks: $((PASS + FAIL + WARN))"
    echo ""
    
    if [ $FAIL -gt 0 ]; then
        echo -e "${RED}Action Required: Please review failed checks above${NC}"
        exit 1
    elif [ $WARN -gt 0 ]; then
        echo -e "${YELLOW}Review Recommended: Please verify warning items${NC}"
        exit 0
    else
        echo -e "${GREEN}All checks passed!${NC}"
        exit 0
    fi
}

# Main execution
main() {
    echo "=========================================="
    echo " Kubernetes Security Audit"
    echo " Based on CIS Benchmark v1.8.0"
    echo " $(date)"
    echo "=========================================="
    
    check_prerequisites
    audit_control_plane
    audit_worker_nodes
    audit_pod_security
    audit_rbac
    audit_network_policies
    audit_secrets
    print_summary
}

main "$@"
