#!/bin/bash

# =============================================================================
# API Security Scanner
# Author: Ahmed Elhiouli
# Description: Automated API endpoint security testing framework
# Usage: ./api-security-scanner.sh -u https://api.target.com -w wordlist.txt
# =============================================================================

set -euo pipefail

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Default values
TARGET_URL=""
WORDLIST=""
OUTPUT_DIR="api_scan_results"
TIMEOUT=10

# Banner
print_banner() {
    echo -e "${BLUE}"
    echo "=========================================="
    echo "          API Security Scanner"
    echo "           Ahmed Elhiouli"
    echo "=========================================="
    echo -e "${NC}"
}

# Usage information
usage() {
    echo "Usage: $0 -u <target_url> [-w <wordlist>] [-o <output_dir>]"
    echo "Options:"
    echo "  -u  Target URL (e.g., https://api.target.com)"
    echo "  -w  Wordlist for endpoint discovery (optional)"
    echo "  -o  Output directory (default: api_scan_results)"
    echo "  -t  Request timeout in seconds (default: 10)"
    exit 1
}

# Check dependencies
check_dependencies() {
    local deps=("curl" "jq")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            echo -e "${RED}[ERROR] Required tool missing: $dep${NC}"
            exit 1
        fi
    done
}

# CORS misconfiguration test
test_cors() {
    local url=$1
    echo -e "\n${YELLOW}[TEST] CORS Misconfiguration Check${NC}"
    
    local response
    response=$(curl -s -I -H "Origin: https://evil.com" -H "Access-Control-Request-Method: GET" "$url" 2>/dev/null || true)
    
    if echo "$response" | grep -q "access-control-allow-origin: *"; then
        echo -e "${RED}[VULNERABLE] CORS misconfiguration - Access-Control-Allow-Origin: *${NC}"
        echo "URL: $url" >> "$OUTPUT_DIR/cors_vulnerabilities.txt"
    elif echo "$response" | grep -q "access-control-allow-origin"; then
        echo -e "${YELLOW}[INFO] CORS headers present but restricted${NC}"
    else
        echo -e "${GREEN}[SAFE] No CORS misconfiguration detected${NC}"
    fi
}

# HTTP Method testing
test_http_methods() {
    local url=$1
    echo -e "\n${YELLOW}[TEST] HTTP Method Testing${NC}"
    
    local methods=("GET" "POST" "PUT" "DELETE" "PATCH" "OPTIONS" "HEAD")
    for method in "${methods[@]}"; do
        local status_code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" -X "$method" "$url" --connect-timeout "$TIMEOUT" 2>/dev/null || echo "000")
        
        if [[ "$status_code" != "000" && "$status_code" != "405" && "$status_code" != "404" ]]; then
            echo -e "${BLUE}[INFO] $method method allowed - Status: $status_code${NC}"
        fi
    done
}

# Information disclosure check
check_info_disclosure() {
    local url=$1
    echo -e "\n${YELLOW}[TEST] Information Disclosure Check${NC}"
    
    local response
    response=$(curl -s "$url" --connect-timeout "$TIMEOUT" 2>/dev/null || true)
    
    local sensitive_patterns=("password" "secret" "key" "token" "database" "internal" "debug")
    for pattern in "${sensitive_patterns[@]}"; do
        if echo "$response" | grep -q -i "$pattern"; then
            echo -e "${YELLOW}[INFO] Potential information disclosure: '$pattern' found${NC}"
        fi
    done
}

# Endpoint discovery from wordlist
discover_endpoints() {
    if [[ -z "$WORDLIST" || ! -f "$WORDLIST" ]]; then
        return
    fi
    
    echo -e "\n${YELLOW}[PHASE] Endpoint Discovery${NC}"
    local count=0
    
    while IFS= read -r endpoint; do
        [[ -z "$endpoint" ]] && continue
        
        local test_url="${TARGET_URL%/}/${endpoint#/}"
        local status_code
        status_code=$(curl -s -o /dev/null -w "%{http_code}" "$test_url" --connect-timeout 5 2>/dev/null || echo "000")
        
        if [[ "$status_code" != "000" && "$status_code" != "404" && "$status_code" != "403" ]]; then
            echo -e "${GREEN}[FOUND] $test_url - Status: $status_code${NC}"
            echo "$test_url" >> "$OUTPUT_DIR/discovered_endpoints.txt"
            ((count++))
        fi
    done < "$WORDLIST"
    
    echo -e "${BLUE}[INFO] Discovered $count endpoints${NC}"
}

# Main scanning function
run_security_scan() {
    echo -e "\n${GREEN}[START] Security scan initiated for: $TARGET_URL${NC}"
    
    # Create output directory
    mkdir -p "$OUTPUT_DIR"
    
    # Run security tests
    test_cors "$TARGET_URL"
    test_http_methods "$TARGET_URL"
    check_info_disclosure "$TARGET_URL"
    
    # Endpoint discovery if wordlist provided
    discover_endpoints
    
    echo -e "\n${GREEN}[COMPLETE] Scan results saved to: $OUTPUT_DIR/${NC}"
}

# Parse command line arguments
while getopts "u:w:o:t:h" opt; do
    case $opt in
        u) TARGET_URL="$OPTARG" ;;
        w) WORDLIST="$OPTARG" ;;
        o) OUTPUT_DIR="$OPTARG" ;;
        t) TIMEOUT="$OPTARG" ;;
        h) usage ;;
        *) usage ;;
    esac
done

# Validate required parameters
if [[ -z "$TARGET_URL" ]]; then
    echo -e "${RED}[ERROR] Target URL (-u) is required${NC}"
    usage
fi

# Main execution
main() {
    print_banner
    check_dependencies
    run_security_scan
}

main "$@"
