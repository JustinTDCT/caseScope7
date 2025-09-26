#!/bin/bash

# caseScope Comprehensive Diagnostic Script
# Tests all components and reports status

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

echo -e "${BLUE}=== caseScope v7.0.101 Diagnostic Report ===${NC}"
echo ""

# System Information
echo -e "${BLUE}=== SYSTEM INFORMATION ===${NC}"
echo "Date: $(date)"
echo "Hostname: $(hostname)"
echo "OS: $(lsb_release -d 2>/dev/null | cut -f2 || echo 'Unknown')"
echo "Kernel: $(uname -r)"
echo "Uptime: $(uptime -p 2>/dev/null || uptime)"
echo ""

# Disk Space
echo -e "${BLUE}=== DISK SPACE ===${NC}"
df -h /opt/casescope 2>/dev/null || df -h /
echo ""

# Memory Usage
echo -e "${BLUE}=== MEMORY USAGE ===${NC}"
free -h
echo ""

# Network
echo -e "${BLUE}=== NETWORK STATUS ===${NC}"
echo "IP Address: $(hostname -I | awk '{print $1}' 2>/dev/null || echo 'Unknown')"
ss -tlnp | grep -E "(5000|9200|6379)" || echo "No services listening on expected ports"
echo ""

# File System Check
echo -e "${BLUE}=== FILE SYSTEM CHECK ===${NC}"
log "Checking caseScope directories..."
for dir in "/opt/casescope" "/opt/casescope/app" "/opt/casescope/data" "/opt/casescope/logs" "/opt/casescope/rules"; do
    if [ -d "$dir" ]; then
        echo "✓ $dir ($(du -sh $dir 2>/dev/null | cut -f1))"
    else
        log_error "$dir missing"
    fi
done

log "Checking critical files..."
for file in "/usr/local/bin/chainsaw" "/usr/local/bin/mappings/sigma-event-logs-all.yml" "/opt/casescope/data/casescope.db"; do
    if [ -f "$file" ]; then
        echo "✓ $file ($(du -sh $file 2>/dev/null | cut -f1))"
    else
        log_error "$file missing"
    fi
done
echo ""

# Service Status
echo -e "${BLUE}=== SERVICE STATUS ===${NC}"
for service in "opensearch" "redis-server" "nginx" "casescope-web" "casescope-worker"; do
    if systemctl is-active --quiet $service; then
        log "✓ $service is running"
    else
        log_error "$service is not running"
        systemctl status $service --no-pager -l | head -10
    fi
done
echo ""

# Application Connectivity Tests
echo -e "${BLUE}=== CONNECTIVITY TESTS ===${NC}"
log "Testing OpenSearch..."
if curl -s "http://localhost:9200/_cluster/health" >/dev/null 2>&1; then
    HEALTH=$(curl -s "http://localhost:9200/_cluster/health" | python3 -m json.tool 2>/dev/null || echo "JSON parse failed")
    log "✓ OpenSearch responding"
    echo "$HEALTH"
else
    log_error "OpenSearch not responding"
fi

log "Testing Redis..."
if redis-cli ping >/dev/null 2>&1; then
    log "✓ Redis responding"
else
    log_error "Redis not responding"
fi

log "Testing Web Application..."
HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 2>/dev/null || echo "000")
if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
    log "✓ Web application responding (HTTP $HTTP_CODE)"
else
    log_error "Web application not responding (HTTP $HTTP_CODE)"
fi

# Test search route specifically (should redirect to login if not authenticated)
log "Testing Search Route..."
SEARCH_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/search 2>/dev/null || echo "000")
if [ "$SEARCH_CODE" = "302" ] || [ "$SEARCH_CODE" = "200" ]; then
    log "✓ Search route responding (HTTP $SEARCH_CODE)"
else
    log_error "Search route not responding (HTTP $SEARCH_CODE)"
fi
echo ""

# Database Check
echo -e "${BLUE}=== DATABASE CHECK ===${NC}"
if [ -f "/opt/casescope/data/casescope.db" ]; then
    DB_SIZE=$(du -sh /opt/casescope/data/casescope.db | cut -f1)
    log "✓ Database file exists ($DB_SIZE)"
    
    # Test database connectivity
    if [ -d "/opt/casescope/app" ]; then
        cd /opt/casescope/app
        USER_COUNT=$(/opt/casescope/venv/bin/python3 -c "
import sys
sys.path.insert(0, '/opt/casescope/app')
try:
    from app import db, app as flask_app, User
    with flask_app.app_context():
        print(User.query.count())
except Exception as e:
    print(f'ERROR: {e}')
" 2>/dev/null || echo "0")
        
        if [[ "$USER_COUNT" =~ ^[0-9]+$ ]] && [ "$USER_COUNT" -ge 0 ]; then
            log "✓ Database connectivity OK ($USER_COUNT users)"
        else
            log_error "Database connectivity failed: $USER_COUNT"
        fi
    else
        log_warning "App directory not found - cannot test database connectivity"
    fi
else
    log_error "Database file missing"
fi
echo ""

# Rules Check
echo -e "${BLUE}=== RULES CHECK ===${NC}"
if [ -d "/opt/casescope/rules/sigma-rules" ]; then
    SIGMA_COUNT=$(find /opt/casescope/rules/sigma-rules -name "*.yml" -o -name "*.yaml" | wc -l)
    log "✓ Sigma rules: $SIGMA_COUNT files"
else
    log_error "Sigma rules directory missing"
fi

if [ -d "/opt/casescope/rules/chainsaw-rules" ]; then
    CHAINSAW_COUNT=$(find /opt/casescope/rules/chainsaw-rules -name "*.yml" -o -name "*.yaml" | wc -l)
    log "✓ Chainsaw rules: $CHAINSAW_COUNT files"
else
    log_error "Chainsaw rules directory missing"
fi

if [ -f "/usr/local/bin/chainsaw" ]; then
    CHAINSAW_VERSION=$(/usr/local/bin/chainsaw --version 2>/dev/null | head -1 || echo "unknown")
    log "✓ Chainsaw binary: $CHAINSAW_VERSION"
else
    log_error "Chainsaw binary missing"
fi
echo ""

# Log Analysis
echo -e "${BLUE}=== RECENT LOG ANALYSIS ===${NC}"
if [ -f "/opt/casescope/logs/error.log" ]; then
    ERROR_COUNT=$(tail -100 /opt/casescope/logs/error.log 2>/dev/null | grep -c "ERROR" || echo "0")
    log "Recent errors in application log: $ERROR_COUNT"
    if [ "$ERROR_COUNT" -gt 0 ]; then
        echo "Last 3 errors:"
        tail -100 /opt/casescope/logs/error.log | grep "ERROR" | tail -3
    fi
else
    log_warning "Application error log not found"
fi

# Check for worker issues
WORKER_ERRORS=$(journalctl -u casescope-worker --since "1 hour ago" --no-pager -l | grep -c "ERROR" 2>/dev/null || echo "0")
log "Recent worker errors: $WORKER_ERRORS"
if [ "$WORKER_ERRORS" -gt 0 ]; then
    echo "Recent worker errors:"
    journalctl -u casescope-worker --since "1 hour ago" --no-pager -l | grep "ERROR" | tail -3
fi
echo ""

# Performance Metrics
echo -e "${BLUE}=== PERFORMANCE METRICS ===${NC}"
echo "Load Average: $(uptime | awk -F'load average:' '{print $2}')"
echo "CPU Usage: $(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)%"
echo "Memory Usage: $(free | grep Mem | awk '{printf("%.1f%%\n", $3/$2 * 100.0)}')"

if command -v iostat >/dev/null 2>&1; then
    echo "Disk I/O: $(iostat -d 1 2 | tail -1 | awk '{print "Read: " $3 " KB/s, Write: " $4 " KB/s"}')"
fi
echo ""

# Summary
echo -e "${BLUE}=== DIAGNOSTIC SUMMARY ===${NC}"
ISSUES=0

# Critical checks
[ ! -f "/usr/local/bin/chainsaw" ] && ISSUES=$((ISSUES+1))
[ ! -f "/opt/casescope/data/casescope.db" ] && ISSUES=$((ISSUES+1))
[ ! -f "/usr/local/bin/mappings/sigma-event-logs-all.yml" ] && ISSUES=$((ISSUES+1))

for service in "opensearch" "casescope-web" "casescope-worker"; do
    if ! systemctl is-active --quiet $service; then
        ISSUES=$((ISSUES+1))
    fi
done

if [ "$ISSUES" -eq 0 ]; then
    log "✓ All critical components are functional"
    echo -e "${GREEN}System Status: HEALTHY${NC}"
else
    log_error "$ISSUES critical issues detected"
    echo -e "${RED}System Status: NEEDS ATTENTION${NC}"
fi

echo ""
echo -e "${BLUE}Diagnostic completed. Check logs above for detailed information.${NC}"
echo -e "${BLUE}For support, provide this output to the administrator.${NC}"
echo ""
echo -e "${YELLOW}Usage: sudo /opt/casescope/debug.sh (after deployment)${NC}"
echo -e "${YELLOW}       or sudo ./debug.sh (from source directory)${NC}"
