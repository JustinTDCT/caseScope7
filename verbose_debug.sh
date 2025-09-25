#!/bin/bash

# caseScope Verbose Debug Script
# Makes everything extremely verbose for debugging
# Usage: sudo ./verbose_debug.sh

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
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

log_debug() {
    echo -e "${CYAN}[$(date '+%Y-%m-%d %H:%M:%S')] DEBUG:${NC} $1"
}

echo -e "${BLUE}=================================================${NC}"
echo -e "${BLUE}caseScope Verbose Debug Script${NC}"
echo -e "${BLUE}Making everything extremely verbose for debugging${NC}"
echo -e "${BLUE}=================================================${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    echo "Usage: sudo ./verbose_debug.sh"
    exit 1
fi

# 1. SYSTEM DIAGNOSTICS
log "=== SYSTEM DIAGNOSTICS ==="
log_debug "OS Information:"
cat /etc/os-release | head -5

log_debug "System Resources:"
echo "Memory: $(free -h | grep Mem: | awk '{print $2 " total, " $3 " used, " $7 " available"}')"
echo "Disk: $(df -h / | tail -1 | awk '{print $2 " total, " $3 " used, " $4 " available"}')"
echo "CPU: $(nproc) cores"

log_debug "Network Utilities:"
which netstat && echo "✓ netstat available" || echo "✗ netstat missing"
which ss && echo "✓ ss available" || echo "✗ ss missing"

# 2. SERVICE STATUS DIAGNOSTICS
log "=== SERVICE STATUS DIAGNOSTICS ==="
SERVICES=("opensearch" "redis-server" "nginx" "casescope-web" "casescope-worker")

for service in "${SERVICES[@]}"; do
    log_debug "Checking $service:"
    
    # Check if service exists
    if systemctl list-unit-files | grep -q "^$service"; then
        echo "  Service file: ✓ exists"
        
        # Check if enabled
        if systemctl is-enabled --quiet "$service" 2>/dev/null; then
            echo "  Enabled: ✓ yes"
        else
            echo "  Enabled: ✗ no"
        fi
        
        # Check if active
        if systemctl is-active --quiet "$service"; then
            echo "  Status: ✓ active"
        else
            echo "  Status: ✗ inactive"
            # Show why it failed
            systemctl status "$service" --no-pager -l | head -10
        fi
        
        # Check port if applicable
        case $service in
            "opensearch")
                if netstat -tlnp 2>/dev/null | grep -q ":9200"; then
                    echo "  Port 9200: ✓ listening"
                else
                    echo "  Port 9200: ✗ not listening"
                fi
                ;;
            "redis-server")
                if netstat -tlnp 2>/dev/null | grep -q ":6379"; then
                    echo "  Port 6379: ✓ listening"
                else
                    echo "  Port 6379: ✗ not listening"
                fi
                ;;
            "nginx")
                if netstat -tlnp 2>/dev/null | grep -q ":80"; then
                    echo "  Port 80: ✓ listening"
                else
                    echo "  Port 80: ✗ not listening"
                fi
                ;;
            "casescope-web")
                if netstat -tlnp 2>/dev/null | grep -q ":5000"; then
                    echo "  Port 5000: ✓ listening"
                else
                    echo "  Port 5000: ✗ not listening"
                fi
                ;;
        esac
    else
        echo "  Service file: ✗ not found"
    fi
    echo ""
done

# 3. CASESCOPE INSTALLATION DIAGNOSTICS
log "=== CASESCOPE INSTALLATION DIAGNOSTICS ==="

log_debug "Directory Structure:"
if [ -d /opt/casescope ]; then
    echo "✓ /opt/casescope exists"
    ls -la /opt/casescope/
    
    # Check subdirectories
    for dir in "app" "data" "logs" "config" "venv" "rules"; do
        if [ -d "/opt/casescope/$dir" ]; then
            echo "✓ /opt/casescope/$dir exists"
            ls -la "/opt/casescope/$dir/" | head -5
        else
            echo "✗ /opt/casescope/$dir missing"
        fi
    done
else
    log_error "/opt/casescope directory not found!"
    exit 1
fi

log_debug "Virtual Environment:"
VENV_PATH="/opt/casescope/venv"
if [ -d "$VENV_PATH" ]; then
    echo "✓ Virtual environment exists"
    echo "Python: $($VENV_PATH/bin/python3 --version)"
    echo "Pip: $($VENV_PATH/bin/pip --version)"
    
    log_debug "Installed packages:"
    $VENV_PATH/bin/pip list | grep -E "(flask|celery|redis|opensearch|pyevtx)" || echo "No key packages found"
else
    echo "✗ Virtual environment missing"
fi

log_debug "Database:"
if [ -f /opt/casescope/data/casescope.db ]; then
    echo "✓ Database file exists"
    echo "Size: $(du -h /opt/casescope/data/casescope.db | cut -f1)"
    echo "Permissions: $(ls -la /opt/casescope/data/casescope.db)"
    
    # Check database contents
    echo "Tables:"
    sqlite3 /opt/casescope/data/casescope.db ".tables" || echo "Could not read database"
    
    echo "Case count:"
    sqlite3 /opt/casescope/data/casescope.db "SELECT COUNT(*) FROM case;" 2>/dev/null || echo "Could not count cases"
    
    echo "File count:"
    sqlite3 /opt/casescope/data/casescope.db "SELECT COUNT(*) FROM case_file;" 2>/dev/null || echo "Could not count files"
else
    echo "✗ Database file missing"
fi

# 4. PYTHON IMPORT TESTING
log "=== PYTHON IMPORT TESTING ==="
cd /opt/casescope/app

log_debug "Testing critical imports:"
sudo -u casescope $VENV_PATH/bin/python3 << 'PYTHON_VERBOSE_TEST'
import sys
print(f"Python executable: {sys.executable}")
print(f"Python path: {sys.path[:3]}...")

imports_to_test = [
    'flask', 'flask_login', 'flask_sqlalchemy', 'flask_wtf',
    'celery', 'redis', 'opensearchpy', 'pyevtx', 'xmltodict',
    'psutil', 'yaml', 'hashlib', 'pathlib', 'subprocess'
]

successful_imports = []
failed_imports = []

for module in imports_to_test:
    try:
        if module == 'opensearchpy':
            import opensearchpy
            version = getattr(opensearchpy, '__version__', 'unknown')
        elif module == 'flask':
            import flask
            version = flask.__version__
        elif module == 'celery':
            import celery
            version = celery.__version__
        else:
            exec(f"import {module}")
            version = "imported"
        
        successful_imports.append(f"{module} ({version})")
        print(f"✓ {module} - {version}")
    except Exception as e:
        failed_imports.append(f"{module}: {e}")
        print(f"✗ {module} - {e}")

print(f"\nSummary: {len(successful_imports)} successful, {len(failed_imports)} failed")
if failed_imports:
    print("Failed imports:")
    for fail in failed_imports:
        print(f"  - {fail}")
PYTHON_VERBOSE_TEST

# 5. APPLICATION MODULE TESTING
log "=== APPLICATION MODULE TESTING ==="
cd /opt/casescope/app

log_debug "Testing app.py import:"
sudo -u casescope $VENV_PATH/bin/python3 << 'PYTHON_APP_TEST'
import sys
sys.path.insert(0, '/opt/casescope/app')

try:
    print("Attempting to import app module...")
    import app
    print("✓ App module imported successfully")
    
    # Check key objects
    if hasattr(app, 'app'):
        print("✓ Flask app object exists")
        print(f"  App name: {app.app.name}")
        print(f"  Debug mode: {app.app.debug}")
    else:
        print("✗ Flask app object missing")
    
    if hasattr(app, 'db'):
        print("✓ Database object exists")
    else:
        print("✗ Database object missing")
    
    if hasattr(app, 'celery'):
        print("✓ Celery object exists")
    else:
        print("✗ Celery object missing")
    
    # Test database models
    try:
        from app import User, Case, CaseFile
        print("✓ Database models imported")
    except Exception as e:
        print(f"✗ Database models import failed: {e}")
    
except Exception as e:
    print(f"✗ App module import failed: {e}")
    import traceback
    traceback.print_exc()
PYTHON_APP_TEST

# 6. OPENSEARCH TESTING
log "=== OPENSEARCH TESTING ==="
log_debug "Testing OpenSearch connection:"

if curl -s http://localhost:9200/_cluster/health >/dev/null 2>&1; then
    echo "✓ OpenSearch responding"
    
    # Get cluster info
    echo "Cluster health:"
    curl -s http://localhost:9200/_cluster/health | python3 -m json.tool 2>/dev/null || echo "Could not parse JSON"
    
    echo "Cluster info:"
    curl -s http://localhost:9200/ | python3 -m json.tool 2>/dev/null || echo "Could not get cluster info"
    
    # Check indices
    echo "Existing indices:"
    curl -s http://localhost:9200/_cat/indices?v || echo "Could not list indices"
    
else
    echo "✗ OpenSearch not responding"
    log_debug "Checking OpenSearch service:"
    systemctl status opensearch --no-pager | head -10
fi

# 7. REDIS TESTING
log "=== REDIS TESTING ==="
log_debug "Testing Redis connection:"

if redis-cli ping >/dev/null 2>&1; then
    echo "✓ Redis responding"
    
    # Get Redis info
    echo "Redis info:"
    redis-cli info server | head -5
    
    # Check queue status
    echo "Queue length:"
    redis-cli llen celery || echo "No celery queue"
    
else
    echo "✗ Redis not responding"
    log_debug "Checking Redis service:"
    systemctl status redis-server --no-pager | head -10
fi

# 8. CELERY TESTING
log "=== CELERY TESTING ==="
cd /opt/casescope/app

log_debug "Testing Celery configuration:"
sudo -u casescope $VENV_PATH/bin/python3 << 'PYTHON_CELERY_TEST'
import sys
sys.path.insert(0, '/opt/casescope/app')

try:
    from app import celery
    print("✓ Celery object accessible")
    
    # Test Celery connection
    i = celery.control.inspect()
    active = i.active()
    if active is not None:
        print(f"✓ Celery broker connection successful")
        print(f"  Active tasks: {len(active.get(list(active.keys())[0], []) if active else [])}")
    else:
        print("✗ Celery broker connection failed")
    
    # Check registered tasks
    registered = i.registered()
    if registered:
        print("Registered tasks:")
        for worker, tasks in registered.items():
            print(f"  Worker {worker}: {len(tasks)} tasks")
            for task in tasks[:3]:  # Show first 3
                print(f"    - {task}")
    
except Exception as e:
    print(f"✗ Celery test failed: {e}")
    import traceback
    traceback.print_exc()
PYTHON_CELERY_TEST

# 9. LOG FILE ANALYSIS
log "=== LOG FILE ANALYSIS ==="
log_debug "Recent log entries:"

LOG_FILES=(
    "/opt/casescope/logs/application.log"
    "/opt/casescope/logs/error.log"
    "/opt/casescope/logs/access.log"
    "/opt/casescope/logs/celery.log"
)

for logfile in "${LOG_FILES[@]}"; do
    if [ -f "$logfile" ]; then
        echo "=== $logfile ==="
        echo "Size: $(du -h "$logfile" | cut -f1)"
        echo "Permissions: $(ls -la "$logfile")"
        echo "Recent entries (last 10 lines):"
        tail -10 "$logfile" 2>/dev/null || echo "Could not read log file"
        echo ""
    else
        echo "✗ $logfile not found"
    fi
done

# System logs
log_debug "Recent systemd journal entries:"
echo "=== casescope-web logs ==="
journalctl -u casescope-web --no-pager -l | tail -10

echo "=== casescope-worker logs ==="
journalctl -u casescope-worker --no-pager -l | tail -10

# 10. FILE PROCESSING STATUS
log "=== FILE PROCESSING STATUS ==="
log_debug "Database file processing status:"

if [ -f /opt/casescope/data/casescope.db ]; then
    sqlite3 /opt/casescope/data/casescope.db << 'SQL'
.headers on
.mode column
SELECT 
    id,
    original_filename,
    processing_status,
    processing_progress,
    sigma_violations,
    chainsaw_violations,
    event_count,
    error_message
FROM case_file
ORDER BY id DESC
LIMIT 10;
SQL
else
    echo "Database not accessible"
fi

# 11. WEB SERVICE TESTING
log "=== WEB SERVICE TESTING ==="
log_debug "Testing web service response:"

if curl -s http://localhost:5000 >/dev/null 2>&1; then
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000)
    echo "✓ Web service responding (HTTP $HTTP_CODE)"
    
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        echo "✓ Response code indicates working service"
    else
        echo "⚠ Unusual response code - service may have issues"
    fi
else
    echo "✗ Web service not responding"
fi

# 12. RULES AND MAPPINGS
log "=== RULES AND MAPPINGS STATUS ==="
log_debug "Sigma rules:"
if [ -d /opt/casescope/rules/sigma-rules ]; then
    SIGMA_COUNT=$(find /opt/casescope/rules/sigma-rules -name "*.yml" -o -name "*.yaml" | wc -l)
    echo "✓ Sigma rules directory exists"
    echo "  Rule count: $SIGMA_COUNT"
    echo "  Sample rules:"
    find /opt/casescope/rules/sigma-rules -name "*.yml" | head -3
else
    echo "✗ Sigma rules directory missing"
fi

log_debug "Chainsaw rules:"
if [ -d /opt/casescope/rules/chainsaw-rules ]; then
    CHAINSAW_COUNT=$(find /opt/casescope/rules/chainsaw-rules -name "*.yml" -o -name "*.yaml" | wc -l)
    echo "✓ Chainsaw rules directory exists"
    echo "  Rule count: $CHAINSAW_COUNT"
    
    # Check for chainsaw binary
    if [ -f /usr/local/bin/chainsaw ]; then
        echo "✓ Chainsaw binary found at /usr/local/bin/chainsaw"
    elif [ -f /opt/casescope/rules/chainsaw ]; then
        echo "✓ Chainsaw binary found at /opt/casescope/rules/chainsaw"
    else
        echo "✗ Chainsaw binary not found"
    fi
else
    echo "✗ Chainsaw rules directory missing"
fi

echo -e "${BLUE}=================================================${NC}"
log "Verbose debugging completed!"
echo -e "${BLUE}=================================================${NC}"
echo ""
echo -e "${GREEN}Summary - Look for any ✗ or ERROR markers above${NC}"
echo -e "${YELLOW}Next steps if issues found:${NC}"
echo "  1. Fix any missing services or directories"
echo "  2. Address any failed Python imports"
echo "  3. Check log files for specific errors"
echo "  4. Verify database and file permissions"
echo ""
echo -e "${CYAN}If everything shows ✓, try uploading a file and run this script again${NC}"
echo -e "${CYAN}to see processing status and any new errors.${NC}"
