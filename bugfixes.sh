#!/bin/bash

# caseScope v7.0.116 Bug Fixes Script
# This script contains all bug fixes and updates for the current version
# Run this after: git pull

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging functions
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')] $1${NC}"
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}"
}

log_info() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')] INFO: $1${NC}"
}

# Get script directory
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Extract version from version.json
if [ -f "$SCRIPT_DIR/version.json" ]; then
    VERSION=$(python3 -c "import json; print(json.load(open('$SCRIPT_DIR/version.json'))['version'])" 2>/dev/null || echo "7.0.116")
else
    VERSION="7.0.116"
fi

log "=== caseScope v$VERSION Bug Fixes ==="
log "Applying all accumulated bug fixes and updates..."

# Ensure we're running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root (use sudo)"
    exit 1
fi

# Stop services
log "Stopping caseScope services..."
systemctl stop casescope-web 2>/dev/null || true
systemctl stop casescope-worker 2>/dev/null || true

# Apply search field name fixes to app.py
log "Applying search field name fixes..."
if [ -f "/opt/casescope/app/app.py" ]; then
    # Update search fields to match actual indexed structure
    sed -i 's/"event_data\.event\.eventdata\.\*\^2",/"source_file^3",\n                                        "event_data.event.eventdata.*^2",/' /opt/casescope/app/app.py
    sed -i 's/"event_data\.event\.system\.channel\^1\.5",/"event_data.event.system.channel^2",/' /opt/casescope/app/app.py
    sed -i 's/"event_data\.event\.system\.provider_name\^1\.5"/"event_data.event.system.computer^2",\n                                        "event_data.event.system.eventid^3",\n                                        "event_data.event.system.eventrecordid^1.5"/' /opt/casescope/app/app.py
    
    log "✓ Search field mappings updated to match indexed data structure"
else
    log_warning "app.py not found - search fixes may not be applied"
fi

# Update version references in app.py
log "Updating version references..."
if [ -f "/opt/casescope/app/app.py" ]; then
    sed -i "s/return version_data\.get('version', '7\.0\.[0-9]\+'/return version_data.get('version', '7.0.116'/g" /opt/casescope/app/app.py
    sed -i 's/return "7\.0\.[0-9]\+"/return "7.0.116"/g' /opt/casescope/app/app.py
    sed -i 's/"version": "7\.0\.[0-9]\+"/"version": "7.0.116"/g' /opt/casescope/app/app.py
    log "✓ Version references updated to v$VERSION"
fi

# Ensure proper file permissions
log "Setting file permissions..."
chown -R casescope:casescope /opt/casescope/
chmod -R 755 /opt/casescope/app/
chmod -R 755 /opt/casescope/data/
chmod 664 /opt/casescope/data/casescope.db 2>/dev/null || true
chmod -R 755 /opt/casescope/logs/
chmod -R 755 /opt/casescope/rules/

# Ensure OpenSearch data directory permissions
if [ -d "/opt/opensearch/data" ]; then
    chown -R casescope:casescope /opt/opensearch/data
    log "✓ OpenSearch data directory permissions updated"
fi

# Restart services
log "Restarting services..."
systemctl daemon-reload
systemctl start opensearch
sleep 5
systemctl start casescope-web
systemctl start casescope-worker

# Wait for services to start
log "Waiting for services to initialize..."
sleep 10

# Check service status
log "Checking service status..."
if systemctl is-active --quiet casescope-web; then
    log "✓ caseScope web service is running"
else
    log_error "caseScope web service failed to start"
fi

if systemctl is-active --quiet casescope-worker; then
    log "✓ caseScope worker service is running"
else
    log_error "caseScope worker service failed to start"
fi

if systemctl is-active --quiet opensearch; then
    log "✓ OpenSearch service is running"
else
    log_error "OpenSearch service failed to start"
fi

# Test OpenSearch connectivity
log "Testing OpenSearch connectivity..."
if curl -s "http://localhost:9200/_cluster/health" >/dev/null 2>&1; then
    log "✓ OpenSearch is responding"
    
    # Check for existing indices
    INDICES=$(curl -s "http://localhost:9200/_cat/indices/casescope*" 2>/dev/null | awk '{print $3}' | tr '\n' ' ')
    if [ -n "$INDICES" ]; then
        log "✓ Found existing indices: $INDICES"
        log "ℹ️  Indices preserved - search should work with existing data"
    else
        log "ℹ️  No existing indices found - upload files to create indices"
    fi
else
    log_error "OpenSearch is not responding"
fi

log "=== Bug Fixes Complete ==="
log "caseScope v$VERSION is ready!"
log ""
log "🔍 SEARCH FIXES APPLIED:"
log "  • Fixed field name mismatch: EventID -> eventid (lowercase)"
log "  • Updated search fields to match indexed data structure"
log "  • Added debug queries: test_match_all, test_eventid_4624"
log ""
log "📊 INDEX PRESERVATION:"
log "  • OpenSearch data is now preserved during install/deploy"
log "  • Existing indices should persist across reinstalls"
log ""
log "🧪 TEST SEARCHES:"
log "  • test_match_all - Returns any 5 documents"
log "  • test_eventid_4624 - Tests EventID 4624 with correct field"
log "  • eventid:4624 - Search for EventID 4624 (lowercase)"
log "  • computer:ENGINEERING5 - Search by computer name"
log ""
log "Access the application at: http://your-server-ip"
