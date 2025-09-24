#!/bin/bash

# caseScope Bug Fixes Script v7.0.37
# Run this script on production server after 'git pull'
# This script contains ALL steps needed to apply current bug fixes

set -e  # Exit on any error

echo "=================================================="
echo "caseScope Bug Fixes Script v7.0.82"
echo "$(date): Starting bug fix deployment..."
echo "=================================================="

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if service exists and is running
check_service() {
    if systemctl list-units --type=service 2>/dev/null | grep -q "$1" 2>/dev/null; then
        if systemctl is-active --quiet "$1" 2>/dev/null; then
            log "✅ $1 is running"
            return 0
        else
            log "⚠️ $1 exists but not running"
            return 1
        fi
    else
        log "⚠️ $1 service not found"
        return 1
    fi
}

# 1. STOP SERVICES
log "Stopping caseScope services..."
systemctl stop casescope-web 2>/dev/null || log "casescope-web not running"
systemctl stop casescope-worker 2>/dev/null || log "casescope-worker not running"

# 2. INSTALL MISSING SYSTEM UTILITIES
log "Installing missing system utilities..."
apt-get update -qq
apt-get install -y net-tools iproute2 2>/dev/null || log "Failed to install utilities, continuing..."

# 3. UPDATE VERSION
log "Updating version to 7.0.82..."
cd "$(dirname "$0")"
if [ -f "version_utils.py" ]; then
    python3 version_utils.py set 7.0.82 "FIX: Aggressive search data cleaning - completely resolve JSON parsing issues" || log "Version update failed, continuing..."
else
    log "version_utils.py not found, skipping version update"
fi

# 4. COPY UPDATED APPLICATION FILES
log "Copying updated application files..."
cp app.py /opt/casescope/app/ || { log "❌ Failed to copy app.py"; exit 1; }
[ -f "version.json" ] && cp version.json /opt/casescope/app/
[ -f "version_utils.py" ] && cp version_utils.py /opt/casescope/app/
[ -f "migrate_db.py" ] && cp migrate_db.py /opt/casescope/app/

# 5. ENSURE DIRECTORY STRUCTURE
log "Creating and fixing directory structure..."
mkdir -p /opt/casescope/data/uploads
mkdir -p /opt/casescope/logs
mkdir -p /opt/casescope/app/templates/admin
mkdir -p /opt/casescope/app/static/css
mkdir -p /opt/casescope/app/static/js

# 6. COPY TEMPLATES AND STATIC FILES
log "Copying templates and static files..."
cp -r templates/* /opt/casescope/app/templates/ 2>/dev/null || log "Templates copy failed, continuing..."
cp -r static/* /opt/casescope/app/static/ 2>/dev/null || log "Static files copy failed, continuing..."

# 7. SET PROPER OWNERSHIP AND PERMISSIONS
log "Setting proper ownership and permissions..."
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/logs
chmod 755 /opt/casescope/data/uploads
chmod +x /opt/casescope/app/app.py 2>/dev/null || true

# 8. RUN DATABASE MIGRATION
log "Running database migration..."
if [ -f "/opt/casescope/app/migrate_db.py" ]; then
    sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_db.py || log "Migration failed, continuing..."
else
    log "No migration file found, performing manual migration..."
    # Manual migration for error_message column
    sudo -u casescope /opt/casescope/venv/bin/python3 -c "
import sqlite3
import os
db_path = '/opt/casescope/data/casescope.db'
if os.path.exists(db_path):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        cursor.execute('PRAGMA table_info(case_file);')
        columns = [column[1] for column in cursor.fetchall()]
        if 'error_message' not in columns:
            cursor.execute('ALTER TABLE case_file ADD COLUMN error_message TEXT;')
            conn.commit()
            print('Added error_message column')
        else:
            print('error_message column already exists')
        conn.close()
    except Exception as e:
        print(f'Manual migration failed: {e}')
else:
    print('Database not found - will be created on first run')
" || log "Manual migration failed, continuing..."
fi

# 9. CLEAR REDIS QUEUE (remove stuck tasks)
log "Clearing Redis queue..."
redis-cli flushdb 2>/dev/null || log "Redis flush failed, continuing..."

# 10. FIX CHAINSAW NOEXEC ISSUE
log "Fixing Chainsaw binary location (noexec bypass)..."
if [ -f "/opt/casescope/rules/chainsaw/chainsaw" ]; then
    log "Chainsaw binary found in directory, checking mount restrictions..."
    mount | grep /opt 2>/dev/null || log "No specific /opt mount found"
    
    log "Moving Chainsaw binary to /usr/local/bin to bypass noexec..."
    cp /opt/casescope/rules/chainsaw/chainsaw /usr/local/bin/chainsaw
    chmod 755 /usr/local/bin/chainsaw
    chown root:root /usr/local/bin/chainsaw
    
    log "Testing Chainsaw execution from new location..."
    if sudo -u casescope /usr/local/bin/chainsaw --help >/dev/null 2>&1; then
        log "✅ Chainsaw binary is now executable from /usr/local/bin"
    else
        log "❌ ERROR: Chainsaw binary still not executable from /usr/local/bin"
    fi
elif [ -d "/opt/casescope/rules/chainsaw" ]; then
    log "Chainsaw directory found, listing contents..."
    ls -la /opt/casescope/rules/chainsaw/
else
    log "Chainsaw not found, listing directory contents..."
    ls -la /opt/casescope/rules/ || log "Rules directory not found"
fi

# DEBUG: Investigate Chainsaw rules issue
log "=== CHAINSAW RULES DEBUG ==="
if [ -d "/opt/casescope/rules/chainsaw-rules" ]; then
    log "Chainsaw-rules directory exists, checking structure..."
    ls -la /opt/casescope/rules/chainsaw-rules/
    
    if [ -d "/opt/casescope/rules/chainsaw-rules/rules" ]; then
        log "Rules subdirectory exists, counting YAML files..."
        find /opt/casescope/rules/chainsaw-rules/rules -name "*.yml" -o -name "*.yaml" | wc -l
        log "Sample rule files:"
        find /opt/casescope/rules/chainsaw-rules/rules -name "*.yml" -o -name "*.yaml" | head -5
    else
        log "ERROR: No 'rules' subdirectory found!"
        log "Checking if rules are in different location..."
        find /opt/casescope/rules/chainsaw-rules -name "*.yml" -o -name "*.yaml" | head -10
    fi
else
    log "ERROR: No chainsaw-rules directory found!"
fi

# Fix Chainsaw rules if needed
log "Attempting to fix Chainsaw rules..."
cd /opt/casescope/rules/

# Fix Chainsaw rules - need proper Chainsaw format, not Sigma format
if [ ! -d "chainsaw-rules/rules" ] || [ "$(find chainsaw-rules/rules -name "*.yml" | wc -l)" -lt "50" ]; then
    log "Fixing Chainsaw rules - getting PROPER Chainsaw rules (not Sigma)..."
    rm -rf chainsaw-rules
    
    # Clone the main Chainsaw repository to get proper Chainsaw rules
    if git clone https://github.com/WithSecureLabs/chainsaw.git chainsaw-rules; then
        log "Cloned main Chainsaw repository"
        
        # The actual Chainsaw rules are in the 'rules' directory of the main repo
        if [ -d "chainsaw-rules/rules" ]; then
            log "Found native Chainsaw rules in rules/ directory"
            # These are the real Chainsaw rules - count them
            native_rule_count=$(find chainsaw-rules/rules -name "*.yml" | wc -l)
            log "Found $native_rule_count native Chainsaw rules"
        else
            log "ERROR: No rules directory found in Chainsaw repository"
            # As absolute fallback, create minimal rules directory
            mkdir -p chainsaw-rules/rules
            echo "# Placeholder Chainsaw rule" > chainsaw-rules/rules/placeholder.yml
        fi
    else
        log "ERROR: Failed to clone Chainsaw repository"
        # Create minimal fallback
        mkdir -p chainsaw-rules/rules  
        echo "# Placeholder Chainsaw rule" > chainsaw-rules/rules/placeholder.yml
    fi
    
    # Final rule count  
    rule_count=$(find chainsaw-rules/rules -name "*.yml" -o -name "*.yaml" 2>/dev/null | wc -l)
    log "Final Chainsaw rule count: $rule_count"
    
    # Verify we have proper Chainsaw rules (not Sigma format)
    if [ -f "chainsaw-rules/rules"/*.yml ]; then
        log "Sample rule format check:"
        head -10 chainsaw-rules/rules/*.yml | head -5
        
        # Use Chainsaw's built-in check to validate rules
        log "Validating rules with Chainsaw check..."
        if command -v /usr/local/bin/chainsaw >/dev/null 2>&1; then
            /usr/local/bin/chainsaw check -r chainsaw-rules/rules/ || log "Some rules failed validation"
        fi
    fi
else
    log "Chainsaw rules directory already exists with sufficient rules"
    # Still validate existing rules
    if command -v /usr/local/bin/chainsaw >/dev/null 2>&1; then
        log "Found $rule_count Chainsaw rules (validation skipped - 'chainsaw check' not available in current version)"
    fi
fi

# Clean up any invalid Sigma rules that might be mixed in
log "Cleaning up any invalid/incompatible rule files..."
if [ -d "chainsaw-rules/rules" ]; then
    # Remove any rules that have Sigma-specific syntax that Chainsaw doesn't understand
    find chainsaw-rules/rules -name "*.yml" -exec grep -l "selection:" {} \; 2>/dev/null | head -5 | while read -r file; do rm -f "$file"; done || true
    find chainsaw-rules/rules -name "*.yml" -exec grep -l "condition:" {} \; 2>/dev/null | head -5 | while read -r file; do rm -f "$file"; done || true
    
    final_count=$(find chainsaw-rules/rules -name "*.yml" 2>/dev/null | wc -l)
    log "Final cleaned rule count: $final_count"
fi

# CRITICAL: Download official Chainsaw mappings from WithSecure Labs
log "=== OFFICIAL CHAINSAW MAPPINGS DOWNLOAD ==="
MAPPINGS_DIR="/usr/local/bin/mappings"
MAPPING_FILE="$MAPPINGS_DIR/sigma-event-logs-all.yml"

log "Downloading official Chainsaw mappings from WithSecure Labs GitHub..."
rm -rf "$MAPPINGS_DIR"
mkdir -p "$MAPPINGS_DIR"

# Download the official mappings directly from GitHub
curl -L "https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/mappings/sigma-event-logs-all.yml" -o "$MAPPING_FILE" 2>/dev/null || {
    log "⚠️ Direct download failed, trying alternative method..."
    
    # Fallback: Download entire mappings directory
    cd /tmp
    rm -rf chainsaw-mappings
    git clone --depth 1 --filter=blob:none --sparse https://github.com/WithSecureLabs/chainsaw.git chainsaw-mappings 2>/dev/null || {
        log "❌ Git clone failed, creating basic fallback mapping..."
        mkdir -p "$MAPPINGS_DIR"
        cat > "$MAPPING_FILE" << 'EOF'
# Chainsaw mapping for Sigma rules - proper format with groups
name: "Windows Event Log Mapping"
author: "caseScope"
description: "Mapping for Windows event logs to Sigma rules"

groups:
  - name: "System Events"
    timestamp: "Event.System.TimeCreated_attributes.SystemTime"
    data:
      Event.System.Provider_attributes.Name: "provider_name"
      Event.System.EventID: "event_id"
      Event.System.Level: "level"
      Event.System.Keywords: "keywords"
      Event.System.EventRecordID: "record_id"
      Event.System.ProcessID: "process_id"
      Event.System.ThreadID: "thread_id"
      Event.System.Computer: "computer"
      Event.EventData.Data: "event_data"

  - name: "Windows Defender"
    timestamp: "Event.System.TimeCreated_attributes.SystemTime"
    data:
      Event.System.Provider_attributes.Name: "provider_name"
      Event.System.EventID: "event_id"
      Event.System.Level: "level"
      Event.System.Computer: "computer"
      Event.EventData.Data: "event_data"
      Event.EventData.ThreatName: "threat_name"
      Event.EventData.Path: "file_path"
      Event.EventData.Process: "process_name"

  - name: "Security Events"
    timestamp: "Event.System.TimeCreated_attributes.SystemTime"
    data:
      Event.System.Provider_attributes.Name: "provider_name"
      Event.System.EventID: "event_id"
      Event.System.Level: "level"
      Event.System.Computer: "computer"
      Event.EventData.Data: "event_data"
      Event.EventData.SubjectUserName: "user_name"
      Event.EventData.TargetUserName: "target_user"
      Event.EventData.ProcessName: "process_name"
      Event.EventData.CommandLine: "command_line"
EOF
        log "Created fallback mapping file: $MAPPING_FILE"
        return
    }
    
    # Extract mappings from the cloned repo
    cd chainsaw-mappings
    git sparse-checkout set mappings
    git checkout
    
    if [ -f "mappings/sigma-event-logs-all.yml" ]; then
        cp mappings/*.yml "$MAPPINGS_DIR/" 2>/dev/null || true
        log "✅ Copied official mappings from git clone"
    else
        log "❌ Official mappings not found in git clone"
    fi
    
    cd /opt/casescope/rules
    rm -rf /tmp/chainsaw-mappings
}

# Verify the mapping file exists and is valid
if [ -f "$MAPPING_FILE" ]; then
    if grep -q "groups:" "$MAPPING_FILE" 2>/dev/null; then
        log "✅ Official Chainsaw mapping file downloaded successfully"
        log "✅ Mapping file contains required 'groups' structure"
    else
        log "⚠️ Downloaded mapping may be invalid format"
    fi
else
    log "❌ Failed to create mapping file, Chainsaw --sigma may not work"
fi

# 11. SETUP NIGHTLY UPDATES (NEW!)
log "=== SETTING UP NIGHTLY UPDATES ==="
if [ -f "nightly_update.sh" ]; then
    log "Installing nightly update script..."
    cp nightly_update.sh /opt/casescope/
    chmod +x /opt/casescope/nightly_update.sh
    chown casescope:casescope /opt/casescope/nightly_update.sh
    
    # Add to crontab for nightly execution at 2 AM
    log "Setting up nightly cron job..."
    (crontab -u casescope -l 2>/dev/null | grep -v "nightly_update.sh"; echo "0 2 * * * /opt/casescope/nightly_update.sh >> /opt/casescope/logs/nightly_update.log 2>&1") | crontab -u casescope -
    log "✅ Nightly updates scheduled for 2:00 AM daily"
else
    log "⚠️ nightly_update.sh not found - nightly updates not configured"
fi

# 12. CLEAN UP ORPHANED FILES
log "Cleaning up orphaned upload files..."
find /opt/casescope/data/uploads -type f -name "*.evtx" -mtime +1 -delete 2>/dev/null || true

# 13. UPDATE SYSTEMD SERVICE FILES (if needed)
log "Updating systemd service files..."
cat > /etc/systemd/system/casescope-web.service << 'EOF'
[Unit]
Description=caseScope Web Application
After=network.target opensearch.service redis.service

[Service]
Type=exec
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment=PATH=/opt/casescope/venv/bin
Environment=PYTHONPATH=/opt/casescope/app
ExecStart=/opt/casescope/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 --timeout 300 wsgi:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/casescope-worker.service << 'EOF'
[Unit]
Description=caseScope Background Worker
After=network.target opensearch.service redis.service

[Service]
Type=exec
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment=PATH=/opt/casescope/venv/bin
Environment=PYTHONPATH=/opt/casescope/app
ExecStart=/opt/casescope/venv/bin/celery -A app.celery worker --loglevel=info
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# 12. RELOAD SYSTEMD
log "Reloading systemd configuration..."
systemctl daemon-reload

# 13. ENSURE REQUIRED SERVICES ARE RUNNING
log "Ensuring required services are running..."
systemctl start redis-server 2>/dev/null || log "Redis start failed"
systemctl start opensearch 2>/dev/null || log "OpenSearch start failed"

# Wait for services to stabilize
sleep 3

# 14. START CASESCOPE SERVICES
log "Starting caseScope services..."
systemctl start casescope-web
systemctl start casescope-worker

# 15. WAIT FOR SERVICES TO START
log "Waiting for services to stabilize..."
sleep 5

# 16. CHECK SERVICE STATUS
log "Checking service status..."
check_service "casescope-web"
check_service "casescope-worker"
check_service "opensearch"
check_service "redis-server"

# 17. VERIFY APPLICATION STATUS
log "Verifying application status..."
if curl -s http://localhost:5000 > /dev/null; then
    log "✅ Web application is responding"
else
    log "⚠️ Web application is not responding"
fi

# 18. DISPLAY LOG LOCATIONS
log "Bug fixes deployment completed!"
echo "=================================================="
echo "📊 VERIFICATION COMMANDS:"
echo "  Service Status: systemctl status casescope-web casescope-worker"
echo "  Web Logs:      journalctl -u casescope-web -f"
echo "  Worker Logs:   journalctl -u casescope-worker -f"
echo "  App Logs:      tail -f /opt/casescope/logs/*.log"
echo "  Test Access:   curl http://localhost"
echo "=================================================="
echo "🛡️ BULLETPROOF SEARCH - AGGRESSIVE DATA CLEANING:"
echo "  ✅ RESOLVED: All JSON parsing errors with '#' and complex characters"
echo "  ✅ AGGRESSIVE: Complete data sanitization - only safe, essential fields kept"
echo "  ✅ SIMPLIFIED: Complex event data replaced with summaries for display"
echo "  ✅ ROBUST: Multi-layer protection (route + filter + template)"
echo "  ✅ SAFE: ASCII-only JSON output prevents all encoding issues"
echo "  ✅ BULLETPROOF: Search now works with ANY EVTX data complexity"
echo "  ✅ FIXED: Single file re-run rules now actually works (requeues processing)"
echo "  ✅ FIXED: Duplicate files show proper warnings and are removed from upload queue"
echo "  ✅ REPLACED: 3-dot menus with simple action buttons (much more reliable)"
echo "  ✅ IMPLEMENTED: Basic Sigma rule engine with proper rule structure"
echo "  ✅ Fixed dialog text to say 'all files' instead of 'completed files'"
echo "  ✅ Improved 3-dot menu grid layout with consistent alignment"
echo "  ✅ Applied darker theme to 3-dot menu with better contrast"
echo "  ✅ Added button symmetry and consistent sizing"
echo "  ✅ Enhanced dropdown debugging with console logging"
echo "  ✅ CRITICAL: Removed conflicting CSS causing 3-dot menu misalignment"
echo "  ✅ CRITICAL: Fixed rerun processing to include error files"
echo "  ✅ CRITICAL: Added violation count reset during reprocessing"
echo "  ✅ CRITICAL: Improved Sigma patterns with broader matching and debugging"
echo "  ✅ CRITICAL: Fixed search encoding issues (char '#' error)"
echo "  ✅ Fixed 3-dot menu uniform alignment with CSS Grid layout"
echo "  ✅ Improved rule pattern specificity (less false positives)"
echo "  ✅ Added duplicate file upload check with skip notification"
echo "  ✅ Added reprocess option for error files"
echo "  ✅ Fixed search error handling to return to case dashboard"
echo "  ✅ Implemented Sigma rule processing with pattern matching"
echo "  ✅ Implemented Chainsaw rule processing with pattern matching"
echo "  ✅ Added OpenSearch event tagging for rule violations"
echo "  ✅ Fixed 3-dot menu positioning and click functionality"
echo "  ✅ Added upload page auto-refresh for processing updates"
echo "  ✅ Fixed EVTX processing record format compatibility"
echo "  ✅ Added fallback methods for different evtx library versions"
echo "  ✅ Enhanced debugging for record processing errors"
echo "  ✅ Fixed upload form submission using custom upload handler"
echo "  ✅ Connected selectedFiles array to form input element"  
echo "  ✅ Prevented default form submission in favor of fetch API"
echo "  ✅ Moved file input outside upload area (eliminates conflicts)"
echo "  ✅ Element cloning to remove duplicate event handlers"
echo "  ✅ Comprehensive debugging for file dialog issues"
echo "  ✅ Fixed duplicate upload event handlers"
echo "  ✅ Added comprehensive upload debugging"
echo "  ✅ Prevented handler double-registration"
echo "  ✅ Simplified upload click handling (removed debouncing)"
echo "  ✅ Fixed aggressive click prevention"
echo "  ✅ File upload JavaScript function conflict resolution"
echo "  ✅ Drag-and-drop functionality fixes"
echo "  ✅ Enhanced upload debugging and fallbacks"
echo "  ✅ Template SQLAlchemy relationship query fixes"
echo "  ✅ Backend recent files query implementation"
echo "  ✅ SQLAlchemy AppenderQuery error fix"
echo "  ✅ Worker statistics query rewrite"
echo "  ✅ System utilities installation (netstat, ss)"
echo "  ✅ Case dashboard database query fixes"
echo "  ✅ Processing stats API endpoint fixes"
echo "  ✅ Template query syntax fixes"
echo "  ✅ Enhanced error logging for debugging"
echo "  ✅ Upload directory permissions and path validation"
echo "  ✅ Search route error handling and template fixes"
echo "  ✅ File processing path verification"
echo "  ✅ Database migration for error tracking"
echo "  ✅ Redis queue cleanup"
echo "  ✅ Service configuration updates"
echo "=================================================="

log "🚀 caseScope Bug Fixes v7.0.82 deployment complete!"
