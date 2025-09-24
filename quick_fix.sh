#!/bin/bash

# Quick Fix Script for Flask App and Celery Issues
# Fixes the immediate circular import and service startup problems

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

echo -e "${BLUE}Quick Fix Script - Resolving Flask and Celery Issues${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    echo "Usage: sudo ./quick_fix.sh"
    exit 1
fi

# 1. STOP SERVICES
log "Stopping services..."
systemctl stop casescope-web casescope-worker

# 2. FIX FLASK APP CIRCULAR IMPORT
log "Fixing Flask app circular import issue..."
cd /opt/casescope/app

# Create a backup
cp app.py app.py.quickfix.backup.$(date +%s)

# Fix the circular import by ensuring app is defined before being used
python3 << 'PYTHON_APP_FIX'
with open('app.py', 'r') as f:
    content = f.read()

# Find the problematic line where app is used before being fully defined
old_line = "upload_dir = app.config.get('UPLOAD_FOLDER', '/opt/casescope/data/uploads')"
new_line = "upload_dir = '/opt/casescope/data/uploads'  # Default upload directory"

if old_line in content:
    content = content.replace(old_line, new_line)
    print("✓ Fixed Flask app config reference")
else:
    print("✗ Could not find problematic app config line")

# Also fix any other early app.config references
import re
# Replace any app.config references before app is fully initialized
pattern = r"app\.config\.get\([^)]+\)"
matches = re.findall(pattern, content)
for match in matches:
    if "UPLOAD_FOLDER" in match:
        content = content.replace(match, "'/opt/casescope/data/uploads'")
        print(f"✓ Fixed early config reference: {match}")

with open('app.py', 'w') as f:
    f.write(content)

print("Flask app circular import fix applied")
PYTHON_APP_FIX

# 3. SIMPLE DATABASE RESET (without importing the problematic app)
log "Resetting database using SQLite directly..."
if [ -f /opt/casescope/data/casescope.db ]; then
    sqlite3 /opt/casescope/data/casescope.db << 'SQL'
UPDATE case_file SET 
    processing_status = 'pending',
    processing_progress = 0,
    sigma_violations = 0,
    chainsaw_violations = 0,
    error_message = NULL,
    event_count = 0;
SQL
    log "✓ Database reset using SQLite directly"
else
    log "Database file not found, skipping reset"
fi

# 4. FIX CELERY WORKER SERVICE CONFIGURATION
log "Fixing Celery worker service..."

# Create a simpler, more reliable Celery service
cat > /etc/systemd/system/casescope-worker.service << 'EOF'
[Unit]
Description=caseScope Celery Worker
After=network.target redis.service opensearch.service

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment="PATH=/opt/casescope/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=/opt/casescope/app"
ExecStartPre=/bin/sleep 10
ExecStart=/opt/casescope/venv/bin/celery -A app.celery worker --loglevel=info --concurrency=2
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 5. ENSURE PROPER PERMISSIONS
log "Setting proper permissions..."
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/logs

if [ -f /opt/casescope/data/casescope.db ]; then
    chown casescope:casescope /opt/casescope/data/casescope.db
    chmod 664 /opt/casescope/data/casescope.db
fi

# 6. ENSURE LOG DIRECTORY
mkdir -p /opt/casescope/logs
chown casescope:casescope /opt/casescope/logs
chmod 755 /opt/casescope/logs

# Create basic log files
touch /opt/casescope/logs/application.log
chown casescope:casescope /opt/casescope/logs/application.log
chmod 664 /opt/casescope/logs/application.log

# 7. CLEAR REDIS
log "Clearing Redis queue..."
redis-cli FLUSHALL || log "Could not clear Redis"

# 8. RELOAD SYSTEMD
log "Reloading systemd..."
systemctl daemon-reload

# 9. START SERVICES STEP BY STEP
log "Starting web service..."
systemctl start casescope-web
sleep 5

# Check if web service started
if systemctl is-active --quiet casescope-web; then
    log "✓ Web service started successfully"
else
    log_error "Web service failed to start"
    systemctl status casescope-web --no-pager
fi

log "Starting worker service..."
systemctl start casescope-worker
sleep 5

# Check if worker service started
if systemctl is-active --quiet casescope-worker; then
    log "✓ Worker service started successfully"
else
    log_error "Worker service failed to start"
    log "Checking worker service logs..."
    journalctl -u casescope-worker --no-pager -l | tail -20
fi

# 10. FINAL STATUS CHECK
log "Final status check..."
echo -e "${BLUE}=== SERVICE STATUS ===${NC}"
systemctl status casescope-web --no-pager
echo ""
systemctl status casescope-worker --no-pager

echo -e "${BLUE}=== LOG FILES ===${NC}"
ls -la /opt/casescope/logs/

echo -e "${BLUE}=== REDIS TEST ===${NC}"
redis-cli ping

echo -e "${BLUE}=== OPENSEARCH TEST ===${NC}"
curl -s http://localhost:9200/_cluster/health || echo "OpenSearch not responding"

log "Quick fix completed!"
echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "  1. Check service status: systemctl status casescope-web casescope-worker"
echo "  2. Monitor logs: tail -f /opt/casescope/logs/application.log"
echo "  3. Watch worker: journalctl -u casescope-worker -f"
echo "  4. Try uploading a file to test processing"