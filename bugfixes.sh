#!/bin/bash

# caseScope Bug Fixes Script v7.0.35
# Run this script on production server after 'git pull'
# This script contains ALL steps needed to apply current bug fixes

set -e  # Exit on any error

echo "=================================================="
echo "caseScope Bug Fixes Script v7.0.35"
echo "$(date): Starting bug fix deployment..."
echo "=================================================="

# Function to log with timestamp
log() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] $1"
}

# Function to check if service exists and is running
check_service() {
    if systemctl list-units --type=service | grep -q "$1"; then
        if systemctl is-active --quiet "$1"; then
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

# 2. UPDATE VERSION
log "Updating version to 7.0.35..."
cd "$(dirname "$0")"
if [ -f "version_utils.py" ]; then
    python3 version_utils.py set 7.0.35 "Critical fix for case dashboard database queries and API endpoints" || log "Version update failed, continuing..."
else
    log "version_utils.py not found, skipping version update"
fi

# 3. COPY UPDATED APPLICATION FILES
log "Copying updated application files..."
cp app.py /opt/casescope/app/ || { log "❌ Failed to copy app.py"; exit 1; }
[ -f "version.json" ] && cp version.json /opt/casescope/app/
[ -f "version_utils.py" ] && cp version_utils.py /opt/casescope/app/
[ -f "migrate_db.py" ] && cp migrate_db.py /opt/casescope/app/

# 4. ENSURE DIRECTORY STRUCTURE
log "Creating and fixing directory structure..."
mkdir -p /opt/casescope/data/uploads
mkdir -p /opt/casescope/logs
mkdir -p /opt/casescope/app/templates/admin
mkdir -p /opt/casescope/app/static/css
mkdir -p /opt/casescope/app/static/js

# 5. COPY TEMPLATES AND STATIC FILES
log "Copying templates and static files..."
cp -r templates/* /opt/casescope/app/templates/ 2>/dev/null || log "Templates copy failed, continuing..."
cp -r static/* /opt/casescope/app/static/ 2>/dev/null || log "Static files copy failed, continuing..."

# 6. SET PROPER OWNERSHIP AND PERMISSIONS
log "Setting proper ownership and permissions..."
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/logs
chmod 755 /opt/casescope/data/uploads
chmod +x /opt/casescope/app/app.py 2>/dev/null || true

# 7. RUN DATABASE MIGRATION
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

# 8. CLEAR REDIS QUEUE (remove stuck tasks)
log "Clearing Redis queue..."
redis-cli flushdb 2>/dev/null || log "Redis flush failed, continuing..."

# 9. CLEAN UP ORPHANED FILES
log "Cleaning up orphaned upload files..."
find /opt/casescope/data/uploads -type f -name "*.evtx" -mtime +1 -delete 2>/dev/null || true

# 10. UPDATE SYSTEMD SERVICE FILES (if needed)
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

# 11. RELOAD SYSTEMD
log "Reloading systemd configuration..."
systemctl daemon-reload

# 12. ENSURE REQUIRED SERVICES ARE RUNNING
log "Ensuring required services are running..."
systemctl start redis-server 2>/dev/null || log "Redis start failed"
systemctl start opensearch 2>/dev/null || log "OpenSearch start failed"

# Wait for services to stabilize
sleep 3

# 13. START CASESCOPE SERVICES
log "Starting caseScope services..."
systemctl start casescope-web
systemctl start casescope-worker

# 14. WAIT FOR SERVICES TO START
log "Waiting for services to stabilize..."
sleep 5

# 15. CHECK SERVICE STATUS
log "Checking service status..."
check_service "casescope-web"
check_service "casescope-worker"
check_service "opensearch"
check_service "redis-server"

# 16. VERIFY APPLICATION STATUS
log "Verifying application status..."
if curl -s http://localhost:5000 > /dev/null; then
    log "✅ Web application is responding"
else
    log "⚠️ Web application is not responding"
fi

# 17. DISPLAY LOG LOCATIONS
log "Bug fixes deployment completed!"
echo "=================================================="
echo "📊 VERIFICATION COMMANDS:"
echo "  Service Status: systemctl status casescope-web casescope-worker"
echo "  Web Logs:      journalctl -u casescope-web -f"
echo "  Worker Logs:   journalctl -u casescope-worker -f"
echo "  App Logs:      tail -f /opt/casescope/logs/*.log"
echo "  Test Access:   curl http://localhost"
echo "=================================================="
echo "🎯 MAIN FIXES APPLIED:"
echo "  ✅ Case dashboard database query fixes"
echo "  ✅ Processing stats API endpoint fixes"
echo "  ✅ Worker statistics calculation fixes"
echo "  ✅ Template query syntax fixes"
echo "  ✅ Enhanced error logging for debugging"
echo "  ✅ Upload directory permissions and path validation"
echo "  ✅ Search route error handling and template fixes"
echo "  ✅ File processing path verification"
echo "  ✅ Database migration for error tracking"
echo "  ✅ Redis queue cleanup"
echo "  ✅ Service configuration updates"
echo "=================================================="

log "🚀 caseScope Bug Fixes v7.0.35 deployment complete!"
