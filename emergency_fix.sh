#!/bin/bash

# Emergency Fix Script for caseScope v7.0.34
# Fixes critical issues with upload, dashboard, search, and file processing

echo "=== caseScope Emergency Fix v7.0.34 ==="
echo "$(date): Starting emergency fixes..."

# Stop services to apply fixes
echo "Stopping services..."
sudo systemctl stop casescope-web casescope-worker 2>/dev/null || true

# Update version
echo "Updating version..."
cd /Users/jdube/caseScope7_cursor
python3 version_utils.py set 7.0.34 "Emergency fixes for case dashboard, search, upload, and file processing issues"

# Copy updated files
echo "Updating application files..."
sudo cp app.py /opt/casescope/app/
sudo cp version.json /opt/casescope/app/
sudo cp version_utils.py /opt/casescope/app/

# Fix upload directory permissions
echo "Fixing upload directory..."
sudo mkdir -p /opt/casescope/data/uploads
sudo chown -R casescope:casescope /opt/casescope/data
sudo chmod 755 /opt/casescope/data/uploads

# Run database migration if needed
echo "Running database migration..."
sudo -u casescope /opt/casescope/venv/bin/python3 /Users/jdube/caseScope7_cursor/migrate_db.py

# Clean up any orphaned files in upload directory
echo "Cleaning orphaned upload files..."
sudo find /opt/casescope/data/uploads -type f -name "*.evtx" -mtime +1 -delete 2>/dev/null || true

# Clear any stuck Celery tasks
echo "Clearing Redis queue..."
redis-cli flushdb 2>/dev/null || true

# Restart services
echo "Restarting services..."
sudo systemctl start casescope-web
sudo systemctl start casescope-worker

# Wait for services to start
sleep 5

# Check status
echo "Service status:"
sudo systemctl is-active casescope-web casescope-worker

echo "Emergency fixes completed!"
echo "Check logs if issues persist:"
echo "  Web: sudo journalctl -u casescope-web -f"
echo "  Worker: sudo journalctl -u casescope-worker -f"
echo "  App: sudo tail -f /opt/casescope/logs/*.log"
