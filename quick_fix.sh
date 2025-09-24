#!/bin/bash

# Quick Fix Script for caseScope v7.0.34
# Run this on the production server after copying the updated app.py

echo "=== caseScope Quick Fix v7.0.34 ==="
echo "$(date): Applying quick fixes..."

# Stop services
echo "Stopping services..."
systemctl stop casescope-web casescope-worker 2>/dev/null || true

# Fix upload directory permissions
echo "Fixing upload directory..."
mkdir -p /opt/casescope/data/uploads
chown -R casescope:casescope /opt/casescope/data
chmod 755 /opt/casescope/data/uploads

# Run database migration if needed (using existing migrate_db.py if present)
if [ -f "/opt/casescope/app/migrate_db.py" ]; then
    echo "Running database migration..."
    sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_db.py
else
    echo "No migration file found, skipping..."
fi

# Clear Redis queue
echo "Clearing Redis queue..."
redis-cli flushdb 2>/dev/null || true

# Restart services
echo "Restarting services..."
systemctl start casescope-web
systemctl start casescope-worker

# Wait for services to start
sleep 5

# Check status
echo "Service status:"
systemctl is-active casescope-web casescope-worker

echo "Quick fixes completed!"
echo "Check logs if issues persist:"
echo "  Web: journalctl -u casescope-web -f"
echo "  Worker: journalctl -u casescope-worker -f"
