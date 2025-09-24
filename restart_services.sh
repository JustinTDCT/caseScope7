#!/bin/bash

# Quick restart script for caseScope services
echo "=== Restarting caseScope Services ==="
echo "Date: $(date)"

# Stop services
echo "Stopping services..."
sudo systemctl stop casescope-web casescope-worker 2>/dev/null || true

# Wait a moment
sleep 2

# Start services
echo "Starting services..."
sudo systemctl start casescope-web casescope-worker

# Check status
echo "Service status:"
sudo systemctl status casescope-web --no-pager -l --lines=3
sudo systemctl status casescope-worker --no-pager -l --lines=3

echo "Restart complete!"
echo "Check version at: http://$(hostname -I | awk '{print $1}')/api/version"
