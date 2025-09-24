#!/bin/bash

# Quick update script for testing server
# Run this to pull latest changes and redeploy

echo "=== caseScope Test Server Update ==="
echo "Date: $(date)"

# Stop services
echo "Stopping caseScope services..."
sudo systemctl stop casescope-web casescope-worker 2>/dev/null || true

# Go to project directory (adjust path as needed)
cd /path/to/your/casescope/repo

# Pull latest changes
echo "Pulling latest changes from Git..."
git pull origin main

# Make scripts executable
chmod +x *.sh

# Run deployment only (skip installation if system is already set up)
echo "Running deployment..."
sudo ./deploy.sh

# Run database migration
echo "Running database migration..."
sudo /opt/casescope/venv/bin/python3 ./migrate_db.py

# Start services
echo "Starting caseScope services..."
sudo systemctl start casescope-web casescope-worker

# Check status
echo "Checking service status..."
sudo systemctl status casescope-web --no-pager -l

echo "Update complete!"
echo "Access: http://$(hostname -I | awk '{print $1}')"
