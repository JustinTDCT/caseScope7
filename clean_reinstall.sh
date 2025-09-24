#!/bin/bash

# Complete clean reinstall for testing
# WARNING: This removes all data and starts fresh

echo "=== caseScope Clean Reinstall ==="
echo "This will remove all caseScope data and reinstall from scratch."
read -p "Are you sure? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 1
fi

# Stop and disable services
echo "Stopping services..."
sudo systemctl stop casescope-web casescope-worker opensearch nginx 2>/dev/null || true
sudo systemctl disable casescope-web casescope-worker opensearch 2>/dev/null || true

# Remove service files
sudo rm -f /etc/systemd/system/casescope-*.service
sudo rm -f /etc/systemd/system/opensearch.service

# Remove installation directories
echo "Removing old installation..."
sudo rm -rf /opt/casescope /opt/opensearch

# Remove nginx config
sudo rm -f /etc/nginx/sites-enabled/casescope
sudo rm -f /etc/nginx/sites-available/casescope

# Reload systemd
sudo systemctl daemon-reload

# Pull latest code
echo "Pulling latest code..."
git pull origin main
chmod +x *.sh

# Fresh install
echo "Starting fresh installation..."
sudo ./install.sh

# Deploy application
echo "Deploying application..."
sudo ./deploy.sh

echo "Clean reinstall complete!"
echo "Access: http://$(hostname -I | awk '{print $1}')"
echo "Login: Admin / ChangeMe!"
