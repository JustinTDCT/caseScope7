#!/bin/bash

# Quick fix for deployment directory issue
# Run this if deploy.sh fails with "Not a directory" error

echo "=== caseScope Deployment Fix ==="
echo "Creating missing directories..."

# Create all required directories
sudo mkdir -p /opt/casescope/app/templates/admin
sudo mkdir -p /opt/casescope/app/static/css
sudo mkdir -p /opt/casescope/app/static/js
sudo mkdir -p /opt/casescope/data/uploads
sudo mkdir -p /opt/casescope/config

# Set proper permissions
sudo chown -R casescope:casescope /opt/casescope/app
sudo chown -R casescope:casescope /opt/casescope/data
sudo chown -R casescope:casescope /opt/casescope/config

echo "Directories created. Now run: sudo ./deploy.sh"
