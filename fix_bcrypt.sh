#!/bin/bash

# Quick Fix for Missing bcrypt Package
# Run this as root to fix the bcrypt import error

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

echo -e "${YELLOW}caseScope bcrypt Fix Script${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    echo "Usage: sudo ./fix_bcrypt.sh"
    exit 1
fi

# Stop services
log "Stopping services..."
systemctl stop casescope-web casescope-worker

# Install bcrypt in virtual environment
log "Installing missing bcrypt package..."
cd /opt/casescope
source venv/bin/activate
pip install bcrypt==4.1.2

# Also install any other potentially missing packages
pip install setuptools wheel

# Copy updated requirements.txt
if [ -f /opt/casescope/app/requirements.txt ]; then
    log "Installing all requirements to ensure nothing is missing..."
    pip install -r /opt/casescope/app/requirements.txt
fi

# Try to initialize database again
log "Attempting database initialization..."
cd /opt/casescope/app
/opt/casescope/venv/bin/python3 -c "
import sys
sys.path.insert(0, '/opt/casescope/app')
try:
    from app import db, app as flask_app
    with flask_app.app_context():
        db.create_all()
        print('✓ Database initialized successfully')
except Exception as e:
    print(f'✗ Database initialization failed: {e}')
    import traceback
    traceback.print_exc()
"

# Set proper permissions
log "Setting permissions..."
chown -R casescope:casescope /opt/casescope/venv
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/logs

# Fix database permissions specifically
if [ -f /opt/casescope/data/casescope.db ]; then
    chown casescope:casescope /opt/casescope/data/casescope.db
    chmod 664 /opt/casescope/data/casescope.db
    log "✓ Database permissions set"
fi

# Start services
log "Starting services..."
systemctl start casescope-web
sleep 5

if systemctl is-active --quiet casescope-web; then
    log "✓ Web service started successfully"
else
    log_error "Web service failed to start"
    systemctl status casescope-web --no-pager
    exit 1
fi

systemctl start casescope-worker
sleep 3

if systemctl is-active --quiet casescope-worker; then
    log "✓ Worker service started successfully"
else
    log_error "Worker service failed to start"
    systemctl status casescope-worker --no-pager
fi

log "bcrypt fix completed!"
echo ""
echo -e "${GREEN}Services should now be running properly.${NC}"
echo "Test the web interface and check logs if needed:"
echo "  - Web interface: http://server-ip"
echo "  - Error logs: tail -f /opt/casescope/logs/error.log"
echo "  - Application logs: tail -f /opt/casescope/logs/application.log"
