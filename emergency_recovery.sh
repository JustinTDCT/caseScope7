#!/bin/bash

# Emergency Recovery Script for Missing App Directory
# Run this to fix the current broken installation

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

echo -e "${BLUE}=== caseScope Emergency Recovery v7.0.101 ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    echo "Usage: sudo ./emergency_recovery.sh"
    exit 1
fi

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

log "Emergency recovery from: $SCRIPT_DIR"

# Stop services
log "Stopping services..."
systemctl stop casescope-web casescope-worker 2>/dev/null || true

# Recreate missing app directory
log "Recreating missing application directory..."
mkdir -p /opt/casescope/app/templates/admin
mkdir -p /opt/casescope/app/static/css
mkdir -p /opt/casescope/app/static/js

# Copy application files if they exist in current directory
if [ -f "$SCRIPT_DIR/app.py" ]; then
    log "Copying application files from source..."
    cp "$SCRIPT_DIR/app.py" /opt/casescope/app/
    cp "$SCRIPT_DIR/version.json" /opt/casescope/app/
    cp -r "$SCRIPT_DIR/templates"/* /opt/casescope/app/templates/
    cp -r "$SCRIPT_DIR/static"/* /opt/casescope/app/static/
    log "✓ Application files copied"
else
    log_error "Application files not found in $SCRIPT_DIR"
    log_error "Please run this script from the source directory containing app.py"
    exit 1
fi

# Copy requirements.txt and install dependencies
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    log "Copying requirements.txt..."
    cp "$SCRIPT_DIR/requirements.txt" /opt/casescope/app/
    
    log "Installing Python dependencies..."
    cd /opt/casescope
    source venv/bin/activate
    pip install -r app/requirements.txt
    log "✓ Dependencies installed"
else
    log_warning "requirements.txt not found - dependencies may be missing"
fi

# Fix permissions
log "Setting correct permissions..."
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/logs

# Initialize database if needed
if [ ! -f "/opt/casescope/data/casescope.db" ] || [ ! -s "/opt/casescope/data/casescope.db" ]; then
    log "Initializing database..."
    cd /opt/casescope/app
    /opt/casescope/venv/bin/python3 -c "
import sys
sys.path.insert(0, '/opt/casescope/app')
try:
    from app import db, app as flask_app, User
    with flask_app.app_context():
        db.create_all()
        
        # Create default admin user if needed
        admin_user = User.query.filter_by(username='Admin').first()
        if not admin_user:
            from werkzeug.security import generate_password_hash
            admin_user = User(
                username='Admin',
                email='admin@casescope.local',
                password_hash=generate_password_hash('ChangeMe!'),
                role='admin'
            )
            db.session.add(admin_user)
            db.session.commit()
            print('✓ Created default admin user')
        
        print('✓ Database initialized successfully')
except Exception as e:
    print(f'✗ Database initialization failed: {e}')
    raise
"
    log "✓ Database initialized"
fi

# Set database permissions
chown casescope:casescope /opt/casescope/data/casescope.db
chmod 664 /opt/casescope/data/casescope.db

# Start services
log "Starting services..."
systemctl start casescope-web
sleep 5

if systemctl is-active --quiet casescope-web; then
    log "✓ Web service started successfully"
    
    # Test web service
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 2>/dev/null || echo "000")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        log "✓ Web application responding (HTTP $HTTP_CODE)"
    else
        log "⚠ Web application not responding properly (HTTP $HTTP_CODE)"
    fi
else
    log_error "Web service failed to start"
    systemctl status casescope-web --no-pager
fi

systemctl start casescope-worker
sleep 3

if systemctl is-active --quiet casescope-worker; then
    log "✓ Worker service started successfully"
else
    log_error "Worker service failed to start"
    systemctl status casescope-worker --no-pager
fi

echo ""
echo -e "${GREEN}=== Recovery Complete ===${NC}"
log "Emergency recovery completed!"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Access web interface: http://server-ip"
echo "  2. Login with: Admin / ChangeMe!"
echo "  3. Run debug script: sudo /opt/casescope/debug.sh"
echo "  4. Monitor logs: tail -f /opt/casescope/logs/error.log"
echo ""
echo -e "${BLUE}If issues persist, run the full deploy script again.${NC}"
