#!/bin/bash

# Complete Fix for Database and bcrypt Issues
# Run this as root to fix all current deployment issues

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

echo -e "${BLUE}=== caseScope Complete Database & bcrypt Fix ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    echo "Usage: sudo ./fix_database_and_bcrypt.sh"
    exit 1
fi

# 1. Stop services
log "Stopping services..."
systemctl stop casescope-web casescope-worker 2>/dev/null || true

# 2. Update requirements.txt with missing packages
log "Updating requirements.txt with all needed packages..."
if [ -f /opt/casescope/app/requirements.txt ]; then
    cat > /opt/casescope/app/requirements.txt << 'EOF'
# caseScope v7.0.93 Python Dependencies
# Core Flask Framework
Flask==3.0.0
Werkzeug==3.0.1

# Database and ORM
Flask-SQLAlchemy==3.1.1
SQLAlchemy==2.0.23

# Authentication and Security
Flask-Login==0.6.3
Flask-WTF==1.2.1
WTForms==3.1.1
bcrypt==4.1.2

# OpenSearch Client
opensearch-py==2.4.2

# Redis Client
redis==5.0.1

# Celery for Background Tasks
celery==5.3.4

# WSGI Server
gunicorn==21.2.0

# EVTX Parsing
evtx

# XML Processing
xmltodict==0.13.0

# System Information
psutil==5.9.6

# YAML Processing (for Sigma rules)
PyYAML==6.0.1

# HTTP Requests
requests==2.31.0

# Date/Time Utilities
python-dateutil==2.8.2

# JSON Processing
simplejson==3.19.2

# File Handling
pathlib2==2.3.7

# Logging Utilities
colorlog==6.8.0

# Additional Required Packages
jinja2==3.1.2
markupsafe==2.1.3
EOF
    log "✓ Updated requirements.txt"
fi

# 3. Install all packages in virtual environment
log "Installing all Python packages..."
cd /opt/casescope
source venv/bin/activate
pip install --upgrade pip setuptools wheel
pip install -r app/requirements.txt

# 4. Test critical imports
log "Testing critical imports..."
/opt/casescope/venv/bin/python3 -c "
import sys
sys.path.insert(0, '/opt/casescope/app')
try:
    import bcrypt
    print('✓ bcrypt imported successfully')
    import flask
    print('✓ flask imported successfully')
    import flask_sqlalchemy
    print('✓ flask_sqlalchemy imported successfully')
    import opensearchpy
    print('✓ opensearch imported successfully')
    import celery
    print('✓ celery imported successfully')
    print('All critical imports successful')
except Exception as e:
    print(f'✗ Import failed: {e}')
    raise
"

# 5. Initialize database with proper error handling
log "Initializing database..."
cd /opt/casescope/app
/opt/casescope/venv/bin/python3 << 'PYTHON_DB_INIT'
import sys
sys.path.insert(0, '/opt/casescope/app')
try:
    from app import db, app as flask_app, User
    with flask_app.app_context():
        # Create all database tables
        db.create_all()
        print('✓ Database tables created')
        
        # Create default admin user if it doesn't exist
        admin_user = User.query.filter_by(username='Admin').first()
        if not admin_user:
            from werkzeug.security import generate_password_hash
            admin_user = User(
                username='Admin',
                email='admin@casescope.local',
                password_hash=generate_password_hash('ChangeMe!'),
                role='administrator'
            )
            db.session.add(admin_user)
            db.session.commit()
            print('✓ Created default admin user: Admin / ChangeMe!')
        else:
            print('✓ Admin user already exists')
        
        print('✓ Database initialized successfully')
        
except Exception as e:
    print(f'✗ Database initialization failed: {e}')
    import traceback
    traceback.print_exc()
    raise
PYTHON_DB_INIT

# 6. Set proper permissions
log "Setting proper permissions..."
chown -R casescope:casescope /opt/casescope/venv
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/logs

# Database specific permissions
if [ -f /opt/casescope/data/casescope.db ]; then
    chown casescope:casescope /opt/casescope/data/casescope.db
    chmod 664 /opt/casescope/data/casescope.db
    log "✓ Database permissions set"
fi

# 7. Start services with monitoring
log "Starting services..."
systemctl start casescope-web
sleep 10

if systemctl is-active --quiet casescope-web; then
    log "✓ Web service started successfully"
    
    # Test web service response
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 || echo "000")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        log "✓ Web service responding (HTTP $HTTP_CODE)"
    else
        log "⚠ Web service not responding properly (HTTP $HTTP_CODE)"
    fi
else
    log_error "Web service failed to start"
    systemctl status casescope-web --no-pager
    journalctl -u casescope-web --no-pager -l | tail -20
fi

systemctl start casescope-worker
sleep 5

if systemctl is-active --quiet casescope-worker; then
    log "✓ Worker service started successfully"
else
    log_error "Worker service failed to start"
    systemctl status casescope-worker --no-pager
    journalctl -u casescope-worker --no-pager -l | tail -10
fi

# 8. Final verification
log "Final verification..."
echo ""
echo -e "${BLUE}=== Service Status ===${NC}"
systemctl status casescope-web casescope-worker --no-pager

echo ""
echo -e "${BLUE}=== Database Status ===${NC}"
if [ -f /opt/casescope/data/casescope.db ]; then
    echo "✓ Database file exists: $(du -h /opt/casescope/data/casescope.db | cut -f1)"
    echo "✓ Database permissions: $(ls -la /opt/casescope/data/casescope.db)"
else
    echo "✗ Database file missing"
fi

echo ""
echo -e "${GREEN}=== Fix Complete ===${NC}"
log "Database and bcrypt fix completed!"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Access web interface: http://server-ip"
echo "  2. Login with: Admin / ChangeMe!"
echo "  3. Create a case and test file upload"
echo "  4. Monitor logs: tail -f /opt/casescope/logs/error.log"
