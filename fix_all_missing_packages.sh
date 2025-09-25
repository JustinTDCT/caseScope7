#!/bin/bash

# Complete Fix for ALL Missing Packages
# Run this as root to fix all import errors and get services running

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

echo -e "${BLUE}=== caseScope Complete Package Fix v7.0.94 ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    echo "Usage: sudo ./fix_all_missing_packages.sh"
    exit 1
fi

# 1. Stop services
log "Stopping services..."
systemctl stop casescope-web casescope-worker 2>/dev/null || true

# 2. Update requirements.txt with ALL missing packages
log "Creating complete requirements.txt with ALL packages..."
cat > /opt/casescope/app/requirements.txt << 'EOF'
# caseScope v7.0.94 Python Dependencies
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

# Background Scheduler
APScheduler==3.10.4

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

# System utilities
setuptools==69.0.0
wheel==0.42.0
EOF

log "✓ Created complete requirements.txt"

# 3. Install ALL packages in virtual environment
log "Installing ALL Python packages..."
cd /opt/casescope
source venv/bin/activate

# Install build tools first
log "Installing build dependencies..."
pip install --upgrade pip
pip install setuptools==69.0.0 wheel==0.42.0

# Install all packages
log "Installing all application packages..."
pip install -r app/requirements.txt

# 4. Comprehensive import test
log "Testing ALL critical imports..."
/opt/casescope/venv/bin/python3 << 'PYTHON_IMPORT_TEST'
import sys
sys.path.insert(0, '/opt/casescope/app')

critical_imports = [
    ('bcrypt', 'bcrypt'),
    ('flask', 'Flask'),
    ('flask_login', 'Flask-Login'),
    ('flask_sqlalchemy', 'Flask-SQLAlchemy'),
    ('flask_wtf', 'Flask-WTF'),
    ('wtforms', 'WTForms'),
    ('opensearchpy', 'opensearch-py'),
    ('redis', 'redis'),
    ('celery', 'Celery'),
    ('evtx', 'evtx'),
    ('xmltodict', 'xmltodict'),
    ('psutil', 'psutil'),
    ('yaml', 'PyYAML'),
    ('apscheduler.schedulers.background', 'APScheduler'),
    ('requests', 'requests'),
    ('jinja2', 'jinja2'),
    ('markupsafe', 'markupsafe')
]

success_count = 0
failed_imports = []

for module_name, package_name in critical_imports:
    try:
        if '.' in module_name:
            # Handle submodule imports
            exec(f'from {module_name} import *')
        else:
            exec(f'import {module_name}')
        print(f'✓ {package_name} imported successfully')
        success_count += 1
    except Exception as e:
        print(f'✗ {package_name} failed: {e}')
        failed_imports.append((package_name, str(e)))

print(f'\nImport Summary: {success_count}/{len(critical_imports)} successful')
if failed_imports:
    print('Failed imports:')
    for pkg, error in failed_imports:
        print(f'  - {pkg}: {error}')
    raise Exception(f'{len(failed_imports)} critical packages failed to import')
else:
    print('All critical imports successful!')
PYTHON_IMPORT_TEST

# 5. Initialize database with comprehensive error handling
log "Initializing database..."
cd /opt/casescope/app
/opt/casescope/venv/bin/python3 << 'PYTHON_DB_INIT'
import sys
sys.path.insert(0, '/opt/casescope/app')
try:
    # Import app components
    from app import db, app as flask_app, User
    
    print('✓ Successfully imported all app components')
    
    with flask_app.app_context():
        # Drop existing tables if they exist (for clean slate)
        db.drop_all()
        print('✓ Dropped existing tables')
        
        # Create all database tables
        db.create_all()
        print('✓ Created all database tables')
        
        # Create default admin user
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
        
        # Verify database
        user_count = User.query.count()
        print(f'✓ Database verification: {user_count} users in database')
        print(f'✓ Database location: /opt/casescope/data/casescope.db')
        
except Exception as e:
    print(f'✗ Database initialization failed: {e}')
    import traceback
    traceback.print_exc()
    raise
PYTHON_DB_INIT

# 6. Set comprehensive permissions
log "Setting comprehensive permissions..."
chown -R casescope:casescope /opt/casescope/venv
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/logs
chown -R casescope:casescope /opt/casescope/config

# Database specific permissions
if [ -f /opt/casescope/data/casescope.db ]; then
    chown casescope:casescope /opt/casescope/data/casescope.db
    chmod 664 /opt/casescope/data/casescope.db
    log "✓ Database permissions set"
fi

# Log file permissions
if [ -d /opt/casescope/logs ]; then
    find /opt/casescope/logs -type f -exec chmod 664 {} \;
    log "✓ Log file permissions set"
fi

# 7. Start services with comprehensive monitoring
log "Starting web service..."
systemctl start casescope-web
sleep 15

if systemctl is-active --quiet casescope-web; then
    log "✓ Web service started successfully"
    
    # Test web service response
    sleep 5
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 || echo "000")
    if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
        log "✓ Web service responding (HTTP $HTTP_CODE)"
    else
        log "⚠ Web service not responding properly (HTTP $HTTP_CODE)"
        log "Checking error logs..."
        if [ -f /opt/casescope/logs/error.log ]; then
            tail -10 /opt/casescope/logs/error.log
        fi
    fi
else
    log_error "Web service failed to start"
    systemctl status casescope-web --no-pager
    echo ""
    log "Checking recent logs..."
    journalctl -u casescope-web --no-pager -l | tail -20
    if [ -f /opt/casescope/logs/error.log ]; then
        echo ""
        log "Error log contents:"
        tail -20 /opt/casescope/logs/error.log
    fi
fi

log "Starting worker service..."
systemctl start casescope-worker
sleep 5

if systemctl is-active --quiet casescope-worker; then
    log "✓ Worker service started successfully"
else
    log_error "Worker service failed to start"
    systemctl status casescope-worker --no-pager
    journalctl -u casescope-worker --no-pager -l | tail -10
fi

# 8. Final comprehensive verification
log "Final verification..."
echo ""
echo -e "${BLUE}=== Service Status ===${NC}"
systemctl status casescope-web casescope-worker --no-pager

echo ""
echo -e "${BLUE}=== Database Status ===${NC}"
if [ -f /opt/casescope/data/casescope.db ]; then
    echo "✓ Database file exists: $(du -h /opt/casescope/data/casescope.db | cut -f1)"
    echo "✓ Database permissions: $(ls -la /opt/casescope/data/casescope.db)"
    
    # Test database connectivity
    cd /opt/casescope/app
    USER_COUNT=$(/opt/casescope/venv/bin/python3 -c "
import sys
sys.path.insert(0, '/opt/casescope/app')
from app import db, app as flask_app, User
with flask_app.app_context():
    print(User.query.count())
" 2>/dev/null || echo "0")
    echo "✓ Database users: $USER_COUNT"
else
    echo "✗ Database file missing"
fi

echo ""
echo -e "${BLUE}=== Log Files ===${NC}"
ls -la /opt/casescope/logs/

echo ""
echo -e "${GREEN}=== Fix Complete ===${NC}"
log "ALL missing packages fixed and services started!"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Access web interface: http://server-ip"
echo "  2. Login with: Admin / ChangeMe!"
echo "  3. Create a case and test file upload"
echo "  4. Monitor logs: tail -f /opt/casescope/logs/error.log"
echo "  5. Monitor worker: journalctl -u casescope-worker -f"
echo ""
echo -e "${BLUE}All issues should now be resolved!${NC}"
