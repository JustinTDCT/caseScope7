#!/bin/bash

# Virtual Environment and Service Configuration Fix
# Fixes virtual environment path issues and service configurations
# Usage: sudo ./venv_service_fix.sh

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

echo -e "${BLUE}Virtual Environment and Service Fix Script${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    echo "Usage: sudo ./venv_service_fix.sh"
    exit 1
fi

# 1. STOP SERVICES
log "Stopping services..."
systemctl stop casescope-web casescope-worker 2>/dev/null || true

# 2. VERIFY VIRTUAL ENVIRONMENT
log "Checking virtual environment..."
VENV_PATH="/opt/casescope/venv"

if [ ! -d "$VENV_PATH" ]; then
    log_error "Virtual environment not found at $VENV_PATH"
    log "Creating virtual environment..."
    python3 -m venv "$VENV_PATH"
    chown -R casescope:casescope "$VENV_PATH"
fi

# Test virtual environment
if [ -f "$VENV_PATH/bin/python3" ]; then
    log "✓ Virtual environment Python found"
else
    log_error "Virtual environment Python not found"
    exit 1
fi

# Test Flask installation in venv
log "Testing Flask installation in virtual environment..."
$VENV_PATH/bin/python3 -c "import flask; print('Flask version:', flask.__version__)" 2>/dev/null || {
    log "Flask not found in venv, installing requirements..."
    $VENV_PATH/bin/pip install --upgrade pip
    if [ -f /opt/casescope/requirements.txt ]; then
        $VENV_PATH/bin/pip install -r /opt/casescope/requirements.txt
    else
        log "Installing basic packages..."
        $VENV_PATH/bin/pip install flask flask-login flask-sqlalchemy flask-wtf celery redis opensearch-py pyevtx xmltodict psutil pyyaml requests
    fi
}

# 3. FIX WEB SERVICE CONFIGURATION
log "Fixing web service configuration..."
cat > /etc/systemd/system/casescope-web.service << 'EOF'
[Unit]
Description=caseScope Web Application
After=network.target opensearch.service redis.service

[Service]
Type=notify
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment="PATH=/opt/casescope/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=/opt/casescope/app"
ExecStart=/opt/casescope/venv/bin/gunicorn --workers 3 --bind 127.0.0.1:5000 --timeout 120 --access-logfile /opt/casescope/logs/access.log --error-logfile /opt/casescope/logs/error.log wsgi:app
ExecReload=/bin/kill -s HUP $MAINPID
KillMode=mixed
TimeoutStopSec=5
PrivateTmp=true
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
EOF

# 4. FIX WORKER SERVICE CONFIGURATION
log "Fixing worker service configuration..."
cat > /etc/systemd/system/casescope-worker.service << 'EOF'
[Unit]
Description=caseScope Celery Worker
After=network.target redis.service opensearch.service

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment="PATH=/opt/casescope/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
Environment="PYTHONPATH=/opt/casescope/app"
ExecStart=/opt/casescope/venv/bin/celery -A app.celery worker --loglevel=info --concurrency=2
Restart=always
RestartSec=10
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# 5. CREATE/VERIFY WSGI FILE
log "Creating/verifying WSGI file..."
cat > /opt/casescope/app/wsgi.py << 'EOF'
#!/usr/bin/env python3
"""
WSGI entry point for caseScope application
"""
import sys
import os

# Add the application directory to the Python path
app_dir = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, app_dir)

try:
    from app import app
    
    if __name__ == "__main__":
        app.run(debug=False, host='0.0.0.0', port=5000)
except Exception as e:
    print(f"Error importing app: {e}")
    import traceback
    traceback.print_exc()
    raise
EOF

# 6. SET PROPER PERMISSIONS
log "Setting proper permissions..."
chown -R casescope:casescope /opt/casescope/venv
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/logs

chmod +x /opt/casescope/app/wsgi.py

# 7. ENSURE LOG DIRECTORIES
log "Creating log directories..."
mkdir -p /opt/casescope/logs
touch /opt/casescope/logs/access.log
touch /opt/casescope/logs/error.log
touch /opt/casescope/logs/application.log
chown casescope:casescope /opt/casescope/logs/*.log
chmod 664 /opt/casescope/logs/*.log

# 8. TEST VIRTUAL ENVIRONMENT PYTHON IMPORT
log "Testing Python imports with virtual environment..."
cd /opt/casescope/app
sudo -u casescope $VENV_PATH/bin/python3 << 'PYTHON_VENV_TEST'
import sys
print(f"Python path: {sys.executable}")
print(f"Python version: {sys.version}")

try:
    import flask
    print(f"✓ Flask {flask.__version__} imported successfully")
    
    import flask_login
    print("✓ Flask-Login imported successfully")
    
    import flask_sqlalchemy
    print("✓ Flask-SQLAlchemy imported successfully")
    
    import celery
    print(f"✓ Celery {celery.__version__} imported successfully")
    
    import redis
    print("✓ Redis imported successfully")
    
    print("✓ All critical imports successful")
    
except Exception as e:
    print(f"✗ Import failed: {e}")
    import traceback
    traceback.print_exc()
PYTHON_VENV_TEST

# 9. TEST APP MODULE IMPORT
log "Testing app module import..."
cd /opt/casescope/app
sudo -u casescope $VENV_PATH/bin/python3 -c "
try:
    import app
    print('✓ App module imported successfully')
    if hasattr(app, 'app'):
        print('✓ Flask app object exists')
    else:
        print('✗ Flask app object missing')
except Exception as e:
    print(f'✗ App import failed: {e}')
    import traceback
    traceback.print_exc()
"

# 10. RELOAD SYSTEMD
log "Reloading systemd..."
systemctl daemon-reload

# 11. START SERVICES WITH BETTER ERROR HANDLING
log "Starting web service..."
if systemctl start casescope-web; then
    sleep 10
    if systemctl is-active --quiet casescope-web; then
        log "✓ Web service started successfully"
        
        # Test web service response
        log "Testing web service response..."
        sleep 5
        HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 || echo "000")
        if [ "$HTTP_CODE" = "200" ] || [ "$HTTP_CODE" = "302" ]; then
            log "✓ Web service responding (HTTP $HTTP_CODE)"
        else
            log_warning "Web service not responding properly (HTTP $HTTP_CODE)"
        fi
    else
        log_error "Web service failed to stay running"
        journalctl -u casescope-web --no-pager -l | tail -20
    fi
else
    log_error "Failed to start web service"
    journalctl -u casescope-web --no-pager -l | tail -20
fi

log "Starting worker service..."
if systemctl start casescope-worker; then
    sleep 5
    if systemctl is-active --quiet casescope-worker; then
        log "✓ Worker service started successfully"
    else
        log_error "Worker service failed to stay running"
        journalctl -u casescope-worker --no-pager -l | tail -10
    fi
else
    log_error "Failed to start worker service"
    journalctl -u casescope-worker --no-pager -l | tail -10
fi

# 12. FINAL STATUS
log "Final status check..."
echo -e "${BLUE}=== SERVICE STATUS ===${NC}"
systemctl status casescope-web --no-pager -l
echo ""
systemctl status casescope-worker --no-pager -l

echo -e "${BLUE}=== LOG FILES ===${NC}"
ls -la /opt/casescope/logs/

log "Virtual environment and service fix completed!"
echo ""
echo -e "${GREEN}If successful:${NC}"
echo "  - Services should be running"
echo "  - Web interface accessible at http://server-ip"
echo "  - Check logs: tail -f /opt/casescope/logs/error.log"
echo "  - Monitor worker: journalctl -u casescope-worker -f"
