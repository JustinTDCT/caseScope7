#!/bin/bash

# Emergency Import Fix Script
# Fixes missing imports and Flask app initialization issues
# Usage: sudo ./emergency_import_fix.sh

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

echo -e "${BLUE}Emergency Import Fix Script${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    echo "Usage: sudo ./emergency_import_fix.sh"
    exit 1
fi

# 1. STOP ALL SERVICES
log "Stopping all services..."
systemctl stop casescope-web casescope-worker

# 2. BACKUP AND FIX IMPORTS
log "Fixing missing imports in app.py..."
cd /opt/casescope/app

# Create backup
cp app.py app.py.import.backup.$(date +%s)

# Fix the import issues
python3 << 'PYTHON_IMPORT_FIX'
import re

def fix_imports():
    with open('app.py', 'r') as f:
        content = f.read()
    
    # Check if UserMixin is imported
    if 'from flask_login import' in content and 'UserMixin' not in content.split('from flask_login import')[1].split('\n')[0]:
        # Fix the flask_login import line
        old_import = re.search(r'from flask_login import[^\n]+', content)
        if old_import:
            old_line = old_import.group(0)
            # Check what's already imported
            if 'UserMixin' not in old_line:
                new_line = old_line.replace('from flask_login import ', 'from flask_login import UserMixin, ')
                content = content.replace(old_line, new_line)
                print(f"Fixed flask_login import: {new_line}")
    
    # Ensure all necessary imports are present
    required_imports = {
        'flask_login': ['LoginManager', 'UserMixin', 'login_user', 'login_required', 'logout_user', 'current_user'],
        'flask_sqlalchemy': ['SQLAlchemy'],
        'flask_wtf': ['FlaskForm'],
        'flask_wtf.file': ['FileField', 'FileAllowed', 'FileRequired'],
        'wtforms': ['StringField', 'PasswordField', 'SelectField', 'TextAreaField', 'BooleanField'],
        'wtforms.validators': ['DataRequired', 'Length', 'Email']
    }
    
    # Check each import group
    for module, items in required_imports.items():
        import_pattern = f'from {module} import'
        if import_pattern in content:
            import_match = re.search(f'from {module} import ([^\n]+)', content)
            if import_match:
                current_imports = [item.strip() for item in import_match.group(1).split(',')]
                missing_imports = [item for item in items if item not in ' '.join(current_imports)]
                
                if missing_imports:
                    old_import_line = import_match.group(0)
                    new_imports = current_imports + missing_imports
                    new_import_line = f'from {module} import {", ".join(new_imports)}'
                    content = content.replace(old_import_line, new_import_line)
                    print(f"Enhanced {module} imports: {new_import_line}")
    
    # Ensure Flask app is created before being used
    # Find where Flask app is created
    app_creation = 'app = Flask(__name__)'
    if app_creation in content:
        # Make sure it comes before any app.config usage
        lines = content.split('\n')
        app_line_idx = None
        config_line_idx = None
        
        for i, line in enumerate(lines):
            if 'app = Flask(__name__)' in line:
                app_line_idx = i
            elif 'app.config[' in line and app_line_idx is None:
                config_line_idx = i
                break
        
        if config_line_idx is not None and app_line_idx is not None and config_line_idx < app_line_idx:
            # Move app creation earlier
            app_line = lines.pop(app_line_idx)
            lines.insert(config_line_idx, app_line)
            content = '\n'.join(lines)
            print("Moved Flask app creation before config usage")
    
    # Fix any remaining app.config references that happen too early
    # Replace with default values
    problematic_configs = {
        "app.config.get('UPLOAD_FOLDER', '/opt/casescope/data/uploads')": "'/opt/casescope/data/uploads'",
        "app.config['UPLOAD_FOLDER']": "'/opt/casescope/data/uploads'",
        "app.config.get('SECRET_KEY', 'default-key')": "'casescope-v7-production-key'",
    }
    
    for old_config, new_value in problematic_configs.items():
        if old_config in content:
            content = content.replace(old_config, new_value)
            print(f"Fixed early config reference: {old_config} -> {new_value}")
    
    with open('app.py', 'w') as f:
        f.write(content)
    
    print("✓ Import fixes applied successfully")
    return True

fix_imports()
PYTHON_IMPORT_FIX

# 3. VERIFY THE FIX BY TESTING IMPORTS
log "Testing import fixes..."
cd /opt/casescope/app

python3 << 'PYTHON_TEST_IMPORTS'
import sys
sys.path.insert(0, '/opt/casescope/app')

try:
    # Test basic imports first
    from flask import Flask
    print("✓ Flask import OK")
    
    from flask_login import UserMixin, LoginManager
    print("✓ Flask-Login imports OK")
    
    from flask_sqlalchemy import SQLAlchemy
    print("✓ Flask-SQLAlchemy import OK")
    
    # Test the app module import
    import app
    print("✓ App module import OK")
    
    # Test if the app object exists
    if hasattr(app, 'app'):
        print("✓ Flask app object exists")
    else:
        print("✗ Flask app object missing")
    
    print("Import test completed successfully")
    
except Exception as e:
    print(f"✗ Import test failed: {e}")
    import traceback
    traceback.print_exc()
PYTHON_TEST_IMPORTS

# 4. SET PERMISSIONS
log "Setting proper permissions..."
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/logs

# 5. START SERVICES ONE BY ONE
log "Starting web service..."
systemctl start casescope-web
sleep 10

# Check web service
if systemctl is-active --quiet casescope-web; then
    log "✓ Web service started successfully"
else
    log_error "Web service failed to start"
    log "Checking web service logs..."
    journalctl -u casescope-web --no-pager -l | tail -20
    exit 1
fi

log "Starting worker service..."
systemctl start casescope-worker
sleep 5

# Check worker service
if systemctl is-active --quiet casescope-worker; then
    log "✓ Worker service started successfully"
else
    log_error "Worker service failed to start"
    log "Checking worker service logs..."
    journalctl -u casescope-worker --no-pager -l | tail -20
fi

# 6. FINAL STATUS
log "Final status check..."
echo -e "${BLUE}=== SERVICE STATUS ===${NC}"
systemctl status casescope-web --no-pager
echo ""
systemctl status casescope-worker --no-pager

echo -e "${BLUE}=== WEB SERVICE TEST ===${NC}"
curl -s -o /dev/null -w "%{http_code}" http://localhost:5000 || echo "Web service not responding"

log "Emergency import fix completed!"
echo ""
echo -e "${GREEN}If services are running:${NC}"
echo "  - Try accessing the web interface"
echo "  - Upload a test file"
echo "  - Monitor logs: tail -f /opt/casescope/logs/application.log"
echo ""
echo -e "${YELLOW}If issues persist:${NC}"
echo "  - Check journalctl -u casescope-web -f"
echo "  - Check journalctl -u casescope-worker -f"
