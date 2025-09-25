#!/bin/bash

# Quick Fix for User Role Mismatch Issue
# Run this as root to fix the immediate role issue

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

echo -e "${BLUE}=== caseScope User Role Fix v7.0.96 ===${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    log_error "This script must be run as root"
    echo "Usage: sudo ./fix_user_roles.sh"
    exit 1
fi

log "Fixing user role mismatch issue..."

# Fix user roles in the database
log "Updating user roles in database..."
cd /opt/casescope/app
/opt/casescope/venv/bin/python3 << 'PYTHON_ROLE_FIX'
import sys
sys.path.insert(0, '/opt/casescope/app')
try:
    from app import db, app as flask_app, User
    
    with flask_app.app_context():
        # Find users with incorrect role names
        users_to_fix = User.query.filter_by(role='administrator').all()
        users_fixed = 0
        
        for user in users_to_fix:
            old_role = user.role
            user.role = 'admin'
            users_fixed += 1
            print(f'✓ Fixed user {user.username}: {old_role} -> admin')
        
        if users_fixed > 0:
            db.session.commit()
            print(f'✓ Fixed {users_fixed} users with incorrect role names')
        else:
            print('✓ All user roles are already correct')
        
        # Verify all users now have correct roles
        all_users = User.query.all()
        print(f'\nCurrent user roles:')
        for user in all_users:
            print(f'  - {user.username}: {user.role}')
        
        # Test admin permissions
        admin_user = User.query.filter_by(username='Admin').first()
        if admin_user:
            print(f'\nAdmin user verification:')
            print(f'  - Username: {admin_user.username}')
            print(f'  - Role: {admin_user.role}')
            print(f'  - Can admin: {admin_user.can_admin()}')
            print(f'  - Can write: {admin_user.can_write()}')
        
except Exception as e:
    print(f'✗ Role fix failed: {e}')
    import traceback
    traceback.print_exc()
    raise
PYTHON_ROLE_FIX

if [ $? -eq 0 ]; then
    log "✓ User roles fixed successfully"
else
    log_error "Failed to fix user roles"
    exit 1
fi

# Restart web service to ensure changes take effect
log "Restarting web service..."
systemctl restart casescope-web
sleep 5

if systemctl is-active --quiet casescope-web; then
    log "✓ Web service restarted successfully"
    
    # Test the fix by attempting to access the create_case route
    sleep 3
    HTTP_CODE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:5000/create_case || echo "000")
    if [ "$HTTP_CODE" = "302" ]; then
        log "⚠ Still getting redirect - may need login first (this is normal)"
    elif [ "$HTTP_CODE" = "200" ]; then
        log "✓ Create case route accessible"
    else
        log "⚠ Unexpected response code: $HTTP_CODE"
    fi
else
    log_error "Web service failed to restart"
    systemctl status casescope-web --no-pager
fi

echo ""
echo -e "${GREEN}=== Role Fix Complete ===${NC}"
log "User role mismatch has been fixed!"
echo ""
echo -e "${YELLOW}Next steps:${NC}"
echo "  1. Access web interface: http://server-ip"
echo "  2. Login with: Admin / ChangeMe!"
echo "  3. Try creating a case - should now work!"
echo "  4. Monitor logs: tail -f /opt/casescope/logs/error.log"
echo ""
echo -e "${BLUE}The create_case route should now work properly!${NC}"
