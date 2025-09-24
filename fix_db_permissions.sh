#!/bin/bash

# caseScope Database Permissions Fix
# Quick fix for "readonly database" error
# Run this as root if you get database write errors

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}caseScope Database Permissions Fix${NC}"
echo "Fixing database write permissions..."

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Usage: sudo ./fix_db_permissions.sh"
    exit 1
fi

# Check if casescope user exists
if ! id "casescope" >/dev/null 2>&1; then
    echo -e "${RED}Error: casescope user does not exist${NC}"
    exit 1
fi

# Fix data directory permissions
echo "Setting data directory permissions..."
chown -R casescope:casescope /opt/casescope/data
chmod 755 /opt/casescope/data

# Fix database file permissions if it exists
if [ -f /opt/casescope/data/casescope.db ]; then
    echo "Setting database file permissions..."
    chown casescope:casescope /opt/casescope/data/casescope.db
    chmod 664 /opt/casescope/data/casescope.db
    echo -e "${GREEN}✓ Database file permissions fixed${NC}"
else
    echo -e "${YELLOW}Warning: Database file not found at /opt/casescope/data/casescope.db${NC}"
fi

# Fix uploads directory permissions
if [ -d /opt/casescope/data/uploads ]; then
    echo "Setting uploads directory permissions..."
    chown -R casescope:casescope /opt/casescope/data/uploads
    chmod 755 /opt/casescope/data/uploads
    echo -e "${GREEN}✓ Uploads directory permissions fixed${NC}"
fi

# Fix logs directory permissions
if [ -d /opt/casescope/logs ]; then
    echo "Setting logs directory permissions..."
    chown -R casescope:casescope /opt/casescope/logs
    chmod 755 /opt/casescope/logs
    echo -e "${GREEN}✓ Logs directory permissions fixed${NC}"
fi

# Restart services to apply changes
echo "Restarting caseScope services..."
systemctl restart casescope-web
systemctl restart casescope-worker

echo -e "${GREEN}✓ Database permissions fix completed!${NC}"
echo ""
echo "You can now try creating a case again."
echo "If you still get errors, check the logs:"
echo "  tail -f /opt/casescope/logs/application.log"
echo "  journalctl -u casescope-web -f"
