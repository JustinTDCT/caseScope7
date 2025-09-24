#!/bin/bash

# caseScope v7.0.87 Deployment Verification Script
# Verifies complete installation start-to-finish
# Copyright 2025 Justin Dube

set -e

# Color codes
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

echo -e "${BLUE}=== caseScope v7.0.87 Deployment Verification ===${NC}"
echo "This script verifies a complete clean deployment"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    exit 1
fi

echo -e "${YELLOW}Step 1: Verifying system prerequisites${NC}"

# Check Ubuntu version
if ! lsb_release -d | grep -q "Ubuntu 24"; then
    echo -e "${RED}Warning: This system is not Ubuntu 24${NC}"
fi

# Check available disk space (need at least 5GB)
AVAILABLE=$(df / | tail -1 | awk '{print $4}')
if [ $AVAILABLE -lt 5242880 ]; then  # 5GB in KB
    echo -e "${RED}Warning: Less than 5GB disk space available${NC}"
fi

echo -e "${GREEN}✓ Prerequisites checked${NC}"

echo -e "${YELLOW}Step 2: Verifying required files${NC}"

# Check for required files
REQUIRED_FILES=(
    "install.sh"
    "deploy.sh"
    "app.py"
    "requirements.txt"
    "version.json"
    "nightly_update.sh"
    "bugfixes.sh"
)

MISSING_FILES=()
for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$file" ]; then
        MISSING_FILES+=("$file")
    fi
done

if [ ${#MISSING_FILES[@]} -gt 0 ]; then
    echo -e "${RED}Error: Missing required files:${NC}"
    for file in "${MISSING_FILES[@]}"; do
        echo "  - $file"
    done
    exit 1
fi

echo -e "${GREEN}✓ All required files present${NC}"

echo -e "${YELLOW}Step 3: Verifying templates and static files${NC}"

if [ ! -d "templates" ] || [ ! -d "static" ]; then
    echo -e "${RED}Error: Missing templates or static directories${NC}"
    exit 1
fi

# Check for critical templates
CRITICAL_TEMPLATES=(
    "templates/base.html"
    "templates/login.html"
    "templates/system_dashboard.html"
    "templates/case_dashboard.html"
    "templates/list_files.html"
    "templates/search.html"
)

for template in "${CRITICAL_TEMPLATES[@]}"; do
    if [ ! -f "$template" ]; then
        echo -e "${RED}Error: Missing critical template: $template${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✓ Templates and static files verified${NC}"

echo -e "${YELLOW}Step 4: Checking requirements.txt${NC}"

# Verify requirements.txt has essential packages
ESSENTIAL_PACKAGES=(
    "Flask"
    "opensearch-py"
    "celery"
    "redis"
    "pyevtx"
)

for package in "${ESSENTIAL_PACKAGES[@]}"; do
    if ! grep -q "$package" requirements.txt; then
        echo -e "${RED}Error: Missing essential package in requirements.txt: $package${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✓ Requirements.txt verified${NC}"

echo -e "${YELLOW}Step 5: Checking script permissions and syntax${NC}"

# Check bash syntax of scripts
for script in install.sh deploy.sh nightly_update.sh bugfixes.sh; do
    if ! bash -n "$script"; then
        echo -e "${RED}Error: Syntax error in $script${NC}"
        exit 1
    fi
done

echo -e "${GREEN}✓ Script syntax verified${NC}"

echo -e "${YELLOW}Step 6: Verifying version consistency${NC}"

# Extract versions from different files
INSTALL_VERSION=$(grep "caseScope v" install.sh | head -1 | sed 's/.*v\([0-9.]*\).*/\1/')
DEPLOY_VERSION=$(grep "caseScope v" deploy.sh | head -1 | sed 's/.*v\([0-9.]*\).*/\1/')
JSON_VERSION=$(grep '"version"' version.json | sed 's/.*"\([0-9.]*\)".*/\1/')

if [ "$INSTALL_VERSION" != "$DEPLOY_VERSION" ] || [ "$INSTALL_VERSION" != "$JSON_VERSION" ]; then
    echo -e "${RED}Error: Version mismatch${NC}"
    echo "  Install script: $INSTALL_VERSION"
    echo "  Deploy script: $DEPLOY_VERSION"
    echo "  Version JSON: $JSON_VERSION"
    exit 1
fi

echo -e "${GREEN}✓ Version consistency verified ($INSTALL_VERSION)${NC}"

echo ""
echo -e "${GREEN}=== Deployment Ready! ===${NC}"
echo -e "${GREEN}All verification checks passed${NC}"
echo ""
echo -e "${BLUE}To deploy on a clean Ubuntu 24 server:${NC}"
echo "1. Copy all files to the server"
echo "2. Run: sudo chmod +x install.sh deploy.sh"
echo "3. Run: sudo ./install.sh"
echo "4. Run: sudo ./deploy.sh"
echo "5. Access web interface at http://server-ip"
echo ""
echo -e "${YELLOW}The deployment includes:${NC}"
echo "- Enhanced error handling and JSON parsing protection"
echo "- Complete OpenSearch integration with cleanup tools"
echo "- Automatic nightly updates"
echo "- Improved UI with better file list alignment"
echo "- Robust search functionality with emergency bypass"
echo "- All latest bug fixes and improvements"
echo ""
echo -e "${GREEN}✓ Deployment verification complete!${NC}"
