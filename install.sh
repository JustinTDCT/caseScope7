#!/bin/bash

# caseScope 7.x Installation Script
# Copyright (c) 2025 Justin Dube <casescope@thedubes.net>

# Note: We don't use 'set -e' because we handle errors explicitly with proper logging
# set -e would cause silent exits on non-critical errors

#══════════════════════════════════════════════════════════════
# CENTRALIZED VERSION CONFIGURATION
#══════════════════════════════════════════════════════════════

# Core application versions
CASESCOPE_VERSION="7.25.0"  # Auto-detected from version.json

# External tool versions
CHAINSAW_VERSION="v2.12.2"    # Sigma rule processor (Rust)
EVTX_DUMP_VERSION="v0.8.2"    # Fast EVTX parser (Rust)
OPENSEARCH_VERSION="2.11.1"   # Search/analytics engine

# Python dependencies (managed via requirements.txt)
# - Flask, SQLAlchemy, Celery, OpenSearch client, etc.

# System package versions (latest from Ubuntu 24 repos)
# - Python 3.12+, Redis 7.x, Nginx 1.24+

#══════════════════════════════════════════════════════════════
# COLOR CODES & LOGGING
#══════════════════════════════════════════════════════════════

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

log_error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1"
}

log_success() {
    echo -e "${GREEN}✓${NC} $1"
}

log_step() {
    echo -e "  ${BLUE}→${NC} $1"
}

log_debug() {
    if [ "${VERBOSE:-0}" = "1" ]; then
        echo -e "${BLUE}[DEBUG]${NC} $1"
    fi
}

# Check a condition and log result
check_and_log() {
    local description=$1
    local command=$2
    
    log_step "Checking $description..."
    if eval "$command" >/dev/null 2>&1; then
        log_success "$description: OK"
        return 0
    else
        log_error "$description: FAILED"
        return 1
    fi
}

# Print section header with progress indicator
print_section() {
    local step=$1
    local total=$2
    local title=$3
    echo
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}  ${GREEN}Step $step/$total:${NC} $title"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
}

#══════════════════════════════════════════════════════════════
# VERIFICATION FUNCTIONS
#══════════════════════════════════════════════════════════════

# Verify core application files are present
verify_application_files() {
    local all_ok=true
    
    log_step "Verifying core application files..."
    
    local required_files=(
        "/opt/casescope/app/main.py:Main application"
        "/opt/casescope/app/tasks.py:Background tasks"
        "/opt/casescope/app/celery_app.py:Task queue"
        "/opt/casescope/app/wsgi.py:Web server interface"
        "/opt/casescope/app/theme.py:UI stylesheet"
        "/opt/casescope/app/requirements.txt:Dependencies"
        "/opt/casescope/app/version.json:Version info"
        "/opt/casescope/app/iris_client.py:DFIR-IRIS client"
        "/opt/casescope/app/iris_sync.py:DFIR-IRIS sync"
        "/opt/casescope/app/migrate_database.py:Database migration"
    )
    
    for file_info in "${required_files[@]}"; do
        IFS=':' read -r file desc <<< "$file_info"
        if [ -f "$file" ]; then
            log_success "$desc: Present"
        else
            log_error "$desc: MISSING ($file)"
            all_ok=false
        fi
    done
    
    echo
    if [ "$all_ok" = true ]; then
        log_success "All core files verified"
        return 0
    else
        log_error "Some core files are missing"
        return 1
    fi
}

# Verify external tool versions
verify_external_tools() {
    local all_ok=true
    
    log_step "Verifying external tools..."
    
    # Check Chainsaw
    if [ -x "/opt/casescope/bin/chainsaw" ]; then
        CHAINSAW_VER=$(sudo -u casescope /opt/casescope/bin/chainsaw --version 2>/dev/null | head -n1 || echo "unknown")
        if [ "$CHAINSAW_VER" != "unknown" ]; then
            log_success "Chainsaw: $CHAINSAW_VER"
        else
            log_error "Chainsaw: Present but not functional"
            all_ok=false
        fi
    else
        log_error "Chainsaw: Not installed"
        all_ok=false
    fi
    
    # Check evtx_dump
    if [ -x "/opt/casescope/bin/evtx_dump" ]; then
        EVTX_VER=$(sudo -u casescope /opt/casescope/bin/evtx_dump --version 2>/dev/null | head -n1 || echo "unknown")
        if [ "$EVTX_VER" != "unknown" ]; then
            log_success "evtx_dump: $EVTX_VER"
        else
            log_error "evtx_dump: Present but not functional"
            all_ok=false
        fi
    else
        log_error "evtx_dump: Not installed"
        all_ok=false
    fi
    
    # Check Python environment
    if [ -x "/opt/casescope/venv/bin/python3" ]; then
        PYTHON_VER=$(sudo -u casescope /opt/casescope/venv/bin/python3 --version 2>&1 | awk '{print $2}')
        log_success "Python: $PYTHON_VER (venv)"
    else
        log_error "Python virtual environment: Not configured"
        all_ok=false
    fi
    
    # Check OpenSearch
    if systemctl is-active --quiet opensearch; then
        sleep 2  # Give OpenSearch a moment to be ready
        OS_VER=$(curl -s -XGET "localhost:9200" 2>/dev/null | python3 -c "import sys,json; print(json.load(sys.stdin).get('version',{}).get('number','unknown'))" 2>/dev/null || echo "unknown")
        if [ "$OS_VER" != "unknown" ]; then
            log_success "OpenSearch: $OS_VER (running)"
        else
            log_warning "OpenSearch: Running but version check failed"
        fi
    else
        log_error "OpenSearch: Not running"
        all_ok=false
    fi
    
    # Check Redis
    if systemctl is-active --quiet redis-server; then
        REDIS_VER=$(redis-cli --version 2>/dev/null | awk '{print $2}' || echo "unknown")
        log_success "Redis: $REDIS_VER (running)"
    else
        log_error "Redis: Not running"
        all_ok=false
    fi
    
    # Check Nginx
    if systemctl is-active --quiet nginx; then
        NGINX_VER=$(nginx -v 2>&1 | awk -F'/' '{print $2}' || echo "unknown")
        log_success "Nginx: $NGINX_VER (running)"
    else
        log_error "Nginx: Not running"
        all_ok=false
    fi
    
    echo
    if [ "$all_ok" = true ]; then
        log_success "All external tools verified"
        return 0
    else
        log_error "Some external tools failed verification"
        return 1
    fi
}

# Verify database integrity
verify_database() {
    log_step "Verifying database integrity..."
    
    if [ ! -f "/opt/casescope/data/casescope.db" ]; then
        log_error "Database file not found"
        return 1
    fi
    
    # Check database file permissions
    if [ -r "/opt/casescope/data/casescope.db" ]; then
        DB_SIZE=$(du -h /opt/casescope/data/casescope.db | cut -f1)
        log_success "Database file: Present ($DB_SIZE)"
    else
        log_error "Database file: Not readable"
        return 1
    fi
    
    # Check database schema
    log_step "Checking database schema..."
    sudo -u casescope /opt/casescope/venv/bin/python3 -c "
import sys
import os
sys.path.insert(0, '/opt/casescope/app')
os.chdir('/opt/casescope/app')

try:
    from main import app, db, User, Case, CaseFile, SigmaRule, IOC, EventTag, AuditLog, SystemSettings
    
    # Try to query each table within app context
    tables = {
        'users': User,
        'cases': Case,
        'case_files': CaseFile,
        'sigma_rules': SigmaRule,
        'iocs': IOC,
        'event_tags': EventTag,
        'audit_log': AuditLog,
        'system_settings': SystemSettings
    }
    
    with app.app_context():
        for table_name, model in tables.items():
            try:
                count = db.session.query(model).count()
                print(f'✓ Table {table_name}: {count} records')
            except Exception as e:
                print(f'✗ Table {table_name}: ERROR - {str(e)}')
                sys.exit(1)
        
        print('✓ All database tables verified')
    sys.exit(0)
except Exception as e:
    print(f'ERROR: Database verification failed: {e}')
    sys.exit(1)
" 2>&1 | while read line; do
        if [[ "$line" == ✓* ]]; then
            echo -e "  ${GREEN}$line${NC}"
        elif [[ "$line" == ✗* ]]; then
            echo -e "  ${RED}$line${NC}"
        elif [[ "$line" == ERROR* ]]; then
            echo -e "  ${RED}$line${NC}"
        else
            echo "  $line"
        fi
    done
    
    DB_CHECK_RESULT=${PIPESTATUS[0]}
    
    echo
    if [ $DB_CHECK_RESULT -eq 0 ]; then
        log_success "Database integrity verified"
        return 0
    else
        log_error "Database verification failed"
        return 1
    fi
}

# Comprehensive final verification
run_final_verification() {
    echo
    echo -e "${BLUE}╔══════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${BLUE}║${NC}          ${GREEN}Running Final System Verification${NC}"
    echo -e "${BLUE}╚══════════════════════════════════════════════════════════════╝${NC}"
    echo
    
    local verification_failed=false
    
    # Verify application files
    if ! verify_application_files; then
        verification_failed=true
    fi
    
    # Verify external tools
    if ! verify_external_tools; then
        verification_failed=true
    fi
    
    # Verify database
    if ! verify_database; then
        verification_failed=true
    fi
    
    # Final verdict
    echo
    if [ "$verification_failed" = false ]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║${NC}     ${GREEN}✓ ALL SYSTEMS CHECKED AND OK ✓${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo
        return 0
    else
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║${NC}     ${RED}✗ VERIFICATION FAILED - ISSUES DETECTED ✗${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo
        log_warning "Installation completed with warnings. System may not function correctly."
        log_warning "Review the errors above and fix them before using caseScope."
        return 1
    fi
}

#══════════════════════════════════════════════════════════════
# INSTALLATION FUNCTIONS
#══════════════════════════════════════════════════════════════

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

# Get version from version.json
get_version() {
    if [ -f "version.json" ]; then
        python3 -c "import json; print(json.load(open('version.json'))['version'])" 2>/dev/null || echo "unknown"
    else
        echo "unknown"
    fi
}

VERSION=$(get_version)

# Display header
clear
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    caseScope $VERSION Installer                  ║"
echo "║              Digital Forensics Case Management               ║"
echo "║                                                              ║"
echo "║              Copyright (c) 2025 Justin Dube                 ║"
echo "║                casescope@thedubes.net                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo

# Installation menu
show_menu() {
    echo -e "${BLUE}Installation Options:${NC}"
    echo
    echo "1) Clean Install"
    echo "   - Removes ALL existing data (database, indexes, files)"
    echo "   - Fresh installation as if system was new"
    echo "   - ${RED}WARNING: This will delete everything!${NC}"
    echo
    echo "2) Preserve Data (Upgrade)"
    echo "   - Keeps user data, cases, and uploaded files"
    echo "   - Updates system files and applies migrations"
    echo "   - Preserves OpenSearch indexes"
    echo
    echo "3) Clear Indexes"
    echo "   - Keeps database and uploaded files"
    echo "   - Clears OpenSearch indexes (requires re-indexing)"
    echo "   - Updates system files"
    echo
    echo "4) Exit"
    echo
}

# Get user choice
get_choice() {
    while true; do
        show_menu
        read -p "Select installation option (1-4): " choice
        case $choice in
            1)
                INSTALL_TYPE="clean"
                echo -e "${RED}"
                echo "WARNING: Clean install will DELETE ALL DATA!"
                echo "This includes:"
                echo "- All cases and files"
                echo "- User accounts (except default admin)"
                echo "- OpenSearch indexes"
                echo "- System logs"
                echo -e "${NC}"
                read -p "Type 'YES' to confirm clean install: " confirm
                if [ "$confirm" = "YES" ]; then
                    break
                else
                    echo "Clean install cancelled."
                    continue
                fi
                ;;
            2)
                INSTALL_TYPE="upgrade"
                echo -e "${GREEN}Upgrade installation selected - preserving user data${NC}"
                break
                ;;
            3)
                INSTALL_TYPE="reindex"
                echo -e "${YELLOW}Clear indexes selected - will require file re-indexing${NC}"
                break
                ;;
            4)
                echo "Installation cancelled."
                exit 0
                ;;
            *)
                echo -e "${RED}Invalid option. Please select 1-4.${NC}"
                ;;
        esac
    done
}

# System requirements check
check_requirements() {
    log_step "Verifying system compatibility..."
    echo
    
    # Check Ubuntu version
    log_step "Checking operating system..."
    if grep -q "Ubuntu 24" /etc/os-release 2>/dev/null; then
        OS_VERSION=$(grep VERSION_ID /etc/os-release | cut -d'"' -f2)
        log_success "Operating System: Ubuntu ${OS_VERSION} (Supported)"
    else
        OS_NAME=$(grep PRETTY_NAME /etc/os-release | cut -d'"' -f2 || echo "Unknown")
        log_warning "Operating System: ${OS_NAME}"
        log_warning "Ubuntu 24.04 LTS is recommended for optimal performance"
    fi
    
    # Check available memory
    log_step "Checking system memory..."
    TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    # Use awk instead of bc for better portability
    TOTAL_MEM_GB=$(awk "BEGIN {printf \"%.1f\", $TOTAL_MEM/1024}")
    if [ "$TOTAL_MEM" -ge 8192 ]; then
        log_success "System Memory: ${TOTAL_MEM_GB}GB (Sufficient)"
    else
        log_warning "System Memory: ${TOTAL_MEM_GB}GB (8GB+ recommended)"
    fi
    
    # Check available disk space
    log_step "Checking disk space..."
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    # Use awk instead of bc for better portability
    AVAILABLE_GB=$(awk "BEGIN {printf \"%.1f\", $AVAILABLE_SPACE/1024/1024}")
    if [ "$AVAILABLE_SPACE" -ge 10485760 ]; then  # 10GB in KB
        log_success "Available Disk Space: ${AVAILABLE_GB}GB (Sufficient)"
    else
        log_warning "Available Disk Space: ${AVAILABLE_GB}GB (10GB+ recommended)"
    fi
    
    # Check if running as root
    log_step "Checking privileges..."
    if [ "$EUID" -eq 0 ]; then
        log_success "Running with root privileges: OK"
    fi
    
    echo
    log_success "System requirements check completed"
    echo
}

# Install system dependencies
install_dependencies() {
    log_step "Updating package repositories..."
    if apt-get update -qq 2>&1 | grep -q "Failed"; then
        log_error "Failed to update package repositories"
        log_error "Check your internet connection and try again"
        return 1
    fi
    log_success "Package repositories updated"
    echo
    
    log_step "Installing system packages..."
    log_debug "Installing: Python 3, build tools, web server, cache server, utilities"
    
    if apt-get install -y -qq \
        python3 \
        python3-venv \
        python3-pip \
        python3-dev \
        build-essential \
        curl \
        wget \
        unzip \
        nginx \
        redis-server \
        git \
        htop \
        tree \
        jq \
        openjdk-11-jdk 2>&1 | tee /tmp/apt-install.log | grep -i "error\|failed" > /tmp/apt-errors.log; then
        
        if [ -s /tmp/apt-errors.log ]; then
            log_error "Some packages failed to install. Errors:"
            cat /tmp/apt-errors.log
            return 1
        fi
    fi
    
    # Verify key packages
    log_step "Verifying installations..."
    check_and_log "Python 3" "python3 --version"
    check_and_log "Pip" "pip3 --version"
    check_and_log "Nginx" "nginx -v"
    check_and_log "Redis" "redis-server --version"
    check_and_log "Git" "git --version"
    check_and_log "Java (OpenJDK)" "java -version"
    
    # Clean up temp files
    rm -f /tmp/apt-install.log /tmp/apt-errors.log
    
    echo
    log_success "All system dependencies installed successfully"
    echo
}

# Install Chainsaw for SIGMA rule processing
install_chainsaw() {
    log_step "Checking for existing Chainsaw installation..."
    
    if [ -f "/opt/casescope/bin/chainsaw" ]; then
        log_step "Testing existing Chainsaw binary..."
        if /opt/casescope/bin/chainsaw --version 2>/dev/null; then
            CHAINSAW_CURRENT=$(/opt/casescope/bin/chainsaw --version | head -n1)
            log_success "Chainsaw already installed: $CHAINSAW_CURRENT"
            return 0
        else
            log_warning "Chainsaw binary exists but is not functional, reinstalling..."
            rm -f /opt/casescope/bin/chainsaw
        fi
    fi
    
    # Create bin directory
    log_step "Creating installation directory..."
    mkdir -p /opt/casescope/bin
    log_success "Directory created: /opt/casescope/bin"
    
    # Download Chainsaw release for x86_64 Linux
    log_step "Downloading Chainsaw ${CHAINSAW_VERSION}..."
    cd /tmp
    log "Downloading Chainsaw ${CHAINSAW_VERSION} from GitHub..."
    
    # Remove old downloads if exist
    rm -f chainsaw_x86_64-unknown-linux-gnu.tar.gz
    rm -rf chainsaw
    
    wget --show-progress https://github.com/WithSecureLabs/chainsaw/releases/download/${CHAINSAW_VERSION}/chainsaw_x86_64-unknown-linux-gnu.tar.gz
    
    if [ $? -ne 0 ] || [ ! -f chainsaw_x86_64-unknown-linux-gnu.tar.gz ]; then
        log_error "Failed to download Chainsaw from GitHub"
        log_error "URL: https://github.com/WithSecureLabs/chainsaw/releases/download/${CHAINSAW_VERSION}/chainsaw_x86_64-unknown-linux-gnu.tar.gz"
        return 1
    fi
    
    log "Download successful ($(du -h chainsaw_x86_64-unknown-linux-gnu.tar.gz | cut -f1)), extracting..."
    
    # Extract the tarball (creates chainsaw/ directory)
    tar -xzf chainsaw_x86_64-unknown-linux-gnu.tar.gz
    
    if [ ! -d "chainsaw" ]; then
        log_error "Extraction failed - chainsaw directory not found"
        ls -la /tmp/chainsaw* || true
        return 1
    fi
    
    log "✓ Extracted Chainsaw"
    ls -lh chainsaw/
    
    # Find the binary inside the extracted directory
    if [ -f "chainsaw/chainsaw" ]; then
        CHAINSAW_BIN="chainsaw/chainsaw"
    else
        log_error "Chainsaw binary not found in extracted directory"
        ls -la chainsaw/
        return 1
    fi
    
    log "Found binary: $CHAINSAW_BIN"
    
    # Move binary to casescope bin
    cp "$CHAINSAW_BIN" /opt/casescope/bin/chainsaw
    chmod +x /opt/casescope/bin/chainsaw
    
    # Verify it's actually there and executable
    if [ ! -f /opt/casescope/bin/chainsaw ]; then
        log_error "Failed to copy Chainsaw binary to /opt/casescope/bin/chainsaw"
        return 1
    fi
    
    if [ ! -x /opt/casescope/bin/chainsaw ]; then
        log_error "Chainsaw binary is not executable"
        ls -la /opt/casescope/bin/chainsaw
        return 1
    fi
    
    # Check if the tarball includes mappings and sigma rules
    if [ -d "chainsaw/mappings" ]; then
        log "Found Chainsaw mappings in tarball, installing..."
        mkdir -p /opt/casescope/chainsaw
        cp -r chainsaw/mappings /opt/casescope/chainsaw/
        log "✓ Installed Chainsaw mappings from tarball"
        
        # Verify the sigma-event-logs-all.yml file exists
        if [ -f /opt/casescope/chainsaw/mappings/sigma/sigma-event-logs-all.yml ]; then
            log "✓ Found sigma-event-logs-all.yml at mappings/sigma/sigma-event-logs-all.yml"
        elif [ -f /opt/casescope/chainsaw/mappings/sigma-event-logs-all.yml ]; then
            log "✓ Found sigma-event-logs-all.yml at mappings/sigma-event-logs-all.yml"
        else
            log_warning "sigma-event-logs-all.yml not found in tarball mappings, downloading..."
            mkdir -p /opt/casescope/chainsaw/mappings
            wget -q https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/mappings/sigma/sigma-event-logs-all.yml -O /opt/casescope/chainsaw/mappings/sigma-event-logs-all.yml
        fi
    else
        # Download mappings separately if not in tarball
        log "Downloading Chainsaw SIGMA mappings from GitHub..."
        mkdir -p /opt/casescope/chainsaw/mappings
        wget -q https://raw.githubusercontent.com/WithSecureLabs/chainsaw/master/mappings/sigma/sigma-event-logs-all.yml -O /opt/casescope/chainsaw/mappings/sigma-event-logs-all.yml
        
        if [ -f /opt/casescope/chainsaw/mappings/sigma-event-logs-all.yml ]; then
            log "✓ Downloaded sigma-event-logs-all.yml mapping"
        else
            log_warning "Could not download mappings, Chainsaw will use default behavior"
        fi
    fi
    
    # Check if tarball includes SIGMA rules
    if [ -d "chainsaw/sigma" ]; then
        log "Found SIGMA rules in tarball, installing..."
        cp -r chainsaw/sigma /opt/casescope/chainsaw/rules
        log "✓ Installed SIGMA rules from tarball"
    else
        log "No SIGMA rules in tarball (we use our own from database)"
    fi
    
    # Clean up
    cd /tmp
    rm -rf chainsaw chainsaw_x86_64-unknown-linux-gnu.tar.gz
    
    # Verify installation works before changing ownership
    log "Verifying Chainsaw installation..."
    if ! /opt/casescope/bin/chainsaw --version 2>&1; then
        log_error "Chainsaw installation verification failed"
        log_error "Binary exists: $([ -f /opt/casescope/bin/chainsaw ] && echo 'YES' || echo 'NO')"
        log_error "Binary executable: $([ -x /opt/casescope/bin/chainsaw ] && echo 'YES' || echo 'NO')"
        ls -la /opt/casescope/bin/ 2>&1 || true
        return 1
    fi
    
    log "✓ Chainsaw installed successfully"
    log "✓ Chainsaw binary location: /opt/casescope/bin/chainsaw"
    log "✓ Chainsaw mappings location: /opt/casescope/chainsaw/mappings/"
    
    # Set ownership so casescope user can execute it
    chown -R casescope:casescope /opt/casescope/bin
    chown -R casescope:casescope /opt/casescope/chainsaw
    
    # Verify casescope user can execute it
    log "Verifying casescope user can execute Chainsaw..."
    if sudo -u casescope /opt/casescope/bin/chainsaw --version >/dev/null 2>&1; then
        log "✓ Chainsaw executable by casescope user"
    else
        log_error "casescope user cannot execute Chainsaw"
        ls -la /opt/casescope/bin/chainsaw
        return 1
    fi
}

install_evtx_dump() {
    log "Installing evtx_dump for fast EVTX parsing..."
    
    if [ -f "/opt/casescope/bin/evtx_dump" ]; then
        log "evtx_dump already installed"
        /opt/casescope/bin/evtx_dump --version 2>/dev/null || {
            log_warning "evtx_dump binary exists but is not executable, reinstalling..."
            rm -f /opt/casescope/bin/evtx_dump
        }
        
        # If evtx_dump is working, skip installation
        if [ -f "/opt/casescope/bin/evtx_dump" ]; then
            return 0
        fi
    fi
    
    # Create bin directory if not exists
    mkdir -p /opt/casescope/bin
    
    # Download evtx_dump release for x86_64 Linux
    cd /tmp
    log "Downloading evtx_dump ${EVTX_DUMP_VERSION} from GitHub..."
    
    # Remove old downloads if exist
    rm -f evtx_dump-*-linux-gnu
    
    wget --show-progress https://github.com/omerbenamram/evtx/releases/download/${EVTX_DUMP_VERSION}/evtx_dump-${EVTX_DUMP_VERSION}-x86_64-unknown-linux-gnu
    
    if [ $? -ne 0 ] || [ ! -f "evtx_dump-${EVTX_DUMP_VERSION}-x86_64-unknown-linux-gnu" ]; then
        log_error "Failed to download evtx_dump from GitHub"
        log_error "URL: https://github.com/omerbenamram/evtx/releases/download/${EVTX_DUMP_VERSION}/evtx_dump-${EVTX_DUMP_VERSION}-x86_64-unknown-linux-gnu"
        return 1
    fi
    
    log "Download successful ($(du -h evtx_dump-${EVTX_DUMP_VERSION}-x86_64-unknown-linux-gnu | cut -f1)), installing..."
    
    # Move binary to casescope bin
    mv "evtx_dump-${EVTX_DUMP_VERSION}-x86_64-unknown-linux-gnu" /opt/casescope/bin/evtx_dump
    chmod +x /opt/casescope/bin/evtx_dump
    
    # Verify it's actually there and executable
    if [ ! -f /opt/casescope/bin/evtx_dump ]; then
        log_error "Failed to move evtx_dump binary to /opt/casescope/bin/evtx_dump"
        return 1
    fi
    
    if [ ! -x /opt/casescope/bin/evtx_dump ]; then
        log_error "evtx_dump binary is not executable"
        ls -la /opt/casescope/bin/evtx_dump
        return 1
    fi
    
    # Set ownership
    chown casescope:casescope /opt/casescope/bin/evtx_dump
    
    # Test execution as casescope user
    log "Testing evtx_dump execution..."
    if sudo -u casescope /opt/casescope/bin/evtx_dump --version 2>/dev/null; then
        log "✓ evtx_dump $(sudo -u casescope /opt/casescope/bin/evtx_dump --version 2>/dev/null | head -n1)"
    else
        log_error "evtx_dump verification failed"
        ls -la /opt/casescope/bin/evtx_dump
        sudo -u casescope /opt/casescope/bin/evtx_dump --version || true
        return 1
    fi
    
    # Cleanup
    rm -f /tmp/evtx_dump-*
    
    log "evtx_dump installed successfully"
}

# Create system user
create_user() {
    log_step "Checking for casescope system user..."
    
    if ! id "casescope" &>/dev/null; then
        log_step "Creating casescope system user..."
        if useradd -r -s /bin/bash -d /opt/casescope -m casescope 2>/dev/null; then
            log_success "User 'casescope' created successfully"
        else
            log_error "Failed to create casescope user"
            return 1
        fi
    else
        log_success "User 'casescope' already exists"
    fi
    
    # Verify user was created properly
    log_step "Verifying user configuration..."
    if id casescope &>/dev/null; then
        USER_INFO=$(id casescope)
        log_success "User verified: $USER_INFO"
    else
        log_error "User verification failed"
        return 1
    fi
    
    echo
}

# Create directory structure and apply system optimizations
create_directories() {
    log_step "Creating complete directory structure..."
    
    # Main directories
    local directories=(
        "/opt/casescope/app:Application code"
        "/opt/casescope/data:Database and case data"
        "/opt/casescope/data/backups:Data backups"
        "/opt/casescope/uploads:Uploaded files"
        "/opt/casescope/logs:Application logs"
        "/opt/casescope/logs/app:App logs"
        "/opt/casescope/logs/nginx:Web server logs"
        "/opt/casescope/logs/system:System logs"
        "/opt/casescope/bin:External binaries"
        "/opt/casescope/rules:SIGMA rules"
        "/opt/casescope/config:Configuration files"
        "/opt/casescope/tmp:Temporary files"
    )
    
    for dir_info in "${directories[@]}"; do
        IFS=':' read -r dir desc <<< "$dir_info"
        mkdir -p "$dir" 2>/dev/null
    done
    log_success "All directories created"
    
    # Set ownership
    log_step "Setting directory ownership and permissions..."
    chown -R casescope:casescope /opt/casescope
    chmod 755 /opt/casescope
    chmod 750 /opt/casescope/data
    chmod 755 /opt/casescope/uploads
    chmod 755 /opt/casescope/logs
    log_success "Ownership and permissions configured"
    
    # System optimizations for OpenSearch and performance
    log_step "Applying system optimizations..."
    
    # Increase virtual memory map limit for OpenSearch (required)
    if ! grep -q "vm.max_map_count" /etc/sysctl.conf; then
        echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
        log_success "Added vm.max_map_count to sysctl.conf"
    fi
    sysctl -w vm.max_map_count=262144 >/dev/null 2>&1
    log_success "Virtual memory map count: 262144"
    
    # Optimize file descriptor limits for casescope user
    if ! grep -q "casescope.*nofile" /etc/security/limits.conf; then
        cat >> /etc/security/limits.conf << EOF
casescope soft nofile 65536
casescope hard nofile 65536
casescope soft nproc 4096
casescope hard nproc 4096
EOF
        log_success "File descriptor limits configured"
    else
        log_success "File descriptor limits already configured"
    fi
    
    # Optimize swappiness for better Java/OpenSearch performance
    if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
        echo 'vm.swappiness=1' >> /etc/sysctl.conf
        log_success "Added vm.swappiness to sysctl.conf"
    fi
    sysctl -w vm.swappiness=1 >/dev/null 2>&1
    log_success "Swappiness optimized for Java workloads"
    
    echo
    log_success "Directory structure and system optimizations completed"
    echo
}

# Handle data based on installation type
handle_existing_data() {
    case $INSTALL_TYPE in
        "clean")
            log "Performing COMPLETE clean installation - removing all existing data and services..."
            
            # Stop and disable all services
            log "Stopping all caseScope services..."
            systemctl stop casescope-worker 2>/dev/null || true
            systemctl stop casescope-web 2>/dev/null || true
            systemctl stop opensearch 2>/dev/null || true
            systemctl stop nginx 2>/dev/null || true
            systemctl stop redis-server 2>/dev/null || true
            
            systemctl disable casescope-worker 2>/dev/null || true
            systemctl disable casescope-web 2>/dev/null || true
            systemctl disable opensearch 2>/dev/null || true
            
            # Remove service files
            log "Removing service files..."
            rm -f /etc/systemd/system/casescope-worker.service 2>/dev/null || true
            rm -f /etc/systemd/system/casescope-web.service 2>/dev/null || true
            rm -f /etc/systemd/system/opensearch.service 2>/dev/null || true
            
            # Remove Nginx site configuration
            log "Removing Nginx configuration..."
            rm -f /etc/nginx/sites-enabled/casescope 2>/dev/null || true
            rm -f /etc/nginx/sites-available/casescope 2>/dev/null || true
            
            # Remove all application data
            log "Removing all application data..."
            rm -rf /opt/casescope/* 2>/dev/null || true
            
            # Remove OpenSearch completely
            log "Removing OpenSearch installation and data..."
            rm -rf /opt/opensearch 2>/dev/null || true
            rm -rf /var/lib/opensearch 2>/dev/null || true
            
            # Remove any leftover processes
            log "Ensuring all processes are terminated..."
            pkill -f opensearch 2>/dev/null || true
            pkill -f casescope 2>/dev/null || true
            
            # Reload systemd
            systemctl daemon-reload
            
            log "Clean installation: ALL data, services, and configurations removed"
            ;;
            
        "upgrade")
            log "Upgrade installation - preserving existing data..."
            
            # Ensure backup directory exists
            mkdir -p /opt/casescope/data/backups
            chown casescope:casescope /opt/casescope/data/backups
            
            # Create backup of database
            if [ -f /opt/casescope/data/casescope.db ]; then
                BACKUP_NAME="casescope.db.backup.$(date +%Y%m%d_%H%M%S)"
                cp /opt/casescope/data/casescope.db /opt/casescope/data/backups/$BACKUP_NAME
                chown casescope:casescope /opt/casescope/data/backups/$BACKUP_NAME
                log "Database backed up to: /opt/casescope/data/backups/$BACKUP_NAME"
            fi
            
            # Stop services for upgrade but keep data
            systemctl stop casescope-worker 2>/dev/null || true
            systemctl stop casescope-web 2>/dev/null || true
            systemctl stop nginx 2>/dev/null || true
            
            log "Upgrade: Existing data preserved, services stopped for update"
            ;;
            
        "reindex")
            log "Clear indexes installation - removing OpenSearch data only..."
            
            # Stop services
            systemctl stop casescope-worker 2>/dev/null || true
            systemctl stop casescope-web 2>/dev/null || true
            systemctl stop opensearch 2>/dev/null || true
            
            # Remove OpenSearch indexes and data (but not the installation)
            log "Removing OpenSearch index data..."
            rm -rf /var/lib/opensearch/nodes/*/indices/casescope-* 2>/dev/null || true
            rm -rf /opt/opensearch/data/nodes/*/indices/casescope-* 2>/dev/null || true
            rm -rf /opt/opensearch/data/nodes/*/indices/* 2>/dev/null || true
            rm -rf /var/lib/opensearch/nodes/*/indices/* 2>/dev/null || true
            
            # Clear upload files (since they'll need to be re-indexed anyway)
            log "Clearing uploaded files (will need re-upload for re-indexing)..."
            rm -rf /opt/casescope/uploads/* 2>/dev/null || true
            
            log "Reindex: OpenSearch indexes and uploaded files cleared"
            log "Database and user accounts preserved"
            ;;
    esac
}

# Update OpenSearch configuration for existing installations
update_opensearch_config() {
    log "Updating OpenSearch configuration for SIGMA rule support..."
    
    # Check if OpenSearch config exists
    if [ ! -f "/opt/opensearch/config/opensearch.yml" ]; then
        log_warning "OpenSearch config not found - will be created during install"
        return 0
    fi
    
    # Remove any existing max_clause_count setting (for idempotency)
    sed -i '/^indices\.query\.bool\.max_clause_count:/d' /opt/opensearch/config/opensearch.yml
    
    # Add the setting to opensearch.yml (cluster config, not JVM option)
    log "Setting indices.query.bool.max_clause_count=16384 in opensearch.yml..."
    echo "" >> /opt/opensearch/config/opensearch.yml
    echo "# SIGMA rule support - increase max boolean clauses for complex queries" >> /opt/opensearch/config/opensearch.yml
    echo "# Some SIGMA rules generate 10,000+ clauses, set to 16,384 for headroom" >> /opt/opensearch/config/opensearch.yml
    echo "indices.query.bool.max_clause_count: 16384" >> /opt/opensearch/config/opensearch.yml
    log "✓ Added max_clause_count=16384 to OpenSearch cluster config"
    
    # Ensure proper ownership and permissions on config files
    log "Setting OpenSearch config ownership..."
    chown -R casescope:casescope /opt/opensearch/config
    log "✓ Config permissions set"
    
    # Restart OpenSearch to apply changes
    if systemctl is-active --quiet opensearch; then
        log "Restarting OpenSearch to apply configuration changes..."
        systemctl restart opensearch
    else
        log "Starting OpenSearch with new configuration..."
        systemctl start opensearch
    fi
    
    # Wait for OpenSearch to come back up
    log "Waiting for OpenSearch to start..."
    for i in {1..60}; do
        sleep 1
        if curl -fsS http://127.0.0.1:9200 >/dev/null 2>&1; then
            log "✓ OpenSearch started successfully"
            
            # Verify the setting was applied
            ACTUAL_VALUE=$(curl -s 'http://127.0.0.1:9200/_nodes?filter_path=nodes.*.settings.indices.query.bool.max_clause_count' 2>/dev/null | grep -o '"max_clause_count":"[0-9]*"' | cut -d'"' -f4 | head -1)
            if [ "$ACTUAL_VALUE" = "16384" ]; then
                log "✓ Verified: max_clause_count is set to 16384 in running cluster"
            else
                log_warning "Warning: max_clause_count is $ACTUAL_VALUE (expected 16384)"
            fi
            
            # Configure cluster to keep queries alive even if client disconnects (prevents timeout cancellations)
            log "Configuring OpenSearch to tolerate client disconnects during long queries..."
            curl -s -X PUT http://127.0.0.1:9200/_cluster/settings \
                -H 'Content-Type: application/json' \
                -d '{"transient":{"search.default_keep_alive":"5m"}}' >/dev/null 2>&1
            log "✓ Configured search.default_keep_alive=5m"
            
            return 0
        fi
    done
    log_warning "OpenSearch is taking longer than expected to start"
}

# Install OpenSearch
install_opensearch() {
    log "Installing OpenSearch ${OPENSEARCH_VERSION}..."
    
    if [ ! -d "/opt/opensearch" ]; then
        cd /tmp
        
        # Download OpenSearch
        log "Downloading OpenSearch ${OPENSEARCH_VERSION}..."
        wget -q https://artifacts.opensearch.org/releases/bundle/opensearch/${OPENSEARCH_VERSION}/opensearch-${OPENSEARCH_VERSION}-linux-x64.tar.gz
        
        # Extract
        log "Extracting OpenSearch..."
        tar -xzf opensearch-${OPENSEARCH_VERSION}-linux-x64.tar.gz
        
        # Move to final location
        mv opensearch-${OPENSEARCH_VERSION} /opt/opensearch
        
        # Create required directories
        mkdir -p /opt/opensearch/tmp
        mkdir -p /opt/opensearch/data
        mkdir -p /opt/opensearch/logs
        
        # Set ownership
        chown -R casescope:casescope /opt/opensearch
        
        # Clean up
        rm -f opensearch-${OPENSEARCH_VERSION}-linux-x64.tar.gz
        
        log "OpenSearch installed"
    else
        log "OpenSearch already installed"
        # Ensure required directories exist even if OpenSearch was already installed
        mkdir -p /opt/opensearch/tmp
        mkdir -p /opt/opensearch/data
        mkdir -p /opt/opensearch/logs
        chown -R casescope:casescope /opt/opensearch
    fi
    
    # Configure OpenSearch with optimized startup settings
    cat > /opt/opensearch/config/opensearch.yml << 'EOF'
# Basic cluster configuration
cluster.name: casescope-cluster
node.name: casescope-node
path.data: /opt/opensearch/data
path.logs: /opt/opensearch/logs
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node

# Security settings
plugins.security.disabled: true
bootstrap.memory_lock: false

# Startup performance optimizations
action.auto_create_index: true
cluster.routing.allocation.disk.threshold_enabled: false
cluster.routing.allocation.awareness.attributes: ""
cluster.routing.rebalance.enable: none

# Index and cache optimizations for faster startup
indices.fielddata.cache.size: 15%
indices.memory.index_buffer_size: 5%
indices.memory.min_index_buffer_size: 48mb
indices.queries.cache.size: 5%
indices.requests.cache.size: 1%

# Network and timeout optimizations
http.max_content_length: 100mb
http.compression: true
http.compression_level: 3
network.tcp.keep_alive: true
network.tcp.reuse_address: true

# Discovery is handled automatically by discovery.type: single-node
# No additional discovery settings needed for single-node mode

# Thread pool optimizations for faster startup
thread_pool.write.queue_size: 200
thread_pool.search.queue_size: 500
thread_pool.get.queue_size: 500

# Gateway and recovery settings for faster startup (OpenSearch 2.11.1 compatible)
gateway.recover_after_data_nodes: 1
gateway.expected_data_nodes: 1
gateway.recover_after_time: 0s

# Plugin management - only disable what we know exists
plugins.index_state_management.enabled: false

# Logging optimizations
logger.level: WARN
logger.org.opensearch.discovery: ERROR
logger.org.opensearch.cluster.service: ERROR

# SIGMA rule support - increase max boolean clauses for complex queries
# Some SIGMA rules generate 10,000+ clauses, set to 16,384 for headroom
indices.query.bool.max_clause_count: 16384
EOF
    
    # Ensure security plugin is disabled and demo config is not installed
    log "Configuring OpenSearch security settings..."
    
    # Remove any existing security configuration
    sed -i '/^plugins\.security\.disabled/d' /opt/opensearch/config/opensearch.yml
    echo 'plugins.security.disabled: true' >> /opt/opensearch/config/opensearch.yml
    
    # Disable demo configuration
    export DISABLE_INSTALL_DEMO_CONFIG=true
    
    # Set proper permissions for OpenSearch config
    chown -R casescope:casescope /opt/opensearch/config
    
    # Set JVM options optimized for fastest startup performance
    TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [ "$TOTAL_MEM" -lt 2048 ]; then
        # Less than 2GB RAM - use 1GB heap
        HEAP_SIZE="1g"
    elif [ "$TOTAL_MEM" -lt 4096 ]; then
        # 2-4GB RAM - use 2GB heap
        HEAP_SIZE="2g"
    elif [ "$TOTAL_MEM" -lt 8192 ]; then
        # 4-8GB RAM - use 4GB heap (was 2GB - too conservative)
        HEAP_SIZE="4g"
    elif [ "$TOTAL_MEM" -lt 16384 ]; then
        # 8-16GB RAM - use 6GB heap (like the old system)
        HEAP_SIZE="6g"
    else
        # 16GB+ RAM - use 8GB heap
        HEAP_SIZE="8g"
    fi
    
    cat > /opt/opensearch/config/jvm.options << EOF
# Heap Settings - Fixed size for faster startup
-Xms${HEAP_SIZE}
-Xmx${HEAP_SIZE}

# Unlock experimental options FIRST (must come before experimental flags)
-XX:+UnlockExperimentalVMOptions
-XX:+UnlockDiagnosticVMOptions

# GC Settings optimized for startup speed
-XX:+UseG1GC
-XX:G1HeapRegionSize=16m
-XX:MaxGCPauseMillis=100
-XX:G1NewSizePercent=20
-XX:G1MaxNewSizePercent=30
-XX:InitiatingHeapOccupancyPercent=45
-XX:+DisableExplicitGC
-XX:+UseStringDeduplication

# JIT Compiler optimizations for faster startup
-XX:TieredStopAtLevel=1
-XX:+UseSharedSpaces
-XX:+UseContainerSupport

# Class loading optimizations
-XX:+LogVMOutput
-XX:+UseTransparentHugePages

# I/O and Security optimizations
-Djava.io.tmpdir=/opt/opensearch/tmp
-Dlog4j2.formatMsgNoLookups=true
-Djava.security.policy=file:///opt/opensearch/config/opensearch.policy
-Dfile.encoding=UTF-8
-Djava.awt.headless=true

# Network optimizations
-Dopensearch.networkaddress.cache.ttl=60
-Dopensearch.networkaddress.cache.negative.ttl=10

# Disable unnecessary features for faster startup
-Dopensearch.scripting.update.ctx_in_params=false
-Dopensearch.allow_insecure_settings=true
EOF
    
    log "Configured JVM with startup optimizations - heap size: ${HEAP_SIZE} (Total RAM: ${TOTAL_MEM}MB)"
    
    # Create systemd service
    cat > /etc/systemd/system/opensearch.service << 'EOF'
[Unit]
Description=OpenSearch
After=network.target

[Service]
Type=simple
RuntimeDirectory=opensearch
PrivateTmp=true
Environment=OS_HOME=/opt/opensearch
Environment=OS_PATH_CONF=/opt/opensearch/config
Environment=DISABLE_INSTALL_DEMO_CONFIG=true
WorkingDirectory=/opt/opensearch
User=casescope
Group=casescope
ExecStart=/opt/opensearch/bin/opensearch
LimitNOFILE=65535
LimitNPROC=4096
LimitAS=infinity
TimeoutStartSec=300
TimeoutStopSec=60
KillMode=process
KillSignal=SIGTERM
SendSIGKILL=no
SuccessExitStatus=143
Restart=no

[Install]
WantedBy=multi-user.target
EOF
    
    systemctl daemon-reload
    systemctl enable opensearch
}

# Copy application files
copy_application() {
    log "Copying application files..."
    
    # Get the directory where the install script is located and current working directory
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd 2>/dev/null || dirname "$(readlink -f "$0" 2>/dev/null || realpath "$0" 2>/dev/null || echo "$0")")"
    CURRENT_DIR="$(pwd)"
    
    log "Script directory: $SCRIPT_DIR"
    log "Current working directory: $CURRENT_DIR"
    log "Available files in script directory:"
    ls -la "$SCRIPT_DIR" | head -10
    log "Available files in current directory:"
    ls -la "$CURRENT_DIR" | head -10
    
    # Try to find application files in common locations
    APP_SOURCE_DIR=""
    
    # Priority 1: Check current working directory first (most common case)
    if [ -f "$CURRENT_DIR/main.py" ]; then
        APP_SOURCE_DIR="$CURRENT_DIR"
        log "Found application files in current working directory: $CURRENT_DIR"
    # Priority 2: Check if files are in the same directory as the script
    elif [ -f "$SCRIPT_DIR/main.py" ]; then
        APP_SOURCE_DIR="$SCRIPT_DIR"
        log "Found application files in script directory: $SCRIPT_DIR"
    # Priority 3: Check parent directory of current working directory
    elif [ -f "$CURRENT_DIR/../main.py" ]; then
        APP_SOURCE_DIR="$(cd "$CURRENT_DIR/.." && pwd)"
        log "Found application files in parent directory: $APP_SOURCE_DIR"
    # Priority 4: Check parent directory of script
    elif [ -f "$SCRIPT_DIR/../main.py" ]; then
        APP_SOURCE_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
        log "Found application files in script parent directory: $APP_SOURCE_DIR"
    # Priority 5: Search for main.py in common home directories
    else
        for homedir in /home/*; do
            if [ -f "$homedir/caseScope7/main.py" ]; then
                APP_SOURCE_DIR="$homedir/caseScope7"
                log "Found application files in: $APP_SOURCE_DIR"
                break
            elif [ -f "$homedir/casescope/main.py" ]; then
                APP_SOURCE_DIR="$homedir/casescope"
                log "Found application files in: $APP_SOURCE_DIR"
                break
            elif [ -f "$homedir/caseScope7_cursor/main.py" ]; then
                APP_SOURCE_DIR="$homedir/caseScope7_cursor"
                log "Found application files in: $APP_SOURCE_DIR"
                break
            fi
        done
    fi
    
    # If still not found, error out
    if [ -z "$APP_SOURCE_DIR" ]; then
        log_error "Cannot locate application files (main.py, requirements.txt, etc.)"
        log_error ""
        log_error "DEBUGGING INFORMATION:"
        log_error "Expected files: main.py, requirements.txt, version.json, wsgi.py"
        log_error "Current script location: $SCRIPT_DIR"
        log_error "Current working directory: $CURRENT_DIR"
        log_error ""
        log_error "FILES IN CURRENT DIRECTORY:"
        ls -la "$CURRENT_DIR"
        log_error ""
        log_error "FILES IN SCRIPT DIRECTORY:"
        ls -la "$SCRIPT_DIR"
        log_error ""
        log_error "SOLUTION:"
        log_error "Ensure you're running: cd caseScope7 && sudo ./install.sh"
        log_error "Current command appears to be running from: $CURRENT_DIR"
        exit 1
    fi
    
    log "Using application source directory: $APP_SOURCE_DIR"
    log "Available files in application source directory:"
    ls -la "$APP_SOURCE_DIR" | head -20
    
    # Copy all application files from source directory, excluding install.sh
    log "Copying all files except install.sh..."
    find "$APP_SOURCE_DIR" -maxdepth 1 -type f ! -name "install.sh" -exec cp {} /opt/casescope/app/ \; 2>/dev/null || true
    
    # Also copy any subdirectories (like templates, static)
    for dir in templates static; do
        if [ -d "$APP_SOURCE_DIR/$dir" ]; then
            log "Copying directory: $dir"
            cp -r "$APP_SOURCE_DIR/$dir" /opt/casescope/app/ 2>/dev/null || true
        fi
    done
    
    # Verify what we actually copied
    log "Files copied to /opt/casescope/app/:"
    ls -la /opt/casescope/app/ | head -20
    
    # Check for critical files and provide detailed diagnostics
    log "Checking for critical application files..."
    
    # Core application files (required for all install types)
    for file in main.py requirements.txt version.json wsgi.py celery_app.py tasks.py theme.py iris_client.py iris_sync.py ConvertEVTXtoJSON.sh; do
        if [ -f "$APP_SOURCE_DIR/$file" ]; then
            log "✓ Found $file in source directory"
            cp "$APP_SOURCE_DIR/$file" /opt/casescope/app/ 2>/dev/null || log_error "Failed to copy $file"
        else
            log_warning "✗ $file not found in source directory: $APP_SOURCE_DIR"
        fi
        
        if [ -f "/opt/casescope/app/$file" ]; then
            log "✓ $file successfully copied to destination"
        else
            log_error "✗ $file missing from destination"
        fi
    done
    
    # Set ownership
    chown -R casescope:casescope /opt/casescope/app
    
    # Final verification with detailed error reporting
    if [ ! -f "/opt/casescope/app/main.py" ]; then
        log_error "CRITICAL: main.py not found after copying"
        log_error "Source directory: $APP_SOURCE_DIR"
        log_error "Source directory contents:"
        ls -la "$APP_SOURCE_DIR"
        log_error "Destination directory contents:"
        ls -la /opt/casescope/app/
        log_error ""
        log_error "SOLUTION: Run the installer from the caseScope project directory:"
        log_error "1. cd /path/to/your/casescope/directory"
        log_error "2. sudo ./install.sh"
        log_error ""
        log_error "Or copy the application files to the same directory as install.sh"
        exit 1
    fi
    
    if [ ! -f "/opt/casescope/app/requirements.txt" ]; then
        log_warning "requirements.txt not found. Will install basic dependencies."
    fi
    
    log "Application files copied successfully from: $APP_SOURCE_DIR"
}

# Setup Python environment
setup_python() {
    log_step "Creating Python virtual environment..."
    if sudo -u casescope python3 -m venv /opt/casescope/venv 2>/dev/null; then
        log_success "Virtual environment created at /opt/casescope/venv"
    else
        log_error "Failed to create virtual environment"
        return 1
    fi
    
    log_step "Upgrading pip to latest version..."
    if sudo -u casescope /opt/casescope/venv/bin/pip install --upgrade pip -q 2>&1 | grep -i "error"; then
        log_warning "Pip upgrade had warnings (non-fatal)"
    else
        PIP_VERSION=$(sudo -u casescope /opt/casescope/venv/bin/pip --version | awk '{print $2}')
        log_success "Pip upgraded to version $PIP_VERSION"
    fi
    
    # Check if requirements.txt exists and install dependencies
    if [ -f "/opt/casescope/app/requirements.txt" ]; then
        log_step "Installing Python dependencies from requirements.txt..."
        DEP_COUNT=$(wc -l < /opt/casescope/app/requirements.txt)
        log_step "Found $DEP_COUNT package dependencies to install..."
        
        if sudo -u casescope /opt/casescope/venv/bin/pip install -r /opt/casescope/app/requirements.txt -q 2>&1 | tee /tmp/pip-install.log | grep -i "error\|failed" > /tmp/pip-errors.log; then
            if [ -s /tmp/pip-errors.log ]; then
                log_error "Some Python packages failed to install:"
                cat /tmp/pip-errors.log
                rm -f /tmp/pip-install.log /tmp/pip-errors.log
                return 1
            fi
        fi
        
        log_success "All Python dependencies installed successfully"
        rm -f /tmp/pip-install.log /tmp/pip-errors.log
    else
        log_warning "requirements.txt not found, installing basic dependencies..."
        sudo -u casescope /opt/casescope/venv/bin/pip install \
            Flask==3.0.0 \
            Flask-Login==0.6.3 \
            Flask-SQLAlchemy==3.1.1 \
            Flask-WTF==1.2.1 \
            WTForms==3.1.1 \
            Werkzeug==3.0.1 \
            bcrypt==4.1.2 \
            SQLAlchemy==2.0.23 \
            opensearch-py==2.4.2 \
            celery==5.3.4 \
            redis==5.0.1 \
            gunicorn==21.2.0
    fi
    
    log "Python environment configured"
}

# Configure services
configure_services() {
    log "Configuring system services..."
    
    # Create Celery worker service
    cat > /etc/systemd/system/casescope-worker.service << 'EOF'
[Unit]
Description=caseScope Celery Worker
After=network.target redis.service opensearch.service

[Service]
Type=simple
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment=PATH=/opt/casescope/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONPATH=/opt/casescope/app
Environment=CELERY_WORKER_LOG_LEVEL=DEBUG
ExecStartPre=/bin/echo "[Worker] Starting Celery worker with DEBUG logging..."
ExecStartPre=/bin/mkdir -p /opt/casescope/tmp /opt/casescope/logs
ExecStartPre=/bin/chown -R casescope:casescope /opt/casescope/tmp /opt/casescope/logs
ExecStart=/opt/casescope/venv/bin/celery -A celery_app worker \
    -Q celery \
    -l DEBUG \
    -E \
    --pool=prefork \
    --concurrency=2 \
    --max-tasks-per-child=50 \
    --logfile=/opt/casescope/logs/celery_worker.log \
    --pidfile=/opt/casescope/tmp/celery_worker.pid
ExecStop=/bin/sh -c '/bin/echo "[Worker] Stopping Celery worker..." && /opt/casescope/venv/bin/celery -A celery_app control shutdown || true'
Restart=always
RestartSec=10
TimeoutStopSec=30
KillMode=mixed
KillSignal=SIGTERM
StandardOutput=journal
StandardError=journal
SyslogIdentifier=casescope-worker

[Install]
WantedBy=multi-user.target
EOF
    
    # Create web service
    cat > /etc/systemd/system/casescope-web.service << 'EOF'
[Unit]
Description=caseScope Web Application
After=network.target opensearch.service redis.service

[Service]
Type=exec
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment=PATH=/opt/casescope/venv/bin
Environment=PYTHONPATH=/opt/casescope/app
Environment=FLASK_ENV=production
Environment=FLASK_DEBUG=1
ExecStart=/opt/casescope/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 --timeout 300 --log-level debug --access-logfile - --error-logfile - main:app
Restart=always
RestartSec=3
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF
    
    # Configure Nginx
    cat > /etc/nginx/sites-available/casescope << 'EOF'
server {
    listen 80;
    server_name _;
    
    client_max_body_size 3G;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_read_timeout 300;
        proxy_connect_timeout 300;
        proxy_send_timeout 300;
    }
}
EOF
    
    # Enable site
    ln -sf /etc/nginx/sites-available/casescope /etc/nginx/sites-enabled/
    rm -f /etc/nginx/sites-enabled/default
    
    # Reload systemd and enable services
    systemctl daemon-reload
    systemctl enable casescope-worker
    systemctl enable casescope-web
    systemctl enable nginx
    systemctl enable redis-server
    
    log "Services configured"
}

# Start services
start_services() {
    log "Starting services in dependency order: OpenSearch → Redis → Web → Worker → Nginx"
    log "This ensures each service has its dependencies available before starting"
    
    # STEP 1: Start OpenSearch FIRST (foundation for indexing/search)
    log "STEP 1/5: Starting OpenSearch search engine..."
    log "Note: OpenSearch is a Java application and may take 1-2 minutes to fully initialize"
    
    # Set environment variable to disable demo config before starting
    export DISABLE_INSTALL_DEMO_CONFIG=true
    
    log "Issuing start command to OpenSearch service..."
    systemctl start opensearch --no-block
    START_RESULT=$?
    
    log "Start command exit code: $START_RESULT"
    
    if [ $START_RESULT -eq 0 ]; then
        log "Start command accepted by systemd. Beginning startup monitoring..."
        # Give a moment for the service to register
        sleep 2
    else
        log_error "Failed to issue start command to OpenSearch service (exit code: $START_RESULT)"
        log_error "Checking service status for more details..."
        systemctl status opensearch --no-pager
        return 1
    fi
    
    # Wait for OpenSearch to start with detailed progress indication  
    log "Monitoring OpenSearch startup progress (maximum wait: 90 attempts x 2 seconds = 3 minutes)"
    log "OpenSearch startup can take 2-3 minutes on first run - this is normal"
    log "Each status check represents a 2-second interval. Service is ready when API responds."
    
    startup_success=false
    for attempt in {1..90}; do
        echo -n "Attempt ${attempt}/90 ($(($attempt * 2))s): "
        
        # Check if the OpenSearch process is actually running (more reliable than systemd status)
        if pgrep -f "opensearch" >/dev/null 2>&1; then
            echo -n "${GREEN}Process running${NC} - "
            
            # Check if API is responding
            if curl -s --connect-timeout 3 --max-time 5 http://127.0.0.1:9200/_cluster/health >/dev/null 2>&1; then
                echo -e "${GREEN}✓ API responding - READY!${NC}"
                log "SUCCESS: OpenSearch is fully operational after ${attempt} attempts ($(($attempt * 2)) seconds)"
                
                # Check systemd status for informational purposes
                local systemd_status=$(systemctl is-active opensearch 2>/dev/null || echo "unknown")
                log "Process status: RUNNING, API status: READY, Systemd status: $systemd_status"
                startup_success=true
                break
            else
                echo -e "${YELLOW}API initializing (listening on port, not ready yet)${NC}"
            fi
        else
            # Process not running - check systemd status for more info
            if systemctl is-failed --quiet opensearch; then
                echo -e "${RED}✗ Service failed${NC}"
                log_error "OpenSearch service entered failed state on attempt ${attempt}"
                break
            elif systemctl is-active --quiet opensearch; then
                echo -e "${YELLOW}Systemd active but process not detected...${NC}"
            else
                echo -e "${YELLOW}Service starting...${NC}"
            fi
        fi
        
        # Show helpful information and current logs every 15 attempts
        if [ $((attempt % 15)) -eq 0 ]; then
            echo
            log "Status after ${attempt} attempts ($(($attempt * 2)) seconds): OpenSearch is still initializing"
            log "This is normal - OpenSearch startup includes: JVM init, plugin loading, cluster formation, index recovery"
            log "Recent OpenSearch activity:"
            journalctl -u opensearch -n 3 --no-pager | head -3
            echo
        fi
        
        sleep 2
    done
    
    if [ "$startup_success" = false ]; then
        echo
        log_error "OpenSearch failed to start properly after 90 attempts (3 minutes total)"
        log_error "This usually indicates a configuration or resource issue"
        echo
        echo -e "${BLUE}Diagnostic Information:${NC}"
        echo -e "Service Status: $(systemctl is-active opensearch 2>/dev/null || echo 'unknown')"
        echo -e "Service State: $(systemctl is-enabled opensearch 2>/dev/null || echo 'unknown')"
        echo
        echo -e "${BLUE}Troubleshooting Steps:${NC}"
        echo -e "1. Check service status: ${YELLOW}sudo systemctl status opensearch${NC}"
        echo -e "2. View recent logs: ${YELLOW}sudo journalctl -u opensearch -n 20${NC}"
        echo -e "3. View live logs: ${YELLOW}sudo journalctl -u opensearch -f${NC}"
        echo -e "4. Check system resources: ${YELLOW}free -h && df -h${NC}"
        echo -e "5. Verify Java installation: ${YELLOW}java -version${NC}"
        echo
        echo -e "${YELLOW}Common Issues and Solutions:${NC}"
        echo -e "• Insufficient memory: Reduce heap size in JVM options"
        echo -e "• Port conflicts: Check if port 9200 is already in use"
        echo -e "• Permission issues: Verify casescope user owns OpenSearch files"
        echo -e "• Disk space: Ensure adequate free space for data and logs"
        echo
        return 1
    fi
    
    # STEP 2: Start Redis (message broker for Celery)
    log "STEP 2/5: Starting Redis message broker..."
    systemctl start redis-server
    sleep 1
    if ! systemctl is-active --quiet redis-server; then
        log_error "Redis failed to start"
        systemctl status redis-server --no-pager
        return 1
    fi
    log "SUCCESS: Redis is running"
    
    # STEP 3: Start Web App (initializes DB, provides UI)
    log "STEP 3/5: Starting caseScope web application..."
    log "This service runs the main web interface and initializes the database"
    
    systemctl start casescope-web
    
    # Give the application time to initialize
    log "Waiting for web application to initialize (checking for 10 seconds)..."
    web_startup_success=false
    for i in {1..5}; do
        sleep 2
        if systemctl is-active --quiet casescope-web; then
            log "SUCCESS: caseScope web application is running"
            web_startup_success=true
            break
        else
            echo -n "."
        fi
    done
    echo
    
    if [ "$web_startup_success" = false ]; then
        log_error "caseScope web service failed to start within 10 seconds"
        echo
        echo -e "${BLUE}Diagnostic Information:${NC}"
        echo -e "Service Status: $(systemctl is-active casescope-web 2>/dev/null || echo 'failed')"
        echo
        echo -e "${BLUE}Detailed Error Analysis:${NC}"
        systemctl status casescope-web --no-pager -l
        echo
        echo -e "${BLUE}Recent Application Logs:${NC}"
        journalctl -u casescope-web -n 10 --no-pager
        echo
        echo -e "${YELLOW}Common Web Service Issues:${NC}"
        echo -e "• Python dependencies missing: Check requirements.txt installation"
        echo -e "• Database connection failed: Verify SQLite database permissions"
        echo -e "• Port 5000 conflict: Another service may be using this port"
        echo -e "• Virtual environment issues: Python venv may not be properly configured"
        echo
        echo -e "${BLUE}Troubleshooting Commands:${NC}"
        echo -e "Live logs: ${YELLOW}sudo journalctl -u casescope-web -f${NC}"
        echo -e "Test Python app: ${YELLOW}sudo -u casescope /opt/casescope/venv/bin/python /opt/casescope/app/main.py${NC}"
        echo -e "Check port 5000: ${YELLOW}sudo netstat -tlnp | grep 5000${NC}"
        echo
        return 1
    fi
    
    # STEP 4: Start Celery Worker (requires OpenSearch + Redis + DB ready)
    log "STEP 4/5: Starting Celery worker..."
    log "Worker depends on OpenSearch, Redis, and database being ready"
    systemctl start casescope-worker
    sleep 2
    if ! systemctl is-active --quiet casescope-worker; then
        log_warning "Celery worker may not have started properly"
        log "Check logs with: journalctl -u casescope-worker -n 50"
    else
        log "SUCCESS: Celery worker is running"
    fi
    
    # STEP 5: Start Nginx (final layer, reverse proxy)
    log "STEP 5/5: Starting Nginx web server..."
    log "Nginx will serve as the front-end proxy to route web traffic to caseScope"
    
    # Test configuration first
    log "Testing Nginx configuration before starting..."
    if nginx -t 2>/dev/null; then
        log "✓ Nginx configuration is valid"
    else
        log_error "Nginx configuration test failed"
        echo -e "${BLUE}Configuration Test Output:${NC}"
        nginx -t
        echo
        echo -e "${YELLOW}Common Nginx Configuration Issues:${NC}"
        echo -e "• Syntax errors in config files"
        echo -e "• Missing SSL certificates (if HTTPS is configured)"
        echo -e "• Invalid upstream server definitions"
        echo -e "• Port conflicts or permission issues"
        echo
        return 1
    fi
    
    systemctl start nginx
    sleep 2
    
    if systemctl is-active --quiet nginx; then
        log "SUCCESS: Nginx web server is running"
        
        # Verify the caseScope site is properly configured
        if [ -f "/etc/nginx/sites-enabled/casescope" ]; then
            log "✓ caseScope site configuration is active"
        else
            log_warning "caseScope site configuration not found in sites-enabled"
        fi
        
        # Check if default site is disabled
        if [ ! -f "/etc/nginx/sites-enabled/default" ]; then
            log "✓ Default Nginx site is properly disabled"
        else
            log_warning "Default Nginx site is still enabled - you may see the default page instead of caseScope"
        fi
    else
        log_error "Nginx failed to start"
        echo
        echo -e "${BLUE}Nginx Service Status:${NC}"
        systemctl status nginx --no-pager -l
        echo
        echo -e "${BLUE}Nginx Error Logs:${NC}"
        tail -n 10 /var/log/nginx/error.log 2>/dev/null || echo "No error log found"
        echo
        echo -e "${YELLOW}Common Nginx Startup Issues:${NC}"
        echo -e "• Port 80 already in use by another service"
        echo -e "• Permission denied accessing log or pid files"
        echo -e "• Configuration file syntax errors"
        echo -e "• SELinux or AppArmor blocking Nginx"
        echo
        return 1
    fi
    
    log "All critical services have been started and verified"
}

# Initialize database
initialize_database() {
    log "Initializing database..."
    
    # Ensure database directory exists with proper permissions
    mkdir -p /opt/casescope/data
    mkdir -p /opt/casescope/data/backups
    chown -R casescope:casescope /opt/casescope/data
    chmod 755 /opt/casescope/data
    
    cd /opt/casescope/app
    
    # Check if database already exists and what type of install we're doing
    DB_EXISTS=false
    if [ -f "/opt/casescope/data/casescope.db" ]; then
        DB_EXISTS=true
        log "Existing database found"
    fi
    
    # Handle database based on installation type
    case $INSTALL_TYPE in
        "clean")
            log "Clean install: Creating fresh database..."
            # Remove existing database for clean install
            rm -f /opt/casescope/data/casescope.db 2>/dev/null || true
            INIT_DB=true
            ;;
        "upgrade")
            if [ "$DB_EXISTS" = true ]; then
                log "Upgrade install: Preserving existing database..."
                INIT_DB=false
            else
                log "Upgrade install: No existing database found, creating new one..."
                INIT_DB=true
            fi
            ;;
        "reindex")
            if [ "$DB_EXISTS" = true ]; then
                log "Reindex install: Preserving existing database..."
                INIT_DB=false
            else
                log "Reindex install: No existing database found, creating new one..."
                INIT_DB=true
            fi
            ;;
        *)
            log "Unknown install type, initializing database..."
            INIT_DB=true
            ;;
    esac
    
    if [ "$INIT_DB" = true ]; then
        # Initialize database with proper error handling
        sudo -u casescope /opt/casescope/venv/bin/python3 -c "
import sys
import os
sys.path.insert(0, '/opt/casescope/app')

try:
    from main import init_db
    print('Starting database initialization...')
    init_db()
    print('✓ Database tables created successfully')
    print('✓ Default administrator user created')
    print('  Username: administrator')
    print('  Password: ChangeMe!')
    print('  (Password change required on first login)')
    print('✓ Database initialization completed')
except Exception as e:
    print(f'ERROR: Database initialization failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"
        DB_INIT_RESULT=$?
        
        if [ $DB_INIT_RESULT -eq 0 ]; then
            log "Database initialized successfully"
            log "Default login: administrator / ChangeMe! (password change required)"
        else
            log_error "Failed to initialize database (exit code: $DB_INIT_RESULT)"
            log_error "Check Python dependencies and database permissions"
            return 1
        fi
    else
        log "Database preservation: Existing database retained"
        log "Using existing user accounts and settings"
        
        # Run unified database migrations
        log "Running database migrations..."
        
        # Use unified migration script (replaces 8 individual migration scripts)
        if [ -f "/opt/casescope/app/migrate_database.py" ]; then
            log "Using unified migration script (migrate_database.py)..."
            sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_database.py
            MIGRATION_RESULT=$?
            
            if [ $MIGRATION_RESULT -eq 0 ]; then
                log "✓ All database migrations completed successfully"
            else
                log_error "Database migrations failed (exit code: $MIGRATION_RESULT)"
                log_error "Check logs above for details"
                # Non-fatal - continue installation
            fi
        else
            log_warning "Unified migration script not found, using legacy migration scripts..."
            cd /opt/casescope/app
            
            # Fallback to individual migration scripts (for backwards compatibility)
            sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_audit_log.py 2>/dev/null || true
            sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_search_enhancements.py 2>/dev/null || true
            sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_case_management.py 2>/dev/null || true
            sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_timeline_tags.py 2>/dev/null || true
            sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_ioc_management.py 2>/dev/null || true
            sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_ioc_matches.py 2>/dev/null || true
            sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_system_settings.py 2>/dev/null || true
            sudo -u casescope /opt/casescope/venv/bin/python3 /opt/casescope/app/migrate_case_company.py 2>/dev/null || true
            
            log "✓ Legacy migrations completed (best-effort)"
        fi
        
        # Still run a basic check to ensure database is accessible
        sudo -u casescope /opt/casescope/venv/bin/python3 -c "
import sys
import os
sys.path.insert(0, '/opt/casescope/app')

try:
    from main import app, db
    with app.app_context():
        # Test database connection
        from sqlalchemy import text
        db.session.execute(text('SELECT 1')).fetchone()
        print('✓ Database connection verified')
        
        # Check if admin user exists
        from main import User
        admin_count = User.query.filter_by(username='administrator').count()
        print(f'✓ Found {admin_count} administrator account(s)')
        
        if admin_count == 0:
            print('⚠ No administrator account found - creating default account...')
            admin = User(
                username='administrator',
                email='admin@casescope.local',
                role='administrator',
                force_password_change=True
            )
            admin.set_password('ChangeMe!')
            db.session.add(admin)
            db.session.commit()
            print('✓ Default administrator user created')
            print('  Username: administrator')
            print('  Password: ChangeMe!')
        
except Exception as e:
    print(f'ERROR: Database verification failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"
        DB_CHECK_RESULT=$?
        
        if [ $DB_CHECK_RESULT -eq 0 ]; then
            log "Database verification completed successfully"
        else
            log_error "Failed to verify existing database (exit code: $DB_CHECK_RESULT)"
            log_error "Database may be corrupted or incompatible"
            return 1
        fi
    fi
}

# Download and import SIGMA rules
download_and_import_sigma_rules() {
    log "Downloading SIGMA rules from SigmaHQ GitHub..."
    
    # Create temp directory
    TEMP_DIR=$(mktemp -d)
    REPO_PATH="$TEMP_DIR/sigma"
    
    # Clone SigmaHQ repository (shallow clone for speed)
    /usr/bin/git clone --depth 1 https://github.com/SigmaHQ/sigma.git "$REPO_PATH" >/dev/null 2>&1
    
    if [ $? -ne 0 ]; then
        log_warning "Failed to clone SIGMA repository from GitHub"
        rm -rf "$TEMP_DIR"
        return 1
    fi
    
    log_success "SIGMA repository cloned successfully"
    
    # Import rules into database using Python script
    log "Importing SIGMA rules into database..."
    
    cd /opt/casescope/app
    sudo -u casescope /opt/casescope/venv/bin/python3 <<PYTHON_SCRIPT
import sys
import os
import yaml
import hashlib
import json
sys.path.insert(0, '/opt/casescope/app')

from main import app, db, SigmaRule

rules_dir = '$REPO_PATH/rules'
imported_count = 0
skipped_count = 0
error_count = 0

print("Scanning SIGMA rules directory...")

with app.app_context():
    for root, dirs, files in os.walk(rules_dir):
        for file in files:
            if file.endswith('.yml') or file.endswith('.yaml'):
                file_path = os.path.join(root, file)
                
                try:
                    with open(file_path, 'r', encoding='utf-8') as f:
                        yaml_content = f.read()
                        rule_data = yaml.safe_load(yaml_content)
                    
                    # Skip non-detection rules
                    if not rule_data.get('detection'):
                        continue
                    
                    # Calculate hash
                    rule_hash = hashlib.sha256(yaml_content.encode()).hexdigest()
                    
                    # Check if already exists
                    existing = db.session.query(SigmaRule).filter_by(rule_hash=rule_hash).first()
                    if existing:
                        skipped_count += 1
                        continue
                    
                    # Extract logsource
                    logsource = rule_data.get('logsource', {})
                    category = logsource.get('category', logsource.get('product', 'unknown'))
                    
                    # Auto-enable threat-hunting rules
                    is_threat_hunting = 'threat-hunting' in file_path and 'windows' in file_path.lower()
                    
                    # Create rule
                    rule = SigmaRule(
                        name=rule_data.get('id', file.replace('.yml', '').replace('.yaml', '')),
                        title=rule_data.get('title', 'Untitled Rule'),
                        description=rule_data.get('description', ''),
                        author=rule_data.get('author', 'SigmaHQ'),
                        level=rule_data.get('level', 'medium'),
                        status=rule_data.get('status', 'stable'),
                        category=category,
                        tags=json.dumps(rule_data.get('tags', [])),
                        rule_yaml=yaml_content,
                        rule_hash=rule_hash,
                        is_builtin=False,
                        is_enabled=is_threat_hunting,
                        uploaded_by=1  # Administrator user ID
                    )
                    
                    db.session.add(rule)
                    imported_count += 1
                    
                    # Commit every 100 rules
                    if imported_count % 100 == 0:
                        db.session.commit()
                        print(f"Imported {imported_count} rules so far...")
                
                except Exception as e:
                    error_count += 1
                    continue
    
    # Final commit
    db.session.commit()
    
    print(f"✓ SIGMA rules import complete:")
    print(f"  - {imported_count} new rules imported")
    print(f"  - {skipped_count} duplicates skipped")
    print(f"  - {error_count} errors")
    
    sys.exit(0)
PYTHON_SCRIPT
    
    if [ $? -eq 0 ]; then
        log_success "SIGMA rules imported successfully"
    else
        log_warning "SIGMA rules import had errors"
    fi
    
    # Cleanup temp directory
    rm -rf "$TEMP_DIR"
    
    # Run enable_threat_hunting_rules.py to enable Windows threat-hunting rules
    log "Enabling Windows threat-hunting rules..."
    
    cd /opt/casescope
    sudo -u casescope /opt/casescope/venv/bin/python3 enable_threat_hunting_rules.py
    
    if [ $? -eq 0 ]; then
        log_success "Windows threat-hunting rules enabled successfully"
    else
        log_warning "enable_threat_hunting_rules.py had errors (non-fatal)"
    fi
    
    echo
}

# Main installation function
main() {
    # Determine total steps based on install type
    local TOTAL_STEPS=13  # Increased from 12 to include SIGMA rules download
    local CURRENT_STEP=0
    
    log "Starting caseScope installation..."
    echo
    
    # Get installation choice
    get_choice
    echo
    
    #══════════════════════════════════════════════════════════════
    # PHASE 1: PRE-INSTALLATION (varies by install type)
    #══════════════════════════════════════════════════════════════
    
    # For clean install, cleanup MUST happen FIRST before any installation
    if [ "$INSTALL_TYPE" = "clean" ]; then
        ((CURRENT_STEP++))
        print_section $CURRENT_STEP $TOTAL_STEPS "Pre-Installation Cleanup"
        handle_existing_data  # Stop services, remove data
    fi
    
    #══════════════════════════════════════════════════════════════
    # PHASE 2: SYSTEM PREPARATION
    #══════════════════════════════════════════════════════════════
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "System Requirements Check"
    check_requirements
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Installing System Dependencies"
    install_dependencies
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Creating System User"
    create_user  # Create casescope user
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Creating Directory Structure & System Optimization"
    create_directories  # Create all directories and apply system optimizations
    
    #══════════════════════════════════════════════════════════════
    # PHASE 3: EXTERNAL TOOLS INSTALLATION
    #══════════════════════════════════════════════════════════════
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Installing External Tools (Chainsaw & evtx_dump)"
    
    # Chainsaw installation is CRITICAL
    if ! install_chainsaw; then
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║           CRITICAL: Chainsaw Installation Failed!          ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "${RED}Chainsaw is required for SIGMA rule processing.${NC}"
        echo -e "${YELLOW}Installation cannot continue without it.${NC}"
        echo
        exit 1
    fi
    
    # evtx_dump installation is CRITICAL
    if ! install_evtx_dump; then
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║          CRITICAL: evtx_dump Installation Failed!           ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "${RED}evtx_dump is required for fast EVTX parsing.${NC}"
        echo -e "${YELLOW}Installation cannot continue without it.${NC}"
        echo
        exit 1
    fi
    
    #══════════════════════════════════════════════════════════════
    # PHASE 4: DATA MANAGEMENT (varies by install type)
    #══════════════════════════════════════════════════════════════
    
    # For upgrade/reindex, backup existing data AFTER creating directories
    if [ "$INSTALL_TYPE" != "clean" ]; then
        ((CURRENT_STEP++))
        print_section $CURRENT_STEP $TOTAL_STEPS "Backing Up Existing Data"
        handle_existing_data  # Backup databases and configurations
    fi
    
    #══════════════════════════════════════════════════════════════
    # PHASE 5: CORE SERVICES INSTALLATION
    #══════════════════════════════════════════════════════════════
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Setting Up OpenSearch"
    # Install or update OpenSearch based on install type
    if [ "$INSTALL_TYPE" = "clean" ]; then
        install_opensearch
    else
        # For upgrade/reindex, update config first if OpenSearch exists
        if [ -d "/opt/opensearch" ]; then
            update_opensearch_config
        fi
        install_opensearch  # Will skip if already installed
    fi
    
    #══════════════════════════════════════════════════════════════
    # PHASE 6: APPLICATION DEPLOYMENT
    #══════════════════════════════════════════════════════════════
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Deploying Application Files"
    copy_application
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Configuring Python Environment"
    setup_python
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Configuring System Services"
    configure_services
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Initializing Database"
    initialize_database
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Downloading & Importing SIGMA Rules"
    download_and_import_sigma_rules
    
    # Force database creation check before starting services
    log "Performing final database verification..."
    cd /opt/casescope/app
    sudo -u casescope /opt/casescope/venv/bin/python3 -c "
import sys
import os
sys.path.insert(0, '/opt/casescope/app')

try:
    from main import app, init_db
    print('Final database check and creation...')
    init_db()
    print('✓ Final database verification completed')
    
    # Test a simple login attempt
    from main import User
    with app.app_context():
        admin = User.query.filter_by(username='administrator').first()
        if admin:
            print(f'✓ Administrator account confirmed: {admin.username}')
            print(f'  - Email: {admin.email}')  
            print(f'  - Role: {admin.role}')
            print(f'  - Active: {admin.is_active}')
            print(f'  - Force password change: {admin.force_password_change}')
        else:
            print('✗ Administrator account not found!')
            sys.exit(1)
except Exception as e:
    print(f'ERROR: Final database verification failed: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"
    
    if [ $? -eq 0 ]; then
        log "Final database verification: SUCCESS"
    else
        log_error "Final database verification failed - login may not work"
        return 1
    fi
    
    ((CURRENT_STEP++))
    print_section $CURRENT_STEP $TOTAL_STEPS "Starting & Verifying Services"
    start_services
    
    # Verify services are running
    log "Verifying service status..."
    echo
    echo -e "${BLUE}Service Status Check:${NC}"
    
    services=("redis-server" "opensearch" "casescope-worker" "casescope-web" "nginx")
    all_running=true
    
    for service in "${services[@]}"; do
        if systemctl is-active --quiet "$service"; then
            echo -e "  ✓ $service: ${GREEN}Running${NC}"
        else
            echo -e "  ✗ $service: ${RED}Failed${NC}"
            all_running=false
        fi
    done
    
    echo
    
    # Run comprehensive final verification
    if [ "$all_running" = true ]; then
        run_final_verification
        VERIFICATION_RESULT=$?
    else
        log_error "Cannot run verification - services failed to start"
        VERIFICATION_RESULT=1
    fi
    
    # Display installation result
    if [ "$all_running" = true ] && [ $VERIFICATION_RESULT -eq 0 ]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 Installation Complete!                      ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "caseScope ${VERSION} is now installed and running!"
        echo
        echo -e "${BLUE}Access Information:${NC}"
        echo -e "URL: ${GREEN}http://$(hostname -I | awk '{print $1}')${NC}"
        echo -e "Alternative: ${GREEN}http://localhost${NC}"
        echo -e "Default Username: ${GREEN}administrator${NC}"
        echo -e "Default Password: ${GREEN}ChangeMe!${NC}"
        echo
        echo -e "${YELLOW}Important:${NC} You will be required to change the default password on first login."
        echo
        echo -e "${BLUE}Troubleshooting (if login fails):${NC}"
        echo -e "Database Debug: ${GREEN}http://localhost/debug/database${NC}"
        echo -e "Service Logs: ${YELLOW}sudo journalctl -u casescope-web -f${NC}"
        echo -e "Application Logs: ${YELLOW}sudo tail -f /opt/casescope/logs/app.log${NC}"
        
        # Final database verification and test
        echo
        echo -e "${BLUE}Final Database Verification:${NC}"
        cd /opt/casescope/app
        sudo -u casescope /opt/casescope/venv/bin/python3 -c "
import sys
import os
sys.path.insert(0, '/opt/casescope/app')

try:
    from main import app, db, User
    with app.app_context():
        # Check database file exists
        db_path = '/opt/casescope/data/casescope.db'
        if os.path.exists(db_path):
            print(f'✓ Database file exists: {db_path}')
            file_size = os.path.getsize(db_path)
            print(f'✓ Database file size: {file_size} bytes')
        else:
            print(f'✗ Database file missing: {db_path}')
            sys.exit(1)
        
        # Test database connection
        try:
            from sqlalchemy import text
            result = db.session.execute(text('SELECT COUNT(*) FROM user')).scalar()
            print(f'✓ Database connection successful - {result} users found')
        except Exception as e:
            print(f'✗ Database connection failed: {e}')
            sys.exit(1)
        
        # Check admin user
        admin = User.query.filter_by(username='administrator').first()
        if admin:
            print(f'✓ Administrator user found: {admin.username}')
            print(f'  Email: {admin.email}')
            print(f'  Role: {admin.role}')
            print(f'  Active: {admin.is_active}')
            print(f'  Password change required: {admin.force_password_change}')
            
            # Test password validation
            password_test = admin.check_password('ChangeMe!')
            print(f'  Password validation test: {password_test}')
            
            if not password_test:
                print('✗ WARNING: Default password validation failed!')
            else:
                print('✓ Default password validation successful')
        else:
            print('✗ Administrator user not found!')
            sys.exit(1)
            
        print('✓ Database verification completed successfully')
        
except Exception as e:
    print(f'✗ Database verification error: {e}')
    import traceback
    traceback.print_exc()
    sys.exit(1)
"
        if [ $? -eq 0 ]; then
            echo -e "${GREEN}✓ Final database verification: PASSED${NC}"
        else
            echo -e "${RED}✗ Final database verification: FAILED${NC}"
            echo -e "${YELLOW}Check the output above for specific issues${NC}"
        fi
    else
        echo -e "${RED}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${RED}║              Installation Issues Detected!                  ║${NC}"
        echo -e "${RED}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "${RED}Some services failed to start properly.${NC}"
        echo
        echo -e "${BLUE}Troubleshooting Commands:${NC}"
        echo -e "Check service status: ${YELLOW}sudo systemctl status casescope-web${NC}"
        echo -e "View service logs: ${YELLOW}sudo journalctl -u casescope-web -f${NC}"
        echo -e "Check Nginx config: ${YELLOW}sudo nginx -t${NC}"
        echo -e "Test port 5000: ${YELLOW}curl http://localhost:5000${NC}"
        echo
        echo -e "If you see the Nginx default page instead of caseScope:"
        echo -e "1. ${YELLOW}sudo rm -f /etc/nginx/sites-enabled/default${NC}"
        echo -e "2. ${YELLOW}sudo systemctl restart nginx${NC}"
        echo -e "3. ${YELLOW}sudo systemctl restart casescope-web${NC}"
    fi
    
    echo
    echo -e "${BLUE}Installation Type:${NC} $INSTALL_TYPE"
    echo -e "${BLUE}Version:${NC} $VERSION"
    echo
    echo -e "Support: casescope@thedubes.net"
    echo -e "Copyright (c) 2025 Justin Dube"
    echo
}

# Run main function
main "$@"
