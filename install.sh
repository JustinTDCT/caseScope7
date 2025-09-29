#!/bin/bash

# caseScope 7.1 Installation Script
# Copyright (c) 2025 Justin Dube <casescope@thedubes.net>

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
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

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

# Get version from version.json
get_version() {
    if [ -f "version.json" ]; then
        python3 -c "import json; print(json.load(open('version.json'))['version'])" 2>/dev/null || echo "7.1.1"
    else
        echo "7.1.1"
    fi
}

VERSION=$(get_version)

# Display header
clear
echo -e "${BLUE}"
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    caseScope 7.1 Installer                  ║"
echo "║              Digital Forensics Case Management               ║"
echo "║                                                              ║"
echo "║              Copyright (c) 2025 Justin Dube                 ║"
echo "║                casescope@thedubes.net                       ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"
echo
echo -e "Version: ${GREEN}$VERSION${NC}"
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
    log "Checking system requirements..."
    
    # Check Ubuntu version
    if ! grep -q "Ubuntu 24" /etc/os-release 2>/dev/null; then
        log_warning "Ubuntu 24.04 LTS is recommended for optimal performance"
    fi
    
    # Check available memory
    TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
    if [ "$TOTAL_MEM" -lt 8192 ]; then
        log_warning "Less than 8GB RAM detected. 8GB+ recommended for optimal performance."
    fi
    
    # Check available disk space
    AVAILABLE_SPACE=$(df / | awk 'NR==2 {print $4}')
    if [ "$AVAILABLE_SPACE" -lt 10485760 ]; then  # 10GB in KB
        log_warning "Less than 10GB free space available. More space recommended for case files."
    fi
    
    log "System requirements check completed"
}

# Install system dependencies
install_dependencies() {
    log "Installing system dependencies..."
    
    # Update package list
    apt-get update
    
    # Install required packages
    apt-get install -y \
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
        openjdk-11-jdk
    
    log "System dependencies installed successfully"
}

# Create system user
create_user() {
    log "Creating casescope system user..."
    
    if ! id "casescope" &>/dev/null; then
        useradd -r -s /bin/bash -d /opt/casescope -m casescope
        log "Created casescope user"
    else
        log "casescope user already exists"
    fi
}

# Create directory structure
create_directories() {
    log "Creating directory structure..."
    
    # Main directories
    mkdir -p /opt/casescope/{app,data,uploads,logs,rules,config,tmp}
    
    # Data subdirectories
    mkdir -p /opt/casescope/data/{database,backups}
    
    # Log subdirectories
    mkdir -p /opt/casescope/logs/{app,nginx,system}
    
    # Set ownership
    chown -R casescope:casescope /opt/casescope
    
    # Set permissions
    chmod 755 /opt/casescope
    chmod 750 /opt/casescope/data
    chmod 755 /opt/casescope/uploads
    chmod 755 /opt/casescope/logs
    
    # System optimizations for faster OpenSearch startup
    log "Applying system optimizations for faster OpenSearch startup..."
    
    # Increase virtual memory map limit for OpenSearch
    if ! grep -q "vm.max_map_count" /etc/sysctl.conf; then
        echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
    fi
    sysctl -w vm.max_map_count=262144
    
    # Optimize file descriptor limits
    if ! grep -q "casescope.*nofile" /etc/security/limits.conf; then
        echo 'casescope soft nofile 65536' >> /etc/security/limits.conf
        echo 'casescope hard nofile 65536' >> /etc/security/limits.conf
        echo 'casescope soft nproc 4096' >> /etc/security/limits.conf
        echo 'casescope hard nproc 4096' >> /etc/security/limits.conf
    fi
    
    # Optimize swappiness for better Java performance
    if ! grep -q "vm.swappiness" /etc/sysctl.conf; then
        echo 'vm.swappiness=1' >> /etc/sysctl.conf
    fi
    sysctl -w vm.swappiness=1
    
    log "Directory structure created and system optimized"
}

# Handle data based on installation type
handle_existing_data() {
    case $INSTALL_TYPE in
        "clean")
            log "Performing COMPLETE clean installation - removing all existing data and services..."
            
            # Stop and disable all services
            log "Stopping all caseScope services..."
            systemctl stop casescope-web 2>/dev/null || true
            systemctl stop opensearch 2>/dev/null || true
            systemctl stop nginx 2>/dev/null || true
            systemctl stop redis-server 2>/dev/null || true
            
            systemctl disable casescope-web 2>/dev/null || true
            systemctl disable opensearch 2>/dev/null || true
            
            # Remove service files
            log "Removing service files..."
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
            
            # Create backup of database
            if [ -f /opt/casescope/data/casescope.db ]; then
                cp /opt/casescope/data/casescope.db /opt/casescope/data/backups/casescope.db.backup.$(date +%Y%m%d_%H%M%S)
                log "Database backed up"
            fi
            ;;
            
        "reindex")
            log "Clear indexes installation - removing OpenSearch data only..."
            
            # Stop services
            systemctl stop casescope-web 2>/dev/null || true
            systemctl stop opensearch 2>/dev/null || true
            
            # Remove only OpenSearch indexes
            rm -rf /var/lib/opensearch/nodes/*/indices/casescope-* 2>/dev/null || true
            rm -rf /opt/opensearch/data/nodes/*/indices/casescope-* 2>/dev/null || true
            
            log "OpenSearch indexes cleared - files will need re-indexing"
            ;;
    esac
}

# Install OpenSearch
install_opensearch() {
    log "Installing OpenSearch..."
    
    if [ ! -d "/opt/opensearch" ]; then
        cd /tmp
        
        # Download OpenSearch
        wget -q https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.tar.gz
        
        # Extract
        tar -xzf opensearch-2.11.1-linux-x64.tar.gz
        
        # Move to final location
        mv opensearch-2.11.1 /opt/opensearch
        
        # Create required directories
        mkdir -p /opt/opensearch/tmp
        mkdir -p /opt/opensearch/data
        mkdir -p /opt/opensearch/logs
        
        # Set ownership
        chown -R casescope:casescope /opt/opensearch
        
        # Clean up
        rm -f opensearch-2.11.1-linux-x64.tar.gz
        
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
Type=notify
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
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
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
    # Priority 5: Check if user has a casescope directory (common git clone location)
    elif [ -d "/home/jdube/caseScope7" ] && [ -f "/home/jdube/caseScope7/main.py" ]; then
        APP_SOURCE_DIR="/home/jdube/caseScope7"
        log "Found application files in user caseScope7 directory: $APP_SOURCE_DIR"
    # Priority 5.5: Check other common casescope directory names
    elif [ -d "/home/jdube/casescope" ] && [ -f "/home/jdube/casescope/main.py" ]; then
        APP_SOURCE_DIR="/home/jdube/casescope"
        log "Found application files in user casescope directory: $APP_SOURCE_DIR"
    # Priority 6: Search broadly for casescope directories
    elif [ -f "/home/*/casescope*/main.py" ]; then
        APP_SOURCE_DIR="$(dirname $(ls /home/*/casescope*/main.py | head -1))"
        log "Found application files in user directory: $APP_SOURCE_DIR"
    else
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
        log_error "Ensure you're running: cd /home/jdube/caseScope7 && sudo ./install.sh"
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
    
    for file in main.py requirements.txt version.json wsgi.py; do
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
    log "Setting up Python virtual environment..."
    
    # Create virtual environment
    sudo -u casescope python3 -m venv /opt/casescope/venv
    
    # Install requirements
    sudo -u casescope /opt/casescope/venv/bin/pip install --upgrade pip
    
    # Check if requirements.txt exists and install dependencies
    if [ -f "/opt/casescope/app/requirements.txt" ]; then
        log "Installing Python dependencies from requirements.txt..."
        sudo -u casescope /opt/casescope/venv/bin/pip install -r /opt/casescope/app/requirements.txt
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
ExecStart=/opt/casescope/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 --timeout 300 main:app
Restart=always
RestartSec=3

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
    systemctl enable casescope-web
    systemctl enable nginx
    systemctl enable redis-server
    
    log "Services configured"
}

# Start services
start_services() {
    log "Starting services..."
    
    # Start services in order with status checks
    log "Starting Redis..."
    systemctl start redis-server
    if ! systemctl is-active --quiet redis-server; then
        log_error "Redis failed to start"
        systemctl status redis-server
    fi
    
    log "Starting OpenSearch search engine..."
    log "Note: OpenSearch is a Java application and may take 1-2 minutes to fully initialize"
    
    # Set environment variable to disable demo config before starting
    export DISABLE_INSTALL_DEMO_CONFIG=true
    
    log "Issuing start command to OpenSearch service..."
    systemctl start opensearch
    
    if [ $? -eq 0 ]; then
        log "Start command accepted by systemd. Beginning startup monitoring..."
    else
        log_error "Failed to issue start command to OpenSearch service"
        return 1
    fi
    
    # Wait for OpenSearch to start with detailed progress indication
    log "Monitoring OpenSearch startup progress (maximum wait: 60 attempts x 2 seconds = 2 minutes)"
    log "Each dot (.) represents a 2-second check. Service is ready when you see 'SUCCESS'"
    
    startup_success=false
    for attempt in {1..30}; do
        echo -n "Attempt ${attempt}/30: "
        
        # Check if the service is active
        if systemctl is-active --quiet opensearch; then
            echo -e "${GREEN}✓ Service is running${NC}"
            
            # Additional check: verify OpenSearch is responding on port 9200
            echo -n "Checking if OpenSearch API is responding... "
            if curl -s --connect-timeout 2 http://127.0.0.1:9200 >/dev/null 2>&1; then
                echo -e "${GREEN}✓ API responding${NC}"
                log "SUCCESS: OpenSearch is fully operational after ${attempt} attempts ($(($attempt * 2)) seconds)"
                startup_success=true
                break
            else
                echo -e "${YELLOW}Service running but API not ready yet${NC}"
            fi
        else
            # Check if service failed
            if systemctl is-failed --quiet opensearch; then
                echo -e "${RED}✗ Service failed${NC}"
                log_error "OpenSearch service entered failed state on attempt ${attempt}"
                break
            else
                echo -e "${YELLOW}Still starting...${NC}"
            fi
        fi
        
        # Show helpful information every 10 attempts
        if [ $((attempt % 10)) -eq 0 ]; then
            log "Status after ${attempt} attempts: OpenSearch is still initializing (this is normal)"
            log "Common startup delays: JVM initialization, plugin loading, cluster formation"
        fi
        
        sleep 2
    done
    
    if [ "$startup_success" = false ]; then
        echo
        log_error "OpenSearch failed to start properly after 30 attempts (60 seconds total)"
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
    
    log "Starting caseScope web application..."
    log "This service runs the main web interface that you'll access through your browser"
    
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
    
    log "Starting Nginx web server..."
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
    
    cd /opt/casescope/app
    sudo -u casescope /opt/casescope/venv/bin/python3 -c "
from main import app, db, User
with app.app_context():
    db.create_all()
    print('Database initialized')
"
    
    log "Database initialized"
}

# Main installation function
main() {
    log "Starting caseScope 7.1 installation..."
    
    # Get installation choice
    get_choice
    
    # Run installation steps
    check_requirements
    install_dependencies
    create_user
    handle_existing_data
    create_directories
    install_opensearch
    copy_application
    setup_python
    configure_services
    initialize_database
    start_services
    
    # Verify services are running
    log "Verifying service status..."
    echo
    echo -e "${BLUE}Service Status Check:${NC}"
    
    services=("redis-server" "opensearch" "casescope-web" "nginx")
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
    
    if [ "$all_running" = true ]; then
        echo -e "${GREEN}╔══════════════════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}║                 Installation Complete!                      ║${NC}"
        echo -e "${GREEN}╚══════════════════════════════════════════════════════════════╝${NC}"
        echo
        echo -e "caseScope 7.1 is now installed and running!"
        echo
        echo -e "${BLUE}Access Information:${NC}"
        echo -e "URL: ${GREEN}http://$(hostname -I | awk '{print $1}')${NC}"
        echo -e "Alternative: ${GREEN}http://localhost${NC}"
        echo -e "Default Username: ${GREEN}administrator${NC}"
        echo -e "Default Password: ${GREEN}ChangeMe!${NC}"
        echo
        echo -e "${YELLOW}Important:${NC} You will be required to change the default password on first login."
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
