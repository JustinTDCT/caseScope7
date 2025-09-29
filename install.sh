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
    
    log "Directory structure created"
}

# Handle data based on installation type
handle_existing_data() {
    case $INSTALL_TYPE in
        "clean")
            log "Performing clean installation - removing all existing data..."
            
            # Stop services
            systemctl stop casescope-web 2>/dev/null || true
            systemctl stop opensearch 2>/dev/null || true
            systemctl stop redis 2>/dev/null || true
            
            # Remove all data
            rm -rf /opt/casescope/data/* 2>/dev/null || true
            rm -rf /opt/casescope/uploads/* 2>/dev/null || true
            rm -rf /opt/casescope/logs/* 2>/dev/null || true
            
            # Remove OpenSearch data
            rm -rf /var/lib/opensearch/* 2>/dev/null || true
            rm -rf /opt/opensearch/data/* 2>/dev/null || true
            
            log "Clean installation: all data removed"
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
        
        # Set ownership
        chown -R casescope:casescope /opt/opensearch
        
        # Clean up
        rm -f opensearch-2.11.1-linux-x64.tar.gz
        
        log "OpenSearch installed"
    else
        log "OpenSearch already installed"
    fi
    
    # Configure OpenSearch
    cat > /opt/opensearch/config/opensearch.yml << 'EOF'
cluster.name: casescope-cluster
node.name: casescope-node
path.data: /opt/opensearch/data
path.logs: /opt/opensearch/logs
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
plugins.security.disabled: true
bootstrap.memory_lock: false
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
    
    # Set JVM options
    cat > /opt/opensearch/config/jvm.options << 'EOF'
-Xms2g
-Xmx2g
-XX:+UseG1GC
-XX:G1HeapRegionSize=16m
-XX:+DisableExplicitGC
-Djava.io.tmpdir=/opt/opensearch/tmp
EOF
    
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
TimeoutStopSec=0
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
    
    # Get the directory where the install script is located
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    
    # Copy all application files from script directory
    cp -r "$SCRIPT_DIR"/* /opt/casescope/app/ 2>/dev/null || true
    
    # Ensure key files are copied
    [ -f "$SCRIPT_DIR/main.py" ] && cp "$SCRIPT_DIR/main.py" /opt/casescope/app/
    [ -f "$SCRIPT_DIR/requirements.txt" ] && cp "$SCRIPT_DIR/requirements.txt" /opt/casescope/app/
    [ -f "$SCRIPT_DIR/version.json" ] && cp "$SCRIPT_DIR/version.json" /opt/casescope/app/
    [ -f "$SCRIPT_DIR/wsgi.py" ] && cp "$SCRIPT_DIR/wsgi.py" /opt/casescope/app/
    
    # Set ownership
    chown -R casescope:casescope /opt/casescope/app
    
    # Verify critical files exist
    if [ ! -f "/opt/casescope/app/main.py" ]; then
        log_error "main.py not found after copying. Installation cannot continue."
        exit 1
    fi
    
    if [ ! -f "/opt/casescope/app/requirements.txt" ]; then
        log_warning "requirements.txt not found. Will install basic dependencies."
    fi
    
    log "Application files copied successfully"
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
    
    log "Starting OpenSearch..."
    # Set environment variable to disable demo config before starting
    export DISABLE_INSTALL_DEMO_CONFIG=true
    systemctl start opensearch
    sleep 15  # Wait for OpenSearch to start
    if ! systemctl is-active --quiet opensearch; then
        log_error "OpenSearch failed to start"
        systemctl status opensearch
        log_error "Check OpenSearch logs with: journalctl -u opensearch -n 50"
    fi
    
    log "Starting caseScope web application..."
    systemctl start casescope-web
    sleep 5  # Give the app time to start
    if ! systemctl is-active --quiet casescope-web; then
        log_error "caseScope web service failed to start"
        systemctl status casescope-web
        log_error "Check the service logs with: journalctl -u casescope-web -n 50"
    fi
    
    log "Starting Nginx..."
    systemctl start nginx
    if ! systemctl is-active --quiet nginx; then
        log_error "Nginx failed to start"
        systemctl status nginx
    fi
    
    # Test Nginx configuration
    nginx -t
    if [ $? -ne 0 ]; then
        log_error "Nginx configuration test failed"
    fi
    
    log "All services startup attempted"
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
    create_directories
    handle_existing_data
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
