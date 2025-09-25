#!/bin/bash

# caseScope v7.0.94 Installation Script
# Designed for Ubuntu 24 headless server
# Copyright 2025 Justin Dube

set -e

# Cleanup function for failed installations
cleanup_on_failure() {
    log_error "Installation failed. Cleaning up..."
    
    # Stop services
    systemctl stop casescope-web 2>/dev/null || true
    systemctl stop casescope-worker 2>/dev/null || true
    systemctl stop opensearch 2>/dev/null || true
    
    # Clean up temp files
    rm -f /tmp/opensearch-2.11.1-linux-x64.tar.gz 2>/dev/null || true
    rm -rf /tmp/opensearch-2.11.1 2>/dev/null || true
    rm -f /tmp/chainsaw.zip 2>/dev/null || true
    rm -f /tmp/chainsaw.tar.gz 2>/dev/null || true
    rm -rf /tmp/chainsaw* 2>/dev/null || true
    
    # Clean up working directory temp files
    rm -f chainsaw.zip chainsaw.tar.gz 2>/dev/null || true
    
    # Clean up any temporary directories
    rm -rf /tmp/tmp.* 2>/dev/null || true
    
    log_error "Cleanup completed. Check /opt/casescope/logs/install.log for details."
    exit 1
}

# Set trap to run cleanup on failure
trap cleanup_on_failure ERR

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a /opt/casescope/logs/install.log
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a /opt/casescope/logs/install.log
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a /opt/casescope/logs/install.log
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   echo "This script must be run as root (use sudo)"
   exit 1
fi

# Create directory structure FIRST (before any logging)
echo "Creating caseScope directory structure..."
mkdir -p /opt/casescope/{app,config,logs,data,rules,venv,tmp}
mkdir -p /opt/casescope/data/uploads
chmod 755 /opt/casescope
chmod 755 /opt/casescope/logs

# Initialize install log
touch /opt/casescope/logs/install.log
chmod 644 /opt/casescope/logs/install.log

# Cleanup any previous failed installations
log "Cleaning up any previous failed installations..."

# Stop any existing services
log "Stopping any existing caseScope services..."
systemctl stop casescope-web 2>/dev/null || true
systemctl stop casescope-worker 2>/dev/null || true
systemctl stop opensearch 2>/dev/null || true
systemctl disable casescope-web 2>/dev/null || true
systemctl disable casescope-worker 2>/dev/null || true
systemctl disable opensearch 2>/dev/null || true

# Remove existing service files
rm -f /etc/systemd/system/casescope-web.service 2>/dev/null || true
rm -f /etc/systemd/system/casescope-worker.service 2>/dev/null || true
rm -f /etc/systemd/system/opensearch.service 2>/dev/null || true

# Remove existing OpenSearch installation
if [ -d "/opt/opensearch" ]; then
    log "Removing existing OpenSearch installation..."
    rm -rf /opt/opensearch
fi

# Clean up temporary files
log "Cleaning up temporary files..."
rm -f /tmp/opensearch-2.11.1-linux-x64.tar.gz 2>/dev/null || true
rm -rf /tmp/opensearch-2.11.1 2>/dev/null || true
rm -f /tmp/chainsaw.zip 2>/dev/null || true
rm -f /tmp/chainsaw.tar.gz 2>/dev/null || true
rm -rf /tmp/chainsaw* 2>/dev/null || true

# Clean up any existing rule directories
if [ -d "/opt/casescope/rules/sigma-rules" ]; then
    log "Removing existing Sigma rules..."
    rm -rf /opt/casescope/rules/sigma-rules
fi

if [ -d "/opt/casescope/rules/chainsaw-rules" ]; then
    log "Removing existing Chainsaw rules..."
    rm -rf /opt/casescope/rules/chainsaw-rules
fi

rm -f /opt/casescope/rules/chainsaw 2>/dev/null || true

# Remove any existing caseScope installation (but preserve logs)
if [ -d "/opt/casescope/app" ]; then
    log "Removing existing caseScope application..."
    rm -rf /opt/casescope/app 2>/dev/null || true
fi

if [ -d "/opt/casescope/venv" ]; then
    log "Removing existing Python virtual environment..."
    rm -rf /opt/casescope/venv 2>/dev/null || true
fi

# Reload systemd to clear removed services
systemctl daemon-reload

log "Starting caseScope v7.0.94 installation..."
log "Target OS: Ubuntu 24 headless server"
log "Installation directory: /opt/casescope"

# Update system packages
log "Updating system packages..."
apt update 2>&1 | tee -a /opt/casescope/logs/install.log
if [ $? -ne 0 ]; then
    log_error "Failed to update package lists"
    exit 1
fi

apt upgrade -y 2>&1 | tee -a /opt/casescope/logs/install.log
if [ $? -ne 0 ]; then
    log_error "Failed to upgrade packages"
    exit 1
fi

# Install system dependencies
log "Installing system dependencies..."
apt install -y python3 python3-pip python3-venv python3-dev \
               build-essential curl wget git unzip \
               nginx supervisor redis-server \
               openjdk-11-jdk \
               sqlite3 libsqlite3-dev \
               libffi-dev libssl-dev \
               htop iotop \
               net-tools iproute2 \
               libxml2-dev libxslt1-dev \
               pkg-config \
               libc6-dev \
               python3-setuptools 2>&1 | tee -a /opt/casescope/logs/install.log

if [ $? -ne 0 ]; then
    log_error "Failed to install system dependencies"
    exit 1
fi

# Create casescope user
log "Creating casescope system user..."
if ! id "casescope" &>/dev/null; then
    useradd -r -d /opt/casescope -s /bin/bash casescope
    usermod -a -G adm casescope
    log "Created casescope user"
else
    log "casescope user already exists"
fi

# Set up Python virtual environment
log "Setting up Python virtual environment..."
cd /opt/casescope
python3 -m venv venv
source venv/bin/activate

# Upgrade pip in venv
log "Upgrading pip in virtual environment..."
pip install --upgrade pip 2>&1 | tee -a /opt/casescope/logs/install.log

# Install Python dependencies
log "Installing Python dependencies..."
# Note: requirements.txt will be provided by deploy script
# For now, install essential packages for system setup

pip install --upgrade pip 2>&1 | tee -a /opt/casescope/logs/install.log
pip install setuptools wheel 2>&1 | tee -a /opt/casescope/logs/install.log
if [ $? -ne 0 ]; then
    log_error "Failed to install Python dependencies"
    exit 1
fi

# Install OpenSearch
log "Installing OpenSearch..."
cd /tmp

# Clean up any existing files first
rm -f opensearch-2.11.1-linux-x64.tar.gz 2>/dev/null || true
rm -rf opensearch-2.11.1 2>/dev/null || true

# Download OpenSearch
log "Downloading OpenSearch 2.11.1..."
wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.tar.gz
if [ $? -ne 0 ]; then
    log_error "Failed to download OpenSearch"
    exit 1
fi

# Extract OpenSearch
log "Extracting OpenSearch..."
tar -xzf opensearch-2.11.1-linux-x64.tar.gz
if [ $? -ne 0 ]; then
    log_error "Failed to extract OpenSearch"
    exit 1
fi

# Move to final location
log "Installing OpenSearch to /opt/opensearch..."
if [ -d "/opt/opensearch" ]; then
    log "Removing existing OpenSearch directory..."
    rm -rf /opt/opensearch
fi

mv opensearch-2.11.1 /opt/opensearch
if [ $? -ne 0 ]; then
    log_error "Failed to move OpenSearch to /opt/opensearch"
    exit 1
fi

chown -R casescope:casescope /opt/opensearch

# Configure OpenSearch
log "Configuring OpenSearch..."

# Create data and logs directories
mkdir -p /opt/opensearch/data /opt/opensearch/logs /opt/opensearch/tmp
chown -R casescope:casescope /opt/opensearch/data /opt/opensearch/logs /opt/opensearch/tmp

# Configure OpenSearch with more conservative settings
cat > /opt/opensearch/config/opensearch.yml << 'EOF'
cluster.name: casescope-cluster
node.name: casescope-node-1
path.data: /opt/opensearch/data
path.logs: /opt/opensearch/logs
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
plugins.security.disabled: true
bootstrap.memory_lock: false
action.auto_create_index: true
cluster.routing.allocation.disk.threshold_enabled: false
EOF

# Set OpenSearch heap size based on available memory
TOTAL_MEM=$(free -m | awk 'NR==2{printf "%.0f", $2}')
if [ $TOTAL_MEM -gt 4096 ]; then
    HEAP_SIZE="2g"
elif [ $TOTAL_MEM -gt 2048 ]; then
    HEAP_SIZE="1g"
else
    HEAP_SIZE="512m"
fi

log "Setting OpenSearch heap size to $HEAP_SIZE (Total RAM: ${TOTAL_MEM}MB)"

cat > /opt/opensearch/config/jvm.options << EOF
-Xms${HEAP_SIZE}
-Xmx${HEAP_SIZE}
-XX:+UseG1GC
-XX:G1HeapRegionSize=16m
-XX:+DisableExplicitGC
-XX:+AlwaysPreTouch
-Xss1m
-Djava.awt.headless=true
-Dfile.encoding=UTF-8
-Djna.nosys=true
-Djdk.io.permissionsUseCanonicalPath=true
-Dio.netty.noUnsafe=true
-Dio.netty.noKeySetOptimization=true
-Dlog4j.shutdownHookEnabled=false
-Dlog4j2.disable.jmx=true
-Djava.locale.providers=SPI,COMPAT
-Djna.tmpdir=/opt/opensearch/tmp
EOF

# Create OpenSearch systemd service
cat > /etc/systemd/system/opensearch.service << 'EOF'
[Unit]
Description=OpenSearch
Documentation=https://opensearch.org/docs/
Wants=network-online.target
After=network-online.target
After=time-sync.target

[Service]
RuntimeDirectory=opensearch
PrivateTmp=true
Environment=OS_HOME=/opt/opensearch
Environment=OS_PATH_CONF=/opt/opensearch/config
Environment=PID_DIR=/var/run/opensearch
Environment=OS_SD_NOTIFY=true
EnvironmentFile=-/etc/default/opensearch
WorkingDirectory=/opt/opensearch
User=casescope
Group=casescope
ExecStart=/opt/opensearch/bin/opensearch
StandardOutput=journal
StandardError=inherit
LimitNOFILE=65535
LimitNPROC=4096
LimitAS=infinity
LimitFSIZE=infinity
TimeoutStopSec=0
KillSignal=SIGTERM
KillMode=process
SendSIGKILL=no
SuccessExitStatus=143
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF

# Configure system limits for OpenSearch
cat > /etc/security/limits.d/opensearch.conf << 'EOF'
casescope soft nofile 65535
casescope hard nofile 65535
casescope soft nproc 4096
casescope hard nproc 4096
casescope soft memlock unlimited
casescope hard memlock unlimited
EOF

# Set ownership
chown -R casescope:casescope /opt/casescope
chown -R casescope:casescope /opt/opensearch

# Download and setup Sigma rules
log "Setting up Sigma rules..."
cd /opt/casescope/rules

# Remove existing sigma-rules directory if it exists
if [ -d "sigma-rules" ]; then
    log "Removing existing Sigma rules directory..."
    rm -rf sigma-rules
fi

git clone https://github.com/SigmaHQ/sigma.git sigma-rules 2>&1 | tee -a /opt/casescope/logs/install.log
if [ $? -ne 0 ]; then
    log_warning "Failed to clone Sigma rules repository"
    # Create placeholder if git clone fails
    mkdir -p sigma-rules/rules
    echo "# Sigma rules placeholder" > sigma-rules/rules/placeholder.yml
fi

# Download and setup Chainsaw rules
log "Setting up Chainsaw rules..."

# Remove existing chainsaw-rules directory if it exists
if [ -d "chainsaw-rules" ]; then
    log "Removing existing Chainsaw rules directory..."
    rm -rf chainsaw-rules
fi

# Clean up any existing chainsaw files
rm -f chainsaw.zip chainsaw_* /opt/casescope/rules/chainsaw 2>/dev/null || true

# Try to download Chainsaw binary - check what's actually available
CHAINSAW_DOWNLOADED=false

# First, let's try the newer release format
log "Trying Chainsaw latest release..."
wget -O chainsaw.tar.gz "https://github.com/WithSecureLabs/chainsaw/releases/latest/download/chainsaw_x86_64-unknown-linux-gnu.tar.gz" 2>&1 | tee -a /opt/casescope/logs/install.log
if [ $? -eq 0 ] && [ -s chainsaw.tar.gz ]; then
    log "Downloaded chainsaw archive, extracting..."
    
    # Create temporary extraction directory
    TEMP_DIR=$(mktemp -d)
    cd "$TEMP_DIR"
    tar -xzf /opt/casescope/rules/chainsaw.tar.gz 2>&1 | tee -a /opt/casescope/logs/install.log
    
    if [ $? -eq 0 ]; then
        # Find the chainsaw binary
        CHAINSAW_BINARY=$(find . -name "chainsaw" -type f -executable | head -1)
        if [ -n "$CHAINSAW_BINARY" ] && [ -f "$CHAINSAW_BINARY" ]; then
            cp "$CHAINSAW_BINARY" /opt/casescope/rules/chainsaw
            chmod +x /opt/casescope/rules/chainsaw
            log "Chainsaw binary installed successfully from $CHAINSAW_BINARY"
            CHAINSAW_DOWNLOADED=true
        else
            log "Chainsaw binary not found in extracted archive"
        fi
    fi
    
    # Clean up temp directory and return to rules directory
    cd /opt/casescope/rules
    rm -rf "$TEMP_DIR"
    rm -f chainsaw.tar.gz 2>/dev/null || true
fi

# If that didn't work, try specific versions with different naming
if [ "$CHAINSAW_DOWNLOADED" = "false" ]; then
    for version in "v2.9.1" "v2.8.0" "v2.7.0"; do
        log "Trying Chainsaw version $version with tar.gz format..."
        wget -O chainsaw.tar.gz "https://github.com/WithSecureLabs/chainsaw/releases/download/$version/chainsaw_x86_64-unknown-linux-gnu.tar.gz" 2>&1 | tee -a /opt/casescope/logs/install.log
        if [ $? -eq 0 ] && [ -s chainsaw.tar.gz ]; then
            # Create temporary extraction directory
            TEMP_DIR=$(mktemp -d)
            cd "$TEMP_DIR"
            tar -xzf /opt/casescope/rules/chainsaw.tar.gz 2>&1 | tee -a /opt/casescope/logs/install.log
            
            if [ $? -eq 0 ]; then
                CHAINSAW_BINARY=$(find . -name "chainsaw" -type f -executable | head -1)
                if [ -n "$CHAINSAW_BINARY" ] && [ -f "$CHAINSAW_BINARY" ]; then
                    cp "$CHAINSAW_BINARY" /opt/casescope/rules/chainsaw
                    chmod +x /opt/casescope/rules/chainsaw
                    log "Chainsaw $version installed successfully from $CHAINSAW_BINARY"
                    CHAINSAW_DOWNLOADED=true
                fi
            fi
            
            # Clean up and return to rules directory
            cd /opt/casescope/rules
            rm -rf "$TEMP_DIR"
            
            if [ "$CHAINSAW_DOWNLOADED" = "true" ]; then
                break
            fi
        fi
        rm -f chainsaw.tar.gz 2>/dev/null || true
    done
fi

# Download Chainsaw rules repository regardless of binary success
log "Downloading Chainsaw rules repository..."
git clone https://github.com/WithSecureLabs/chainsaw.git chainsaw-rules 2>&1 | tee -a /opt/casescope/logs/install.log
if [ $? -ne 0 ]; then
    log_warning "Failed to clone Chainsaw rules repository"
    # Create placeholder for chainsaw rules
    mkdir -p chainsaw-rules/rules
    echo "# Chainsaw rules placeholder" > chainsaw-rules/rules/placeholder.yml
fi

if [ "$CHAINSAW_DOWNLOADED" = "true" ]; then
    log "Chainsaw setup completed successfully"
else
    log_warning "Failed to download Chainsaw binary - rules repository downloaded but binary not available"
fi

# Clean up any temporary files
rm -f chainsaw.zip chainsaw.tar.gz chainsaw_* 2>/dev/null || true

# Create systemd services
log "Creating systemd services..."

# Casescope web service
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
ExecStart=/opt/casescope/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 --timeout 300 app:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Casescope worker service (for background tasks)
cat > /etc/systemd/system/casescope-worker.service << 'EOF'
[Unit]
Description=caseScope Background Worker
After=network.target opensearch.service redis.service

[Service]
Type=exec
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment=PATH=/opt/casescope/venv/bin
ExecStart=/opt/casescope/venv/bin/celery -A app.celery worker --loglevel=info
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Configure Nginx
log "Configuring Nginx..."
cat > /etc/nginx/sites-available/casescope << 'EOF'
server {
    listen 80;
    server_name _;
    
    client_max_body_size 500M;
    
    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_connect_timeout 300s;
        proxy_send_timeout 300s;
        proxy_read_timeout 300s;
    }
    
    location /static {
        alias /opt/casescope/app/static;
        expires 1y;
        add_header Cache-Control "public, immutable";
    }
}
EOF

ln -sf /etc/nginx/sites-available/casescope /etc/nginx/sites-enabled/
rm -f /etc/nginx/sites-enabled/default

# Test nginx configuration
nginx -t 2>&1 | tee -a /opt/casescope/logs/install.log
if [ $? -ne 0 ]; then
    log_error "Nginx configuration test failed"
    exit 1
fi

# Enable and start services
log "Enabling and starting services..."
systemctl daemon-reload
systemctl enable redis-server
systemctl enable opensearch
systemctl enable nginx
systemctl enable casescope-web
systemctl enable casescope-worker

# Configure system limits for OpenSearch before starting
log "Configuring system for OpenSearch..."
echo 'vm.max_map_count=262144' >> /etc/sysctl.conf
sysctl -p

# Ensure Java is properly configured
log "Checking Java installation..."
if ! java -version 2>&1 | grep -q "11\|17\|21"; then
    log_warning "Java version may not be optimal for OpenSearch"
fi

# Start Redis service first
log "Starting Redis service..."
systemctl start redis-server

# Start OpenSearch service
log "Starting OpenSearch service..."
systemctl start opensearch

# Wait for OpenSearch to start with better diagnostics
log "Waiting for OpenSearch to start..."
OPENSEARCH_STARTED=false

for i in {1..60}; do
    # Check if service is running
    if systemctl is-active --quiet opensearch; then
        log "OpenSearch service is active, checking connectivity..."
        
        # Check if port is listening
        if netstat -tlnp | grep -q ":9200"; then
            log "OpenSearch port 9200 is listening, testing HTTP response..."
            
            # Test HTTP connectivity
            if curl -s -m 5 http://localhost:9200 > /dev/null 2>&1; then
                log "OpenSearch is responding to HTTP requests"
                OPENSEARCH_STARTED=true
                break
            else
                log "OpenSearch port is open but not responding to HTTP yet (attempt $i/60)..."
            fi
        else
            log "OpenSearch port 9200 not yet listening (attempt $i/60)..."
        fi
    else
        log "OpenSearch service not yet active (attempt $i/60)..."
        
        # Check for common startup issues
        if [ $i -eq 10 ]; then
            log "Checking OpenSearch logs for startup issues..."
            if [ -f /opt/opensearch/logs/opensearch.log ]; then
                tail -20 /opt/opensearch/logs/opensearch.log | tee -a /opt/casescope/logs/install.log
            fi
        fi
        
        if [ $i -eq 20 ]; then
            log "Checking system resources..."
            free -h | tee -a /opt/casescope/logs/install.log
            df -h | tee -a /opt/casescope/logs/install.log
        fi
        
        if [ $i -eq 30 ]; then
            log "Checking OpenSearch service status..."
            systemctl status opensearch --no-pager | tee -a /opt/casescope/logs/install.log
        fi
    fi
    
    sleep 2
done

if [ "$OPENSEARCH_STARTED" = "false" ]; then
    log_error "OpenSearch failed to start within 2 minutes"
    log_error "Checking final diagnostics..."
    
    # Final diagnostic information
    log "=== OpenSearch Service Status ==="
    systemctl status opensearch --no-pager | tee -a /opt/casescope/logs/install.log
    
    log "=== OpenSearch Logs ==="
    if [ -f /opt/opensearch/logs/opensearch.log ]; then
        tail -50 /opt/opensearch/logs/opensearch.log | tee -a /opt/casescope/logs/install.log
    else
        log "No OpenSearch log file found"
    fi
    
    log "=== System Resources ==="
    free -h | tee -a /opt/casescope/logs/install.log
    df -h /opt/opensearch | tee -a /opt/casescope/logs/install.log
    
    log "=== Java Version ==="
    java -version 2>&1 | tee -a /opt/casescope/logs/install.log
    
    log "=== Network Ports ==="
    netstat -tlnp | grep -E "(9200|9300)" | tee -a /opt/casescope/logs/install.log
    
    log_error "OpenSearch startup failed. Check the logs above for details."
    exit 1
else
    log "OpenSearch started successfully!"
fi

# Create application files (will be created in next steps)
log "Installation framework complete. Application files will be created next."

# Create version file
echo "7.0.94" > /opt/casescope/VERSION

# Set final permissions
chown -R casescope:casescope /opt/casescope

log "caseScope v7.0.94 installation framework completed successfully!"
log "Application files will be deployed next..."

# Check if reboot is needed
if [ -f /var/run/reboot-required ]; then
    echo ""
    echo -e "${YELLOW}System reboot is recommended to complete the installation.${NC}"
    echo -e "${YELLOW}Would you like to reboot now? (y/N):${NC}"
    read -r response
    if [[ "$response" =~ ^([yY][eE][sS]|[yY])$ ]]; then
        log "Rebooting system as requested..."
        reboot
    else
        log "Reboot postponed. Please reboot manually when convenient."
    fi
fi

echo ""
echo -e "${GREEN}Installation completed successfully!${NC}"
echo -e "${GREEN}Please run the application deployment script next.${NC}"

