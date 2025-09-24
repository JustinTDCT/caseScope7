#!/bin/bash

# caseScope v7.0.0 Installation Script
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
    rm -rf /tmp/chainsaw* 2>/dev/null || true
    
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
rm -rf /tmp/chainsaw* 2>/dev/null || true

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

log "Starting caseScope v7.0.0 installation..."
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
               net-tools 2>&1 | tee -a /opt/casescope/logs/install.log

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
cat > requirements.txt << 'EOF'
Flask==3.0.0
Flask-Login==0.6.3
Flask-WTF==1.2.1
Flask-SQLAlchemy==3.1.1
Werkzeug==3.0.1
WTForms==3.1.0
opensearch-py==2.4.2
gunicorn==21.2.0
python-evtx==0.8.1
pyyaml==6.0.1
requests==2.31.0
bcrypt==4.1.2
python-dateutil==2.8.2
psutil==5.9.8
celery==5.3.4
redis==5.0.1
xmltodict==0.13.0
elasticsearch-dsl==8.11.0
APScheduler==3.10.4
jinja2==3.1.2
markupsafe==2.1.3
EOF

pip install -r requirements.txt 2>&1 | tee -a /opt/casescope/logs/install.log
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
cat > /opt/opensearch/config/opensearch.yml << 'EOF'
cluster.name: casescope-cluster
node.name: casescope-node-1
path.data: /opt/opensearch/data
path.logs: /opt/opensearch/logs
network.host: 127.0.0.1
http.port: 9200
discovery.type: single-node
plugins.security.disabled: true
bootstrap.memory_lock: true
EOF

# Set OpenSearch heap size
cat > /opt/opensearch/config/jvm.options << 'EOF'
-Xms1g
-Xmx1g
-XX:+UseG1GC
-XX:G1HeapRegionSize=16m
-XX:+UseLargePages
-XX:+UnlockExperimentalVMOptions
-XX:+UseZGC
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
git clone https://github.com/SigmaHQ/sigma.git sigma-rules 2>&1 | tee -a /opt/casescope/logs/install.log
if [ $? -ne 0 ]; then
    log_warning "Failed to clone Sigma rules repository"
fi

# Download and setup Chainsaw rules
log "Setting up Chainsaw rules..."
# Try multiple versions of Chainsaw
CHAINSAW_DOWNLOADED=false
for version in "v2.9.1" "v2.8.0" "v2.7.0"; do
    log "Trying Chainsaw version $version..."
    wget -O chainsaw.zip "https://github.com/WithSecureLabs/chainsaw/releases/download/$version/chainsaw_all_linux.zip" 2>&1 | tee -a /opt/casescope/logs/install.log
    if [ $? -eq 0 ]; then
        unzip -q chainsaw.zip 2>&1 | tee -a /opt/casescope/logs/install.log
        # Find and move the chainsaw binary
        find . -name "*chainsaw*" -type f -executable | head -1 | while read file; do
            if [ -f "$file" ]; then
                mv "$file" /opt/casescope/rules/chainsaw
                chmod +x /opt/casescope/rules/chainsaw
            fi
        done
        if [ -f /opt/casescope/rules/chainsaw ]; then
            CHAINSAW_DOWNLOADED=true
            log "Chainsaw $version downloaded successfully"
            break
        fi
    fi
    rm -f chainsaw.zip 2>/dev/null
done

if [ "$CHAINSAW_DOWNLOADED" = "true" ] || [ -f /opt/casescope/rules/chainsaw ]; then
    # Download Chainsaw rules
    git clone https://github.com/WithSecureLabs/chainsaw.git chainsaw-rules 2>&1 | tee -a /opt/casescope/logs/install.log
    log "Chainsaw setup completed"
else
    log_warning "Failed to download Chainsaw - will continue without it"
    # Create placeholder for chainsaw rules
    mkdir -p chainsaw-rules/rules
    echo "# Chainsaw rules placeholder" > chainsaw-rules/rules/placeholder.yml
fi

# Clean up any temporary files
rm -f chainsaw.zip chainsaw_* 2>/dev/null || true

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

# Start services
systemctl start redis-server
systemctl start opensearch

# Wait for OpenSearch to start
log "Waiting for OpenSearch to start..."
sleep 30
for i in {1..30}; do
    if curl -s http://localhost:9200 > /dev/null; then
        log "OpenSearch is running"
        break
    fi
    if [ $i -eq 30 ]; then
        log_error "OpenSearch failed to start within timeout"
        exit 1
    fi
    sleep 2
done

# Create application files (will be created in next steps)
log "Installation framework complete. Application files will be created next."

# Create version file
echo "7.0.0" > /opt/casescope/VERSION

# Set final permissions
chown -R casescope:casescope /opt/casescope

log "caseScope v7.0.0 installation framework completed successfully!"
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

