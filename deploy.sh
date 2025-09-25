#!/bin/bash

# caseScope v7.0.94 Deployment Script
# Deploys application files after installation
# Copyright 2025 Justin Dube

set -e

# Color codes for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    echo -e "${GREEN}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" | tee -a /opt/casescope/logs/deploy.log
}

log_error() {
    echo -e "${RED}[$(date '+%Y-%m-%d %H:%M:%S')] ERROR:${NC} $1" | tee -a /opt/casescope/logs/deploy.log
}

log_warning() {
    echo -e "${YELLOW}[$(date '+%Y-%m-%d %H:%M:%S')] WARNING:${NC} $1" | tee -a /opt/casescope/logs/deploy.log
}

# Check if running as root
if [[ $EUID -ne 0 ]]; then
   log_error "This script must be run as root (use sudo)"
   exit 1
fi

# Verify installation completed
if [ ! -f /opt/casescope/logs/install.log ]; then
    log_error "Installation not found. Please run install.sh first."
    exit 1
fi

log "Starting caseScope v7.0.94 application deployment..."

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Create application directories first
log "Creating application directories..."
mkdir -p /opt/casescope/app/templates/admin
mkdir -p /opt/casescope/config
mkdir -p /opt/casescope/app/static/css
mkdir -p /opt/casescope/app/static/js
mkdir -p /opt/casescope/data/uploads

# Copy application files
log "Copying application files..."
cp "$SCRIPT_DIR/app.py" /opt/casescope/app/
cp "$SCRIPT_DIR/version.json" /opt/casescope/app/
cp "$SCRIPT_DIR/version_utils.py" /opt/casescope/app/
cp -r "$SCRIPT_DIR/templates"/* /opt/casescope/app/templates/
cp -r "$SCRIPT_DIR/static"/* /opt/casescope/app/static/

# Fix Flask app circular import issue
log "Fixing Flask app circular import..."
cd /opt/casescope/app
python3 << 'PYTHON_FIX_IMPORTS'
# Fix the circular import issue in app.py
with open('app.py', 'r') as f:
    content = f.read()

# Replace the problematic line that uses app before it's defined
old_line = "upload_dir = app.config.get('UPLOAD_FOLDER', '/opt/casescope/data/uploads')"
new_line = "upload_dir = '/opt/casescope/data/uploads'  # Default upload directory"

if old_line in content:
    content = content.replace(old_line, new_line)
    print("✓ Fixed Flask app config circular reference")

# Also fix any other early app.config references
import re
pattern = r"app\.config\.get\([^)]+\)"
matches = re.findall(pattern, content)
for match in matches:
    if "UPLOAD_FOLDER" in match:
        content = content.replace(match, "'/opt/casescope/data/uploads'")
        print(f"✓ Fixed early config reference: {match}")

with open('app.py', 'w') as f:
    f.write(content)

print("Flask app import fix completed")
PYTHON_FIX_IMPORTS

# Copy requirements.txt to the app directory
log "Copying requirements.txt..."
if [ -f "$SCRIPT_DIR/requirements.txt" ]; then
    cp "$SCRIPT_DIR/requirements.txt" /opt/casescope/app/
    log "✓ Copied requirements.txt from source"
else
    log_error "requirements.txt not found in source directory"
    exit 1
fi

# Create admin templates
log "Creating admin templates..."

# Admin cases template
cat > /opt/casescope/app/templates/admin/cases.html << 'EOF'
{% extends "base.html" %}

{% block title %}Case Management - caseScope{% endblock %}

{% block content %}
<div class="admin-container">
    <div class="page-header">
        <h1>Case Management</h1>
        <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">
            <i class="fas fa-arrow-left"></i>
            Back to Dashboard
        </a>
    </div>

    <div class="card">
        <div class="card-header">
            <h3 class="card-title">
                <i class="fas fa-folder"></i>
                All Cases
            </h3>
        </div>
        <div class="card-content">
            {% if cases %}
            <div class="table-container">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Case Name</th>
                            <th>Created</th>
                            <th>Creator</th>
                            <th>Files</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for case in cases %}
                        <tr>
                            <td>
                                <div class="case-name">{{ case.name }}</div>
                                {% if case.description %}
                                <div class="case-description">{{ case.description[:100] }}...</div>
                                {% endif %}
                            </td>
                            <td>{{ case.created_at.strftime('%Y-%m-%d') }}</td>
                            <td>{{ case.creator.username }}</td>
                            <td>{{ case.files.count() }}</td>
                            <td>
                                <span class="badge badge-{{ 'success' if case.is_active else 'secondary' }}">
                                    {{ 'Active' if case.is_active else 'Inactive' }}
                                </span>
                            </td>
                            <td>
                                <div class="action-buttons">
                                    <a href="{{ url_for('select_case', case_id=case.id) }}" class="btn btn-sm btn-primary">
                                        <i class="fas fa-eye"></i>
                                        View
                                    </a>
                                    <button class="btn btn-sm btn-danger" onclick="deleteCase({{ case.id }})">
                                        <i class="fas fa-trash"></i>
                                        Delete
                                    </button>
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="empty-state">
                <i class="fas fa-folder-plus"></i>
                <h4>No Cases Found</h4>
                <p>No cases have been created yet.</p>
            </div>
            {% endif %}
        </div>
    </div>
</div>

<script>
function deleteCase(caseId) {
    if (confirm('Are you sure you want to delete this case? This will permanently remove all associated files and data.')) {
        fetch(`/api/admin/case/${caseId}`, { method: 'DELETE' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', 'Case deleted successfully.');
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    showAlert('error', 'Failed to delete case: ' + data.error);
                }
            })
            .catch(error => {
                showAlert('error', 'Error deleting case: ' + error.message);
            });
    }
}
</script>
{% endblock %}
EOF

# Admin users template
cat > /opt/casescope/app/templates/admin/users.html << 'EOF'
{% extends "base.html" %}

{% block title %}User Management - caseScope{% endblock %}

{% block content %}
<div class="admin-container">
    <div class="page-header">
        <h1>User Management</h1>
        <div class="header-actions">
            <a href="{{ url_for('admin_create_user') }}" class="btn btn-primary">
                <i class="fas fa-plus"></i>
                Create User
            </a>
            <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">
                <i class="fas fa-arrow-left"></i>
                Back to Dashboard
            </a>
        </div>
    </div>

    <div class="card">
        <div class="card-header">
            <h3 class="card-title">
                <i class="fas fa-users"></i>
                All Users
            </h3>
        </div>
        <div class="card-content">
            {% if users %}
            <div class="table-container">
                <table class="table">
                    <thead>
                        <tr>
                            <th>Username</th>
                            <th>Email</th>
                            <th>Role</th>
                            <th>Created</th>
                            <th>Last Login</th>
                            <th>Status</th>
                            <th>Actions</th>
                        </tr>
                    </thead>
                    <tbody>
                        {% for user in users %}
                        <tr>
                            <td>{{ user.username }}</td>
                            <td>{{ user.email }}</td>
                            <td>
                                <span class="badge badge-{{ 'danger' if user.role == 'admin' else 'primary' if user.role == 'analyst' else 'secondary' }}">
                                    {{ user.role.title() }}
                                </span>
                            </td>
                            <td>{{ user.created_at.strftime('%Y-%m-%d') }}</td>
                            <td>
                                {% if user.last_login %}
                                    {{ user.last_login.strftime('%Y-%m-%d %H:%M') }}
                                {% else %}
                                    Never
                                {% endif %}
                            </td>
                            <td>
                                <span class="badge badge-{{ 'success' if user.is_active else 'secondary' }}">
                                    {{ 'Active' if user.is_active else 'Inactive' }}
                                </span>
                            </td>
                            <td>
                                <div class="action-buttons">
                                    {% if user.id != current_user.id %}
                                    <button class="btn btn-sm btn-warning" onclick="resetPassword({{ user.id }})">
                                        <i class="fas fa-key"></i>
                                        Reset Password
                                    </button>
                                    <button class="btn btn-sm btn-danger" onclick="deleteUser({{ user.id }})">
                                        <i class="fas fa-trash"></i>
                                        Delete
                                    </button>
                                    {% else %}
                                    <span class="text-muted">Current User</span>
                                    {% endif %}
                                </div>
                            </td>
                        </tr>
                        {% endfor %}
                    </tbody>
                </table>
            </div>
            {% else %}
            <div class="empty-state">
                <i class="fas fa-user-plus"></i>
                <h4>No Users Found</h4>
                <p>No additional users have been created yet.</p>
            </div>
            {% endif %}
        </div>
    </div>
</div>

<script>
function resetPassword(userId) {
    const newPassword = prompt('Enter new password for user:');
    if (newPassword && newPassword.length >= 6) {
        fetch(`/api/admin/user/${userId}/reset-password`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ password: newPassword })
        })
        .then(response => response.json())
        .then(data => {
            if (data.success) {
                showAlert('success', 'Password reset successfully.');
            } else {
                showAlert('error', 'Failed to reset password: ' + data.error);
            }
        })
        .catch(error => {
            showAlert('error', 'Error resetting password: ' + error.message);
        });
    } else if (newPassword !== null) {
        showAlert('error', 'Password must be at least 6 characters long.');
    }
}

function deleteUser(userId) {
    if (confirm('Are you sure you want to delete this user? This action cannot be undone.')) {
        fetch(`/api/admin/user/${userId}`, { method: 'DELETE' })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    showAlert('success', 'User deleted successfully.');
                    setTimeout(() => window.location.reload(), 1000);
                } else {
                    showAlert('error', 'Failed to delete user: ' + data.error);
                }
            })
            .catch(error => {
                showAlert('error', 'Error deleting user: ' + error.message);
            });
    }
}
</script>
{% endblock %}
EOF

# Create user form template
cat > /opt/casescope/app/templates/admin/create_user.html << 'EOF'
{% extends "base.html" %}

{% block title %}Create User - caseScope{% endblock %}

{% block content %}
<div class="admin-container">
    <div class="page-header">
        <h1>Create New User</h1>
        <a href="{{ url_for('admin_users') }}" class="btn btn-secondary">
            <i class="fas fa-arrow-left"></i>
            Back to Users
        </a>
    </div>

    <div class="form-container">
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">
                    <i class="fas fa-user-plus"></i>
                    User Information
                </h3>
            </div>
            <div class="card-content">
                <form method="POST" class="user-form">
                    {{ form.hidden_tag() }}
                    
                    <div class="form-group">
                        {{ form.username.label(class="form-label") }}
                        {{ form.username(class="form-input", placeholder="Enter username") }}
                        {% if form.username.errors %}
                            <div class="form-error">
                                {% for error in form.username.errors %}
                                    <span>{{ error }}</span>
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="form-group">
                        {{ form.email.label(class="form-label") }}
                        {{ form.email(class="form-input", placeholder="Enter email address") }}
                        {% if form.email.errors %}
                            <div class="form-error">
                                {% for error in form.email.errors %}
                                    <span>{{ error }}</span>
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="form-group">
                        {{ form.password.label(class="form-label") }}
                        {{ form.password(class="form-input", placeholder="Enter password (minimum 6 characters)") }}
                        {% if form.password.errors %}
                            <div class="form-error">
                                {% for error in form.password.errors %}
                                    <span>{{ error }}</span>
                                {% endfor %}
                            </div>
                        {% endif %}
                    </div>
                    
                    <div class="form-group">
                        {{ form.role.label(class="form-label") }}
                        {{ form.role(class="form-select") }}
                        {% if form.role.errors %}
                            <div class="form-error">
                                {% for error in form.role.errors %}
                                    <span>{{ error }}</span>
                                {% endfor %}
                            </div>
                        {% endif %}
                        <div class="form-help">
                            <strong>Administrator:</strong> Full system access<br>
                            <strong>Analyst:</strong> Can create cases and upload files<br>
                            <strong>Read Only:</strong> Can only view and search data
                        </div>
                    </div>
                    
                    <div class="form-actions">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-plus"></i>
                            Create User
                        </button>
                        <a href="{{ url_for('admin_users') }}" class="btn btn-secondary">
                            <i class="fas fa-times"></i>
                            Cancel
                        </a>
                    </div>
                </form>
            </div>
        </div>
    </div>
</div>
{% endblock %}
EOF

# Create diagnostics template
cat > /opt/casescope/app/templates/admin/diagnostics.html << 'EOF'
{% extends "base.html" %}

{% block title %}System Diagnostics - caseScope{% endblock %}

{% block content %}
<div class="admin-container">
    <div class="page-header">
        <h1>System Diagnostics</h1>
        <div class="header-actions">
            <button class="btn btn-primary" onclick="runDiagnostics()">
                <i class="fas fa-play"></i>
                Run Diagnostics
            </button>
            <button class="btn btn-warning" onclick="toggleDebugConsole()">
                <i class="fas fa-bug"></i>
                Toggle Debug Console
            </button>
            <a href="{{ url_for('dashboard') }}" class="btn btn-secondary">
                <i class="fas fa-arrow-left"></i>
                Back to Dashboard
            </a>
        </div>
    </div>

    <div class="diagnostics-grid">
        <div class="card">
            <div class="card-header">
                <h3 class="card-title">
                    <i class="fas fa-heartbeat"></i>
                    System Health Check
                </h3>
            </div>
            <div class="card-content">
                <div id="health-check-results">
                    <p class="text-center text-secondary">Click "Run Diagnostics" to perform health check</p>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 class="card-title">
                    <i class="fas fa-chart-line"></i>
                    Performance Metrics
                </h3>
            </div>
            <div class="card-content">
                <div id="performance-metrics">
                    <div class="metric-item">
                        <label>CPU Usage:</label>
                        <span id="cpu-usage">--</span>
                    </div>
                    <div class="metric-item">
                        <label>Memory Usage:</label>
                        <span id="memory-usage">--</span>
                    </div>
                    <div class="metric-item">
                        <label>Disk Usage:</label>
                        <span id="disk-usage">--</span>
                    </div>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 class="card-title">
                    <i class="fas fa-cogs"></i>
                    Service Status
                </h3>
            </div>
            <div class="card-content">
                <div id="service-status">
                    <p class="text-center text-secondary">Service status will appear here</p>
                </div>
            </div>
        </div>

        <div class="card">
            <div class="card-header">
                <h3 class="card-title">
                    <i class="fas fa-database"></i>
                    OpenSearch Health
                </h3>
            </div>
            <div class="card-content">
                <div id="opensearch-health">
                    <p class="text-center text-secondary">OpenSearch health will appear here</p>
                </div>
            </div>
        </div>
    </div>
</div>

<script>
function runDiagnostics() {
    showAlert('info', 'Running system diagnostics...');
    
    fetch('/api/admin/diagnostics', { method: 'POST' })
        .then(response => response.json())
        .then(data => {
            updateDiagnosticsResults(data);
            showAlert('success', 'Diagnostics completed.');
        })
        .catch(error => {
            showAlert('error', 'Error running diagnostics: ' + error.message);
        });
}

function updateDiagnosticsResults(data) {
    // Update health check results
    const healthResults = document.getElementById('health-check-results');
    healthResults.innerHTML = data.health_check || 'No health check data available';
    
    // Update performance metrics
    document.getElementById('cpu-usage').textContent = data.cpu_usage || '--';
    document.getElementById('memory-usage').textContent = data.memory_usage || '--';
    document.getElementById('disk-usage').textContent = data.disk_usage || '--';
    
    // Update service status
    const serviceStatus = document.getElementById('service-status');
    serviceStatus.innerHTML = data.service_status || 'No service status data available';
    
    // Update OpenSearch health
    const opensearchHealth = document.getElementById('opensearch-health');
    opensearchHealth.innerHTML = data.opensearch_health || 'No OpenSearch health data available';
}

// Auto-refresh diagnostics every 30 seconds
setInterval(() => {
    if (document.visibilityState === 'visible') {
        runDiagnostics();
    }
}, 30000);

// Run initial diagnostics
document.addEventListener('DOMContentLoaded', runDiagnostics);
</script>

<style>
.diagnostics-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
    gap: 1.5rem;
}

.metric-item {
    display: flex;
    justify-content: space-between;
    align-items: center;
    padding: 0.75rem;
    background: var(--bg-secondary);
    border-radius: 8px;
    margin-bottom: 0.5rem;
}

.metric-item label {
    font-weight: 600;
    color: var(--text-primary);
}

.metric-item span {
    color: var(--text-secondary);
    font-family: 'Courier New', monospace;
}
</style>
{% endblock %}
EOF

# Create WSGI entry point
log "Creating WSGI entry point..."
cat > /opt/casescope/app/wsgi.py << 'EOF'
#!/usr/bin/env python3
"""
WSGI entry point for caseScope
"""

import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, '/opt/casescope/app')

from app import app

if __name__ == "__main__":
    app.run()
EOF

# Create Celery worker entry point
log "Creating Celery worker entry point..."
cat > /opt/casescope/app/celery_worker.py << 'EOF'
#!/usr/bin/env python3
"""
Celery worker entry point for caseScope
"""

import sys
import os

# Add the app directory to the Python path
sys.path.insert(0, '/opt/casescope/app')

from app import celery, app

if __name__ == '__main__':
    with app.app_context():
        celery.start()
EOF

# Create configuration file
log "Creating configuration file..."
cat > /opt/casescope/config/casescope.conf << 'EOF'
# caseScope Configuration File

[database]
url = sqlite:////opt/casescope/data/casescope.db

[opensearch]
host = localhost
port = 9200
timeout = 30

[redis]
host = localhost
port = 6379
db = 0

[upload]
max_file_size = 524288000
upload_folder = /opt/casescope/data/uploads
allowed_extensions = evtx

[rules]
sigma_path = /opt/casescope/rules/sigma-rules
chainsaw_path = /opt/casescope/rules/chainsaw-rules
update_interval = 86400

[logging]
level = INFO
log_folder = /opt/casescope/logs

[security]
session_timeout = 3600
max_login_attempts = 5
EOF

# Create and set up log files
log "Creating log files with proper permissions..."
mkdir -p /opt/casescope/logs
touch /opt/casescope/logs/application.log
touch /opt/casescope/logs/error.log
touch /opt/casescope/logs/access.log
touch /opt/casescope/logs/celery.log
chown -R casescope:casescope /opt/casescope/logs
chmod 755 /opt/casescope/logs
chmod 664 /opt/casescope/logs/*.log

# Set permissions
log "Setting file permissions..."
chown -R casescope:casescope /opt/casescope/app
chown -R casescope:casescope /opt/casescope/data
chown -R casescope:casescope /opt/casescope/config
chmod +x /opt/casescope/app/wsgi.py
chmod +x /opt/casescope/app/celery_worker.py

# Install Python dependencies in virtual environment
log "Installing Python dependencies..."
cd /opt/casescope
source venv/bin/activate
pip install -r app/requirements.txt 2>&1 | tee -a /opt/casescope/logs/deploy.log

if [ $? -ne 0 ]; then
    log_error "Failed to install Python dependencies"
    exit 1
fi

# Initialize database (using the virtual environment)
log "Initializing database..."
cd /opt/casescope/app

# Test imports first
log "Testing Python imports..."
/opt/casescope/venv/bin/python3 -c "
import sys
sys.path.insert(0, '/opt/casescope/app')
try:
    import bcrypt
    print('✓ bcrypt imported successfully')
    import flask
    print('✓ flask imported successfully')
    import flask_sqlalchemy
    print('✓ flask_sqlalchemy imported successfully')
    print('All critical imports successful')
except Exception as e:
    print(f'✗ Import failed: {e}')
    raise
" 2>&1 | tee -a /opt/casescope/logs/deploy.log

if [ $? -ne 0 ]; then
    log_error "Failed import test - check requirements.txt"
    exit 1
fi

# Now initialize database
log "Creating database tables..."
/opt/casescope/venv/bin/python3 -c "
import sys
sys.path.insert(0, '/opt/casescope/app')
try:
    from app import db, app as flask_app, User
    with flask_app.app_context():
        # Create all database tables
        db.create_all()
        
        # Create default admin user if it doesn't exist
        admin_user = User.query.filter_by(username='Admin').first()
        if not admin_user:
            from werkzeug.security import generate_password_hash
            admin_user = User(
                username='Admin',
                email='admin@casescope.local',
                password_hash=generate_password_hash('ChangeMe!'),
                role='administrator'
            )
            db.session.add(admin_user)
            db.session.commit()
            print('✓ Created default admin user: Admin / ChangeMe!')
        else:
            print('✓ Admin user already exists')
        
        print('✓ Database initialized successfully')
        print(f'✓ Database location: /opt/casescope/data/casescope.db')
        
except Exception as e:
    print(f'✗ Database initialization failed: {e}')
    import traceback
    traceback.print_exc()
    raise
" 2>&1 | tee -a /opt/casescope/logs/deploy.log

if [ $? -ne 0 ]; then
    log_error "Failed to initialize database"
    exit 1
fi

# Run database migration
log "Running database migration..."
/opt/casescope/venv/bin/python3 "$SCRIPT_DIR/migrate_db.py" 2>&1 | tee -a /opt/casescope/logs/deploy.log

if [ $? -ne 0 ]; then
    log_error "Database migration failed"
    exit 1
fi

# Fix database permissions specifically
log "Setting database permissions..."
if [ -f /opt/casescope/data/casescope.db ]; then
    chown casescope:casescope /opt/casescope/data/casescope.db
    chmod 664 /opt/casescope/data/casescope.db
    log "Database file permissions set"
fi

# Ensure the data directory is writable
chown -R casescope:casescope /opt/casescope/data
chmod 755 /opt/casescope/data
log "Data directory permissions verified"

# Update systemd service files to use correct paths
log "Updating systemd service files..."
cat > /etc/systemd/system/casescope-web.service << 'EOF'
[Unit]
Description=caseScope Web Application
After=network.target opensearch.service redis.service

[Service]
Type=exec
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment=PATH=/opt/casescope/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONPATH=/opt/casescope/app
ExecStart=/opt/casescope/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 4 --timeout 300 --access-logfile /opt/casescope/logs/access.log --error-logfile /opt/casescope/logs/error.log wsgi:app
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

cat > /etc/systemd/system/casescope-worker.service << 'EOF'
[Unit]
Description=caseScope Background Worker
After=network.target opensearch.service redis.service

[Service]
Type=exec
User=casescope
Group=casescope
WorkingDirectory=/opt/casescope/app
Environment=PATH=/opt/casescope/venv/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
Environment=PYTHONPATH=/opt/casescope/app
ExecStart=/opt/casescope/venv/bin/celery -A app.celery worker --loglevel=info --logfile=/opt/casescope/logs/celery.log
Restart=always
RestartSec=3

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start services
log "Enabling and starting services..."
systemctl daemon-reload

# Enable services to start on boot
systemctl enable opensearch
systemctl enable nginx
systemctl enable casescope-web
systemctl enable casescope-worker

# Start services
systemctl restart opensearch
systemctl restart nginx
systemctl start casescope-web
systemctl start casescope-worker

# Wait a moment for services to start
sleep 5

# Copy utility scripts
log "Installing utility scripts..."
if [ -f "$SCRIPT_DIR/nightly_update.sh" ]; then
    cp "$SCRIPT_DIR/nightly_update.sh" /opt/casescope/
    chmod +x /opt/casescope/nightly_update.sh
    chown casescope:casescope /opt/casescope/nightly_update.sh
    
    # Add cron job for nightly updates
    (crontab -u casescope -l 2>/dev/null; echo "0 2 * * * /opt/casescope/nightly_update.sh >> /opt/casescope/logs/nightly_update.log 2>&1") | crontab -u casescope -
    log "Nightly updates scheduled for 2:00 AM daily"
else
    log_warning "nightly_update.sh not found - nightly updates not configured"
fi

if [ -f "$SCRIPT_DIR/bugfixes.sh" ]; then
    cp "$SCRIPT_DIR/bugfixes.sh" /opt/casescope/
    chmod +x /opt/casescope/bugfixes.sh
    chown casescope:casescope /opt/casescope/bugfixes.sh
    log "Bug fixes script installed"
fi

# Check service status
log "Checking service status..."
if systemctl is-active --quiet casescope-web; then
    log "caseScope web service started successfully"
else
    log_error "caseScope web service failed to start"
    systemctl status casescope-web --no-pager
fi

if systemctl is-active --quiet casescope-worker; then
    log "caseScope worker service started successfully"
else
    log_warning "caseScope worker service failed to start"
    systemctl status casescope-worker --no-pager
fi

# Create daily rule update cron job
log "Creating daily rule update cron job..."
cat > /etc/cron.d/casescope-rules << 'EOF'
# Update Sigma and Chainsaw rules daily at 2 AM
0 2 * * * casescope /opt/casescope/venv/bin/python3 -c "
import sys
sys.path.insert(0, '/opt/casescope/app')
from app import app, update_rules
with app.app_context():
    update_rules()
" >> /opt/casescope/logs/rules-update.log 2>&1
EOF

# Create log rotation
log "Setting up log rotation..."
cat > /etc/logrotate.d/casescope << 'EOF'
/opt/casescope/logs/*.log {
    daily
    missingok
    rotate 30
    compress
    delaycompress
    notifempty
    sharedscripts
    postrotate
        systemctl reload casescope-web casescope-worker || true
    endscript
}
EOF

# Final setup verification
log "Performing final verification..."
if curl -s http://localhost:5000 > /dev/null; then
    log "Web application is responding correctly"
else
    log_error "Web application is not responding"
fi

if systemctl is-active --quiet opensearch; then
    log "OpenSearch is running"
else
    log_error "OpenSearch is not running"
fi

if systemctl is-active --quiet redis-server; then
    log "Redis is running"
else
    log_error "Redis is not running"
fi

if systemctl is-active --quiet nginx; then
    log "Nginx is running"
else
    log_error "Nginx is not running"
fi

log "caseScope v7.0.94 deployment completed successfully!"
echo ""
echo -e "${GREEN}=== Deployment Summary ===${NC}"
echo -e "${GREEN}Web Interface:${NC} http://$(hostname -I | awk '{print $1}')"
echo -e "${GREEN}Default Login:${NC} Admin / ChangeMe!"
echo -e "${GREEN}Log Files:${NC} /opt/casescope/logs/"
echo -e "${GREEN}Data Directory:${NC} /opt/casescope/data/"
echo -e "${GREEN}Configuration:${NC} /opt/casescope/config/"
echo -e "${GREEN}Utility Scripts:${NC} /opt/casescope/"
echo ""
echo -e "${GREEN}=== Features Included ===${NC}"
echo "- Enhanced file processing with detailed status tracking"
echo "- Robust error handling and data sanitization"
echo "- Search functionality with JSON parsing protection"
echo "- Automatic nightly updates for Sigma/Chainsaw rules"
echo "- Complete OpenSearch index management"
echo "- Improved UI with better alignment and status display"
echo ""
echo -e "${YELLOW}IMPORTANT:${NC} Change the default admin password immediately after first login!"
echo -e "${YELLOW}NOTE:${NC} The system is now ready for use with enhanced stability and features."
echo ""
echo -e "${BLUE}Monitoring Commands:${NC}"
echo "  sudo systemctl status casescope-web casescope-worker"
echo "  tail -f /opt/casescope/logs/application.log"
echo "  curl http://localhost:9200/_cluster/health"
echo "  journalctl -u casescope-worker -f"
echo ""
echo -e "${BLUE}Available Scripts:${NC}"
echo "  /opt/casescope/bugfixes.sh - Apply latest bug fixes"
echo "  /opt/casescope/nightly_update.sh - Manual rule updates"

