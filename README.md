# caseScope v7.0.0

**Advanced EVTX Analysis Platform for Digital Forensics and Incident Response**

caseScope is a comprehensive web-based platform designed for analyzing Windows Event Log (EVTX) files in digital forensics and incident response scenarios. Built for security professionals, it provides case-based organization, automated rule analysis, and powerful search capabilities.

## 🚀 Features

### Core Functionality
- **Case-Based Organization**: All files and analysis are organized by case for better workflow management
- **EVTX File Processing**: Native support for Windows Event Log files with automatic parsing
- **Real-Time Analysis**: Automatic application of Sigma and Chainsaw rules during file ingestion
- **Advanced Search**: TimeSKetch-style search interface with OpenSearch backend
- **Rule Violations**: Automatic detection and color-coding of security events by severity
- **Duplicate Detection**: Intelligent deduplication of identical events
- **Multi-User Support**: Role-based access control (Administrator, Analyst, Read-Only)

### Technical Features
- **Native Installation**: Runs directly on Ubuntu 24 without Docker containers
- **OpenSearch Integration**: Powerful full-text search and indexing
- **Background Processing**: Asynchronous file processing with Celery
- **Audit Logging**: Comprehensive logging of all user actions and system events
- **Dark/Light Themes**: Modern responsive UI with theme switching
- **Real-Time Updates**: Live status updates for file processing
- **Export Capabilities**: Export search results and analysis data

### Security & Compliance
- **Comprehensive Audit Trail**: Three-tier logging (Logins, Audit, Admin)
- **IP Agnostic**: Can be installed on any IP address and accessed from anywhere
- **Session Management**: Secure user authentication and session handling
- **Role-Based Access**: Granular permission control
- **Data Integrity**: SHA256 file hashing and integrity verification

## 📋 Requirements

### System Requirements
- **Operating System**: Ubuntu 24 LTS (headless server)
- **Memory**: Minimum 8GB RAM (16GB+ recommended)
- **Storage**: Minimum 100GB free space
- **Network**: Internet access for initial setup and rule updates

### Supported File Types
- Windows Event Log files (.evtx)
- Maximum file size: 500MB per file
- Batch upload: Up to 5 files simultaneously

## 🛠️ Installation

### Quick Installation

1. **Download caseScope**:
   ```bash
   git clone https://github.com/your-repo/casescope.git
   cd casescope
   ```

2. **Run Installation Script** (as root):
   ```bash
   sudo chmod +x install.sh
   sudo ./install.sh
   ```

3. **Deploy Application**:
   ```bash
   sudo chmod +x deploy.sh
   sudo ./deploy.sh
   ```

4. **Access the Application**:
   - Open your web browser
   - Navigate to `http://your-server-ip`
   - Login with default credentials: `Admin` / `ChangeMe!`
   - **IMPORTANT**: Change the default password immediately!

### Manual Installation Steps

If you prefer to install manually or need to troubleshoot:

1. **System Updates**:
   ```bash
   sudo apt update && sudo apt upgrade -y
   ```

2. **Install Dependencies**:
   ```bash
   sudo apt install -y python3 python3-pip python3-venv python3-dev \
                      build-essential curl wget git unzip \
                      nginx supervisor redis-server openjdk-11-jdk
   ```

3. **Create System User**:
   ```bash
   sudo useradd -r -d /opt/casescope -s /bin/bash casescope
   ```

4. **Setup Directory Structure**:
   ```bash
   sudo mkdir -p /opt/casescope/{app,config,logs,data,rules,venv,tmp}
   sudo chown -R casescope:casescope /opt/casescope
   ```

5. **Install OpenSearch**:
   ```bash
   wget https://artifacts.opensearch.org/releases/bundle/opensearch/2.11.1/opensearch-2.11.1-linux-x64.tar.gz
   sudo tar -xzf opensearch-2.11.1-linux-x64.tar.gz -C /opt/
   sudo mv /opt/opensearch-2.11.1 /opt/opensearch
   sudo chown -R casescope:casescope /opt/opensearch
   ```

6. **Setup Python Environment**:
   ```bash
   cd /opt/casescope
   sudo -u casescope python3 -m venv venv
   sudo -u casescope venv/bin/pip install -r requirements.txt
   ```

## 🏗️ Architecture

### System Components
- **Web Application**: Flask-based web interface
- **Database**: SQLite for metadata storage
- **Search Engine**: OpenSearch for event indexing and search
- **Task Queue**: Celery with Redis for background processing
- **Web Server**: Nginx as reverse proxy
- **Rule Engines**: Sigma and Chainsaw for threat detection

### File Processing Workflow
1. User uploads EVTX file(s) to a case
2. Files are validated and stored securely
3. Background worker parses EVTX content
4. Events are indexed in OpenSearch
5. Sigma and Chainsaw rules are applied
6. Violations are tagged and color-coded
7. Results are available for search and analysis

### Directory Structure
```
/opt/casescope/
├── app/                 # Web application code
├── config/              # Configuration files
├── data/                # Database and uploaded files
├── logs/                # Application logs
├── rules/               # Sigma and Chainsaw rules
├── venv/                # Python virtual environment
└── tmp/                 # Temporary files
```

## 📚 User Guide

### Getting Started

1. **Create Your First Case**:
   - Click "Cases" in the sidebar
   - Select "Create New Case"
   - Provide a descriptive name and optional description
   - Click "Create Case"

2. **Upload EVTX Files**:
   - Select your case from the dashboard
   - Click "Upload Files" in the sidebar
   - Drag and drop EVTX files or click to browse
   - Monitor upload progress in real-time

3. **Monitor Processing**:
   - Go to "List Files" to see processing status
   - Files progress through: Pending → Processing → Completed
   - Processing includes parsing, indexing, and rule analysis

4. **Search Events**:
   - Click "Event Search" in the sidebar
   - Use the search interface to query events
   - Apply filters for time range, severity, rule violations
   - View detailed event information

### Search Syntax

caseScope supports powerful search queries:

- **Basic text search**: `powershell`
- **Field-specific search**: `EventID:4624`
- **Wildcard search**: `process:*.exe`
- **Boolean operators**: `user:admin AND EventID:4625`
- **Range queries**: `EventID:[4624 TO 4634]`
- **Phrase search**: `"failed logon attempt"`

### User Roles

- **Administrator**: Full system access, user management, case deletion
- **Analyst**: Can create cases, upload files, perform analysis
- **Read Only**: Can view cases, search events, but cannot modify data

## ⚙️ Configuration

### Main Configuration File
Location: `/opt/casescope/config/casescope.conf`

Key settings:
- Database connection
- OpenSearch configuration
- File upload limits
- Rule update intervals
- Security settings

### Service Management

Start/stop services:
```bash
sudo systemctl start casescope-web
sudo systemctl start casescope-worker
sudo systemctl start opensearch
sudo systemctl start redis-server
sudo systemctl start nginx
```

Check service status:
```bash
sudo systemctl status casescope-web
sudo systemctl status casescope-worker
```

View logs:
```bash
sudo tail -f /opt/casescope/logs/app.log
sudo journalctl -f -u casescope-web
```

## 🔧 Maintenance

### Regular Tasks

1. **Update Rules** (automated daily at 2 AM):
   ```bash
   # Manual update
   sudo -u casescope /opt/casescope/venv/bin/python3 -c "
   import sys; sys.path.insert(0, '/opt/casescope/app')
   from app import app, update_rules
   with app.app_context(): update_rules()
   "
   ```

2. **Monitor Disk Space**:
   ```bash
   df -h /opt/casescope
   ```

3. **Review Logs**:
   ```bash
   sudo tail -100 /opt/casescope/logs/audit.log
   ```

4. **Backup Database**:
   ```bash
   sudo cp /opt/casescope/data/casescope.db /backup/casescope-$(date +%Y%m%d).db
   ```

### Log Files
- `app.log`: Application events
- `audit.log`: User actions and data changes
- `logins.log`: Authentication events
- `admin.log`: Administrative actions
- `install.log`: Installation events
- `deploy.log`: Deployment events

## 🚨 Troubleshooting

### Common Issues

1. **Web Interface Not Accessible**:
   ```bash
   sudo systemctl status nginx casescope-web
   sudo netstat -tlnp | grep :80
   ```

2. **File Processing Stuck**:
   ```bash
   sudo systemctl restart casescope-worker
   sudo tail -f /opt/casescope/logs/app.log
   ```

3. **OpenSearch Issues**:
   ```bash
   sudo systemctl status opensearch
   curl http://localhost:9200/_cluster/health
   ```

4. **Permission Errors**:
   ```bash
   sudo chown -R casescope:casescope /opt/casescope
   ```

### Debug Mode

Enable debug console from the Diagnostics page (Admin only) for real-time troubleshooting.

### Log Analysis

Check specific log files:
```bash
# Application errors
sudo grep -i error /opt/casescope/logs/app.log

# Failed logins
sudo grep -i failed /opt/casescope/logs/logins.log

# System events
sudo journalctl -u casescope-web -n 100
```

## 🔐 Security Considerations

### Best Practices

1. **Change Default Password**: Immediately change the default admin password
2. **Regular Updates**: Keep the system and rules updated
3. **Access Control**: Use appropriate user roles and permissions
4. **Network Security**: Consider firewall rules and VPN access
5. **Backup Strategy**: Regular backups of database and configuration
6. **Log Monitoring**: Regular review of audit logs
7. **SSL/TLS**: Consider implementing SSL certificates for production

### Hardening

1. **Firewall Configuration**:
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 22/tcp
   sudo ufw enable
   ```

2. **SSL Certificate** (optional):
   - Configure nginx with SSL certificate
   - Update configuration for HTTPS

## 📊 Performance Tuning

### For Large Deployments

1. **Increase Worker Processes**:
   Edit `/etc/systemd/system/casescope-web.service`:
   ```
   ExecStart=/opt/casescope/venv/bin/gunicorn --bind 127.0.0.1:5000 --workers 8 --timeout 300 wsgi:app
   ```

2. **OpenSearch Memory**:
   Edit `/opt/opensearch/config/jvm.options`:
   ```
   -Xms4g
   -Xmx4g
   ```

3. **Database Optimization**:
   - Consider PostgreSQL for larger deployments
   - Regular database maintenance

## 🤝 Support

### Getting Help

- Review this documentation
- Check the troubleshooting section
- Examine log files for error messages
- Verify system requirements and configuration

### Reporting Issues

When reporting issues, please include:
- caseScope version
- Operating system details
- Error messages from logs
- Steps to reproduce the issue
- System resource usage

## 📄 License

Copyright 2025 Justin Dube  
Email: casescope@thedubes.net

This software is provided for evaluation and educational purposes. Please review the license terms before use.

## 🎯 Version Information

**Current Version**: 7.0.0

### Version History
- v7.0.0: Initial release with full EVTX analysis capabilities
- Future versions will follow semantic versioning:
  - Major.Minor.Patch
  - Major: Breaking changes requiring migration
  - Minor: New features, backward compatible
  - Patch: Bug fixes and minor improvements

### Upgrade Notes
This is the initial release. Future upgrade procedures will be documented here.

---

**caseScope v7.0.0** - Advanced EVTX Analysis Platform  
Built with ❤️ for the cybersecurity community

