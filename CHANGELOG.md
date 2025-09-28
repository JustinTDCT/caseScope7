# caseScope 7.1 - Changelog

## Version 7.1.1 (2025-09-28)

### Initial Release
- **New Architecture**: Complete rebuild from caseScope 7.0.x
- **User Management**: Three-tier access control (Administrator, Analyst, Read-Only)
- **Case-Driven Design**: Proper case isolation and organization
- **Modern UI**: Dark blue theme with 3D tiles and responsive design
- **Installation System**: Three-option installer (Clean, Upgrade, Clear Indexes)
- **Version Management**: Centralized version control system
- **Security**: Bcrypt password hashing and role-based access
- **Audit Trail**: Foundation for comprehensive activity logging

### Core Features
- Flask-based web application with SQLAlchemy ORM
- User authentication with forced password change for default admin
- Basic dashboard with system tiles
- Installation script with menu-driven options
- OpenSearch integration preparation
- Python virtual environment support for Ubuntu 24.04

### Default Credentials
- Username: `administrator`
- Password: `ChangeMe!` (must be changed on first login)

### System Requirements
- Ubuntu 24.04 LTS (recommended)
- Python 3.10+
- 8GB+ RAM recommended
- Multi-core CPU for optimal performance

### Installation
```bash
sudo ./install.sh
```

### Architecture
- **Application**: `/opt/casescope/app/`
- **Data**: `/opt/casescope/data/`
- **Uploads**: `/opt/casescope/uploads/<case_id>/`
- **Logs**: `/opt/casescope/logs/`
- **Virtual Environment**: `/opt/casescope/venv/`

### Next Release (7.2.1)
- Case management interface
- File upload system
- EVTX parsing and indexing
- Search functionality
- SIGMA rule integration
