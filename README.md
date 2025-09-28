# caseScope 7.1 - Digital Forensics Case Management System

**Version:** 7.1.1  
**Copyright:** (c) 2025 Justin Dube <casescope@thedubes.net>

## Overview

caseScope 7.1 is a comprehensive digital forensics case management system designed for analyzing Windows Event Logs (EVTX files) with integrated SIGMA rule processing and advanced search capabilities.

## Key Features

- **Case-Driven Architecture**: Organize investigations by cases with proper data isolation
- **Multi-Tier User Access**: Administrator, Analyst, and Read-Only user roles
- **Advanced EVTX Processing**: Parse and index Windows Event Logs with full field extraction
- **SIGMA Rule Integration**: Automated threat detection using SIGMA rules
- **Powerful Search Engine**: Boolean logic, nested queries, and forensic-grade results
- **Audit Trail**: Complete logging of all user actions and system events
- **Modern UI**: Dark blue theme with 3D tiles and responsive design

## System Requirements

- Ubuntu 24.04 LTS (recommended)
- Python 3.10+ with virtual environment support
- OpenSearch 2.11+
- Redis 6.0+
- Nginx (for production)
- Minimum 8GB RAM, 16GB recommended
- Multi-core CPU recommended for file processing

## Installation

### Quick Install
```bash
# Clone repository
git clone <repository-url>
cd caseScope7_cursor

# Run installer with menu options
sudo ./install.sh
```

### Installation Options
1. **Clean Install**: Complete fresh installation (removes all existing data)
2. **Preserve Data**: Upgrade system files while keeping user data
3. **Clear Indexes**: Keep database but clear OpenSearch indexes for re-indexing

## Default Credentials

**Username:** administrator  
**Password:** ChangeMe!

*Note: You will be required to change the password on first login.*

## Directory Structure

```
/opt/casescope/
├── app/                 # Application code
├── data/                # Database and system data
├── uploads/             # Uploaded EVTX files (organized by case ID)
├── logs/                # Application and system logs
├── rules/               # SIGMA rules repository
├── venv/                # Python virtual environment
└── config/              # Configuration files
```

## User Roles

### Administrator
- Full system access
- User management
- Case creation/deletion
- System configuration
- All analyst and read-only permissions

### Analyst
- Case creation and management
- File upload and processing
- Search and analysis
- Own account management
- Cannot delete data or manage other users

### Read-Only
- Search and view capabilities
- Case browsing
- Cannot create, modify, or delete any data

## File Processing Workflow

1. **Upload**: EVTX files uploaded to specific cases (3GB max per file)
2. **Validation**: Hash checking to prevent duplicates
3. **Parsing**: Multi-core EVTX parsing and field extraction
4. **Indexing**: OpenSearch indexing with nested field structure
5. **Rule Processing**: SIGMA rule analysis and violation tagging
6. **Search Ready**: Events available for search and analysis

## Search Capabilities

### Basic Search
- Case-insensitive text search across all fields
- Automatic pagination and result limiting

### Advanced Search
- Boolean operators: `AND`, `OR`, `NOT`
- Parenthetical grouping: `(4624 AND administrator) NOT user`
- Phrase matching: `"powershell -bypass"`
- Field-specific searches: `EventID:4624`

### Search Results
- Wazuh/TimeSketch style table layout
- Event timestamp, ID, summary, computer, violations
- Expandable event details with all fields
- Clickable fields to add to search query
- CSV export functionality

## API Endpoints

- `/api/cases` - Case management
- `/api/files` - File operations
- `/api/search` - Search interface
- `/api/users` - User management (admin only)
- `/api/audit` - Audit log access

## Logging and Debugging

- Application logs: `/opt/casescope/logs/app.log`
- System logs: `journalctl -u casescope-*`
- Debug console: Available in UI (top-left debug button)
- Audit trail: Complete user action logging

## Support

For issues, feature requests, or support:
- Email: casescope@thedubes.net
- Documentation: See `/opt/casescope/docs/`

## License

Copyright (c) 2025 Justin Dube. All rights reserved.
