# caseScope 7.4 - Digital Forensics EVTX Analysis Platform

**Version:** 7.4.0  
**Copyright:** (c) 2025 Justin Dube <casescope@thedubes.net>

## Overview

caseScope is a comprehensive digital forensics platform for analyzing Windows Event Logs (EVTX files) with Chainsaw SIGMA rule processing, OpenSearch indexing, and advanced search capabilities.

## Key Features

- **Case-Driven Organization**: Organize investigations by cases with proper data isolation
- **Multi-User System**: Administrator, Analyst, and Read-Only user roles with audit logging
- **EVTX Processing**: Parse and index Windows Event Logs with real-time progress tracking
- **Chainsaw SIGMA Engine**: Automated threat detection using 3000+ SIGMA rules via Chainsaw v2.12.2
- **Powerful Search**: Boolean logic, field-specific queries, SIGMA violation filtering
- **Event Type Descriptions**: Human-readable descriptions for 100+ Windows Event IDs
- **Audit Trail**: Complete logging of authentication, file operations, searches, admin actions
- **Modern Render-Based UI**: Dark blue gradient theme, no templates

## System Requirements

- **OS**: Ubuntu 24.04 LTS (headless server)
- **RAM**: Minimum 8GB, 16GB recommended
- **CPU**: Multi-core recommended for file processing
- **Storage**: 100GB+ for EVTX files and indexes
- **Network**: Internet access for initial setup and rule updates

## Installation

### Quick Install

```bash
# Clone repository
git clone https://github.com/JustinTDCT/caseScope7.git
cd caseScope7

# Run installer
sudo bash install.sh
```

### Installation Options

1. **Option 1 - Clean Install**: Complete fresh installation (removes all existing data)
2. **Option 2 - Upgrade**: Preserve database, upgrade code (runs migrations automatically)
3. **Option 3 - Reindex**: Keep database, clear OpenSearch indexes for re-indexing

## Default Credentials

**Username:** administrator  
**Password:** ChangeMe!

*Password change required on first login.*

## Directory Structure

```
/opt/casescope/
├── app/                    # Application code (main.py, tasks.py, celery_app.py)
├── data/                   # SQLite database
├── uploads/{case_id}/      # Uploaded EVTX files organized by case
├── logs/                   # Application logs
├── rules/sigma-rules/      # SigmaHQ rules repository (3000+ rules)
├── bin/                    # Chainsaw binary
├── chainsaw/mappings/      # Chainsaw field mappings
└── venv/                   # Python virtual environment
```

## Services

```bash
# Service management
sudo systemctl status casescope-web      # Flask web app (Gunicorn)
sudo systemctl status casescope-worker   # Celery background worker
sudo systemctl status opensearch         # OpenSearch 2.11.1
sudo systemctl status redis-server       # Redis broker
sudo systemctl status nginx              # Reverse proxy

# View logs
sudo journalctl -u casescope-web -f
sudo journalctl -u casescope-worker -f
```

## User Roles

### Administrator
- Full system access
- User management (create/edit/delete users)
- Audit log access
- Case/file/search permissions
- SIGMA rule management

### Analyst
- Case creation and management
- File upload and processing
- Search and analysis
- Cannot manage users or view audit logs

### Read-Only
- Search and view capabilities
- Case browsing
- Cannot create, modify, or delete data

## File Processing Workflow

1. **Upload**: EVTX files uploaded to case (3GB max per file, 5 files per batch)
2. **Duplicate Check**: SHA256 hash verification
3. **Event Counting**: Real-time event count for accurate progress
4. **Indexing**: OpenSearch bulk indexing with flattened event structure
5. **SIGMA Processing**: Chainsaw hunt on EVTX with enabled rules
6. **Enrichment**: Flag violated events with `has_violations`, `violation_count`, `sigma_detections`
7. **Completed**: Events searchable with violation filtering

## Search Capabilities

### Search Syntax
- **Text search**: `defender` or `powershell`
- **Field search**: `EventID:4624` or `Computer:WS01`
- **Boolean**: `EventID:4624 AND Computer:DC01`
- **Wildcards**: `*.exe` or `admin*`
- **Phrases**: `"mimikatz detected"`

### Supported Fields
- EventID, Computer, Channel, Provider, Level, Task
- TimeCreated, event_type (description)
- source_filename, has_violations

### Violation Filtering
- Checkbox: "Show only SIGMA violations"
- Filters for events flagged by Chainsaw rules
- View violation details and matched rules

## SIGMA Rules

### Rule Management
- Download 3000+ rules from SigmaHQ GitHub
- Auto-enable Windows threat-hunting rules
- Enable/disable individual rules
- View rule details (level, category, description)
- Client-side search filtering

### Chainsaw Processing
- Uses official `sigma-event-logs-all.yml` mapping
- Processes raw EVTX files (not JSON)
- Creates `SigmaViolation` records in database
- Enriches OpenSearch events with detection flags

## API Endpoints

- `/` - Dashboard
- `/case/select` - Case selection
- `/case/dashboard` - Case dashboard
- `/upload` - File upload
- `/files` - File list
- `/search` - Event search
- `/violations` - SIGMA violations
- `/sigma-rules` - Rule management
- `/users` - User management (admin)
- `/audit-log` - Audit log viewer (admin)
- `/api/file/progress/<id>` - Real-time task progress
- `/api/reindex-all-files` - Bulk re-index
- `/api/rerun-all-rules` - Bulk re-run rules

## Configuration

### OpenSearch
- **max_clause_count**: 16384 (supports complex SIGMA rules)
- **search.default_keep_alive**: 5m
- **Single-node cluster** on localhost:9200

### Celery
- **Broker**: Redis (localhost:6379)
- **Queue**: `celery` (direct exchange)
- **Tasks**: `start_file_indexing`, `process_sigma_rules`

### Database
- **SQLite**: `/opt/casescope/data/casescope.db`
- **Models**: User, Case, CaseFile, SigmaRule, SigmaViolation, AuditLog
- **Migrations**: Auto-run on Option 2/3 installs

## Logging

### Application Logs
- **Web**: `journalctl -u casescope-web -f`
- **Worker**: `journalctl -u casescope-worker -f`
- **OpenSearch**: `journalctl -u opensearch -f`

### Audit Logging (v7.4.0)
- **Authentication**: Login/logout/failed attempts (with IP)
- **File Operations**: Uploads
- **Search**: Query text and result counts
- **Admin**: User create/edit/delete

## Troubleshooting

### File Processing Stuck
```bash
sudo systemctl restart casescope-worker
sudo journalctl -u casescope-worker -n 100
```

### SIGMA Rules Not Matching
```bash
# Verify Chainsaw installed
ls -lh /opt/casescope/bin/chainsaw
sudo -u casescope /opt/casescope/bin/chainsaw --version

# Check enabled rules
sudo -u casescope /opt/casescope/venv/bin/python3 -c "
import sys; sys.path.insert(0, '/opt/casescope/app')
from main import app, db, SigmaRule
with app.app_context():
    print(f'Enabled: {SigmaRule.query.filter_by(enabled=True).count()}')
"
```

### OpenSearch Issues
```bash
curl http://localhost:9200/_cluster/health
curl http://localhost:9200/_cluster/settings?include_defaults=true | grep max_clause_count
```

### Database Migration
```bash
# Option 2/3 auto-runs, or manually:
cd /opt/casescope/app
sudo -u casescope /opt/casescope/venv/bin/python3 migrate_audit_log.py
```

## Version History

- **7.4.0**: Audit logging system
- **7.3.x**: User management system
- **7.2.x**: Chainsaw SIGMA engine integration
- **7.1.x**: Core EVTX indexing and search
- **7.0.x**: Initial architecture

See `version.json` for complete changelog.

## Support

**Email**: casescope@thedubes.net  
**Repository**: https://github.com/JustinTDCT/caseScope7

## License

Copyright (c) 2025 Justin Dube. All rights reserved.
