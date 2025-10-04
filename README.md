# caseScope 7.19 - Digital Forensics EVTX Analysis Platform

**Version:** 7.19.2  
**Copyright:** (c) 2025 Justin Dube <casescope@thedubes.net>

---

## ⚠️ ALPHA VERSION NOTICE

**This is an actively developed ALPHA version of caseScope 7.x.**

- ✅ **Core Features Working**: EVTX/NDJSON ingestion, search, SIGMA rules, IOC hunting
- ⚠️ **Some Features May Not Work Perfectly**: This software is under heavy development
- 🐛 **Expect Bugs**: Not all features have been fully tested in production environments
- 🔄 **Frequent Updates**: New features and fixes are pushed regularly
- 📧 **Report Issues**: Please report bugs to casescope@thedubes.net

**Not recommended for production use without thorough testing in your environment.**

---

## Overview

caseScope is a comprehensive digital forensics platform for analyzing Windows Event Logs (EVTX files) and EDR telemetry (NDJSON) with Chainsaw SIGMA rule processing, OpenSearch indexing, IOC threat hunting, timeline analysis, DFIR-IRIS integration, and advanced search capabilities.

## Key Features

- **Case-Driven Organization**: Organize investigations by cases with proper data isolation and company/customer tracking
- **Multi-User System**: Administrator, Analyst, and Read-Only user roles with comprehensive audit logging
- **EVTX & NDJSON Processing**: Parse and index Windows Event Logs and EDR telemetry with real-time progress tracking
- **IOC Threat Hunting**: Add and hunt for IPs, hashes, commands, hostnames, FQDNs, usernames across all indexed events
- **DFIR-IRIS Integration**: One-click sync of cases, IOCs, and timeline events to DFIR-IRIS platform
- **Timeline Event Tagging**: Star/bookmark important events for timeline analysis with collaborative multi-user tagging
- **Chainsaw SIGMA Engine**: Automated threat detection using 3000+ SIGMA rules via Chainsaw v2.12.2
- **Powerful Search**: Boolean logic, field-specific queries, SIGMA/IOC violation filtering, timestamp sorting
- **Event Information Descriptions**: Human-readable descriptions for 100+ Windows Event IDs and EDR events
- **Audit Trail**: Complete logging of authentication, file operations, searches, admin actions
- **System Settings**: User-friendly configuration interface for DFIR-IRIS integration
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

1. **Upload**: EVTX/NDJSON files uploaded to case (3GB max per file, 5 files per batch)
2. **Duplicate Check**: SHA256 hash verification
3. **Event Counting**: Real-time event count for accurate progress
4. **Indexing**: OpenSearch bulk indexing with flattened event structure
5. **SIGMA Processing**: Chainsaw hunt on EVTX with enabled rules (EDR logs skip this step)
6. **Enrichment**: Flag violated events with `has_violations`, `violation_count`, `sigma_detections`
7. **IOC Hunting**: Automatic hunt for case-specific IOCs across all indexed events
8. **Completed**: Events searchable with violation filtering, IOC matches, timeline tagging, and sorting

## Search Capabilities

### Search Syntax
- **Text search**: `defender` or `powershell`
- **Field search**: `EventID:4624` or `Computer:WS01`
- **Boolean**: `EventID:4624 AND Computer:DC01`
- **Wildcards**: `*.exe` or `admin*`
- **Phrases**: `"mimikatz detected"`
- **Case-insensitive**: Automatically applied for analyzed text fields

### Supported Fields
- EventID, Computer, Channel, Provider, Level, Task
- TimeCreated, event_type (description)
- source_filename, has_violations
- EDR fields: command_line, process_name, parent_process, user, hash values

### Timeline Tagging (v7.13.0)
- **Star Icon**: Click ☆ to tag important events for timeline
- **Visual Feedback**: Tagged events show filled gold star ★
- **Collaborative**: All analysts see who tagged each event
- **Persistent**: Tags saved per case and per user
- **API Access**: `/api/event/tag`, `/api/event/untag`, `/api/event/tags`

### Timestamp Sorting (v7.13.1)
- **▼ Newest First**: Sort events by timestamp descending
- **▲ Oldest First**: Sort events by timestamp ascending
- **Default**: Relevance sorting by search score
- **Persistent**: Sort order maintained across pagination

### Violation Filtering
- Checkbox: "Show only SIGMA violations"
- Filters for events flagged by Chainsaw rules
- View violation details and matched rules
- Checkbox: "Show only IOC matches"
- Filters for events matching indicators of compromise
- View matched IOCs and matched field details

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

## IOC Management (v7.14.0)

### IOC Types Supported
- **IP Addresses**: IPv4/IPv6 addresses
- **Hash Values**: MD5, SHA1, SHA256
- **Commands**: Command-line patterns and executables
- **Hostnames**: Computer names and NetBIOS names
- **FQDNs**: Fully qualified domain names
- **Usernames**: Account names and identities

### IOC Workflow
1. **Add IOCs**: Manually enter IOCs from `/ioc-management` page
2. **Automatic Hunting**: IOCs automatically hunted across all indexed events in the case
3. **View Matches**: See all events matching IOCs with field details
4. **Timeline Integration**: Tagged IOC matches can be synced to DFIR-IRIS

### IOC Features
- Case-specific IOC management
- Automatic hunting on file upload
- Manual re-run hunting for existing files
- Match tracking with source filename, timestamp, matched field
- Bulk operations (add multiple IOCs, delete all)

## DFIR-IRIS Integration (v7.16.0)

### Configuration
- **System Settings Page**: Management → System Settings
- Configure IRIS URL, API key, customer ID
- Test connection before enabling
- Auto-sync or manual sync options

### Sync Features
1. **Company Management**: Automatically creates companies in IRIS if they don't exist
2. **Case Sync**: Creates cases in IRIS linked to the correct company
3. **IOC Sync**: Pushes all case IOCs to IRIS with proper type mapping
4. **Timeline Sync**: Syncs tagged events to IRIS timeline with full context

### Sync Workflow
- One-click sync from case dashboard
- Progress feedback during sync
- Sync status indicators (last synced timestamp)
- Intelligent deduplication (won't create duplicates)
- SSL/TLS support including self-signed certificates

### IRIS API Integration
- Company create/update via `/manage/customers/add`
- Case create/update via `/manage/cases/add`
- IOC management via `/case/ioc/add`
- Timeline events via `/case/timeline/events/add`
- Full error handling and retry logic

## API Endpoints

### Web Pages
- `/` - Dashboard
- `/case/select` - Case selection
- `/case/dashboard` - Case dashboard with DFIR-IRIS sync
- `/upload` - File upload
- `/files` - File list
- `/search` - Event search (with sorting and tagging)
- `/violations` - SIGMA violations
- `/sigma-rules` - Rule management
- `/ioc-management` - IOC hunting and management
- `/users` - User management (admin)
- `/audit-log` - Audit log viewer (admin)
- `/case-management` - Case lifecycle management (admin)
- `/file-management` - Cross-case file management (admin)
- `/system-settings` - DFIR-IRIS integration config (admin)

### API Endpoints
- `/api/file/progress/<id>` - Real-time task progress
- `/api/reindex-all-files` - Bulk re-index
- `/api/rerun-all-rules` - Bulk re-run rules
- `/api/event/tag` - Tag event for timeline (POST)
- `/api/event/untag` - Remove event tag (POST)
- `/api/event/tags` - Get tagged events (GET)
- `/api/ioc/add` - Add IOC (POST)
- `/api/ioc/delete/<id>` - Delete IOC (DELETE)
- `/api/ioc/hunt` - Manual IOC hunting (POST)
- `/api/iris/test-connection` - Test DFIR-IRIS connection (POST)
- `/api/iris/sync-case/<id>` - Sync case to DFIR-IRIS (POST)

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
- **SQLAlchemy**: 2.0+ compatible (migrated from 1.x)
- **Models**: User, Case, CaseFile, SigmaRule, SigmaViolation, AuditLog, EventTag, SearchHistory, SavedSearch, CaseTemplate, IOC, IOCMatch, SystemSettings
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

- **7.19.2** (2025-10-04): Bugfix - DFIR-IRIS timeline sync for NDJSON/EDR events (event title + computer name extraction)
- **7.19.1** (2025-10-04): Bugfix - Skip SIGMA processing for NDJSON/EDR files + better status handling
- **7.19.0** (2025-10-04): MAJOR - Replaced python-evtx with evtx_dump (Rust) for 50x faster EVTX processing
- **7.18.1** (2025-10-04): Critical bugfix - IOC field name + intelligent index search fallback
- **7.18.0** (2025-10-04): MAJOR - Complete timeline sync enhancement (real timestamps, Event Information, IOC linking)
- **7.17.x** (2025-10-04): DFIR-IRIS API fixes (IOC sync, timeline timestamps, cached ID verification)
- **7.16.6** (2025-10-04): Bugfix - Fixed SQL syntax error in case company migration
- **7.16.5** (2025-10-04): Critical fix - SSL certificate handling for DFIR-IRIS (self-signed cert support)
- **7.16.4** (2025-10-04): MAJOR - Complete DFIR-IRIS sync implementation
- **7.16.3** (2025-10-04): DFIR-IRIS sync service with 4-step workflow
- **7.16.2** (2025-10-04): DFIR-IRIS API client module
- **7.16.1** (2025-10-04): Added company field to cases for DFIR-IRIS
- **7.16.0** (2025-10-04): Major feature - System Settings page for DFIR-IRIS integration
- **7.15.x** (2025-10-04): IOC hunting enhancements and SQLAlchemy 2.0 migration
- **7.14.x** (2025-10-03): MAJOR - IOC Management & Threat Hunting system
- **7.13.1** (2025-10-03): Timestamp column sorting (newest/oldest first) + Event Information rename
- **7.13.0** (2025-10-02): Timeline event tagging with star icons for incident analysis
- **7.12.x** (2025-10-02): NDJSON/EDR telemetry ingestion, case-insensitive search fixes
- **7.11.x**: NDJSON ingestion foundation
- **7.10.x**: Search enhancements with saved searches and history
- **7.9.x**: Case templates and workflow improvements
- **7.8.x**: Enhanced search with field extraction
- **7.7.x**: Case management improvements
- **7.6.x**: SIGMA violation management
- **7.5.x**: File management and progress tracking
- **7.4.x**: Audit logging system
- **7.3.x**: User management system
- **7.2.x**: Chainsaw SIGMA engine integration
- **7.1.x**: Core EVTX indexing and search
- **7.0.x**: Initial architecture

See `version.json` and `CHANGELOG.md` for complete changelog.

## Support

**Email**: casescope@thedubes.net  
**Repository**: https://github.com/JustinTDCT/caseScope7

## License

Copyright (c) 2025 Justin Dube. All rights reserved.
