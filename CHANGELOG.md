# caseScope 7.x - Changelog

## Version 7.13.1 (2025-10-03)

### Enhancements
- **Timestamp Sorting**: Added sortable Timestamp column in search results
  - ▼ arrow sorts newest first (descending)
  - ▲ arrow sorts oldest first (ascending)
  - Uses OpenSearch date field mapping with fallback for unmapped fields
  - Sort order persists across pagination
  - JavaScript `sortBy()` function with hidden form inputs
- **UI Improvement**: Renamed "Event Type" column to "Event Information" for clarity
- **CSS Styling**: Added `.sortable-header` and `.sort-controls` classes with hover effects

### Bug Fixes
- **Critical**: Fixed `NameError: name 'sort_field' is not defined` in `render_search_page()`
  - Added `sort_field` and `sort_order` parameters to function signature
  - Pass parameters from search route to render function

### Technical Details
- Sort configuration in OpenSearch query body
- Secondary sort by relevance score (`_score`)
- Default: `sort_field='relevance'`, `sort_order='desc'`

---

## Version 7.13.0 (2025-10-02)

### Major Features
- **Timeline Event Tagging**: Comprehensive event tagging system for incident analysis
  - New `EventTag` database model with full relationship mapping
  - Tag events with star/bookmark icon directly in search results
  - Real-time tag/untag with visual feedback (☆ empty star → ★ filled gold star)
  - Tagged events persist per case and per user
  - Multi-user collaborative tagging with unique constraints
  - Hover tooltip shows who tagged each event

### API Endpoints
- `POST /api/event/tag` - Tag an event for timeline
- `POST /api/event/untag` - Remove timeline tag
- `GET /api/event/tags` - Get all tagged events for active case

### Database Changes
- **New Table**: `event_tag`
  - Fields: `case_id`, `event_id`, `index_name`, `event_timestamp`, `tag_type`, `color`, `notes`, `tagged_by`, `tagged_at`
  - Unique constraint: one user can tag event once per tag_type
  - Relationships: Case, User (tagger)
- **Migration**: `migrate_timeline_tags.py` (auto-run on upgrade)

### UI Enhancements
- New "Tag" column in search results table
- Star icon button on each event row
- Gold star (#fbbf24) with glow effect for tagged events
- Gray star (#94a3b8) for untagged events
- Smooth CSS transitions and hover animations
- Tags load automatically via AJAX on page load

### Technical Details
- Stores OpenSearch document ID (`_id` field) for precise event reference
- Index name preserved for future cross-index queries
- Event timestamp stored for timeline sorting
- Tag type field supports categorization (timeline, important, suspicious, etc.)
- Color field for future timeline visualization
- Foundation for upcoming timeline view feature

---

## Version 7.12.5 (2025-10-02)

### Critical Bug Fixes
- **OpenSearch Compatibility**: Removed `case_insensitive` parameter from `query_string` query
  - OpenSearch 2.11.1 does not support `case_insensitive` parameter
  - Error: `RequestError(400, 'parsing_exception', '[query_string] query does not support [case_insensitive]')`
  - Solution: Rely on OpenSearch's default case-insensitive matching for analyzed text fields
  - Impact: Search behavior remains functionally the same for most fields

---

## Version 7.12.4 (2025-10-02)

### Enhancements
- **Case-Insensitive Search**: Added explicit `case_insensitive=True` to query_string (later removed in 7.12.5)

---

## Version 7.12.3 (2025-10-02)

### Bug Fixes
- **Event Type Display**: Fixed Event Type column to show actual `command_line` for EDR events instead of generic process name

---

## Version 7.12.2 (2025-10-02)

### Critical Bug Fixes
- **NDJSON/EDR Display**: Fixed Event Type and Computer fields not displaying correctly in search results table
- Improved field extraction logic for EDR telemetry events

---

## Version 7.12.1 (2025-10-01)

### Bug Fixes
- **NDJSON Progress**: Fixed progress display during NDJSON file upload
- **Upload Progress Bar**: Corrected progress bar visualization
- **EDR Field Mappings**: Improved field mappings for EDR telemetry data

---

## Version 7.12.0 (2025-10-01)

### Major Features
- **NDJSON/EDR Telemetry Ingestion**: Unified EVTX + endpoint telemetry search
  - Support for newline-delimited JSON files from EDR tools
  - Flatten nested JSON structures for OpenSearch indexing
  - Skip SIGMA processing for NDJSON files (not applicable)
  - Display command_line, process info, user, hashes in search results
  - Unified search across EVTX and EDR telemetry

### Technical Details
- Auto-detect NDJSON files by extension
- Event counting with newline parsing
- Field extraction for common EDR fields
- Compatible with multiple EDR vendors

---

## Version 7.11.x - 7.7.x

### 7.11.x - NDJSON Foundation
- Initial groundwork for NDJSON ingestion
- Field mapping research and testing

### 7.10.x - Search Enhancements
- **Saved Searches**: Save frequently used queries
- **Search History**: Track recent searches per user
- **Quick Load**: Click to reload previous searches

### 7.9.x - Case Templates
- **Case Templates**: Reusable case configurations
- **Priority Levels**: High, Medium, Low case priorities
- **Assignee Management**: Assign cases to analysts

### 7.8.x - Enhanced Search
- **Field Extraction**: Improved field parsing
- **Wildcard Support**: Better wildcard query handling
- **Query Validation**: Input validation and error messages

### 7.7.x - Case Management
- **Case Dashboard**: Enhanced case overview
- **File Management**: Improved file listing and filtering
- **Status Tracking**: Case status workflow (Open, In Progress, Closed)
- **Database Migration**: `migrate_case_management.py`

---

## Version 7.6.x - SIGMA Violations

### Features
- **Violation Management**: Comprehensive SIGMA violation interface
- **Mark as Reviewed**: Review and annotate violations
- **Severity Filtering**: Filter by Critical, High, Medium, Low
- **Bulk Operations**: Re-run SIGMA rules across all files

---

## Version 7.5.x - File Management

### Features
- **File Progress Tracking**: Real-time Celery task monitoring
- **Event Counting**: Accurate progress with `/api/file/progress/<id>`
- **File Status**: Clear visual indicators (Pending, Processing, Indexed, Failed)
- **Bulk Re-indexing**: `/api/reindex-all-files` endpoint

---

## Version 7.4.x - Audit Logging

### Features
- **Comprehensive Audit Trail**: Log all user actions
  - Authentication (login/logout/failures) with IP addresses
  - File operations (uploads, deletions)
  - Search queries with result counts
  - Admin actions (user create/edit/delete)
- **Audit Log Viewer**: Admin-only access
- **Filtering**: By category, user, success/failure
- **Database Migration**: `migrate_audit_log.py`

---

## Version 7.3.x - User Management

### Features
- **User CRUD**: Create, edit, delete users
- **Role Management**: Administrator, Analyst, Read-Only
- **Password Management**: Forced password change on first login
- **User Status**: Active/inactive user accounts

---

## Version 7.2.x - Chainsaw SIGMA Engine

### Features
- **Chainsaw Integration**: v2.12.2 Rust-based SIGMA engine
- **3000+ SIGMA Rules**: SigmaHQ rules repository
- **Automated Threat Detection**: `process_sigma_rules` Celery task
- **Event Enrichment**: Flag violated events in OpenSearch
- **Rule Management**: Enable/disable individual rules
- **Violation Tracking**: `SigmaViolation` database model

### Bug Fixes
- **v7.2.12**: Fixed Chainsaw CLI syntax (positional rules directory argument)

---

## Version 7.1.x - Core Platform

### Initial Release (7.1.1 - 2025-09-28)
- **New Architecture**: Complete rebuild from caseScope 7.0.x
- **User Management**: Three-tier access control
- **Case-Driven Design**: Proper case isolation
- **Modern UI**: Dark blue gradient theme, render-based (no templates)
- **Installation System**: Three-option installer (Clean, Upgrade, Reindex)
- **EVTX Processing**: Parse and index Windows Event Logs
- **OpenSearch Integration**: Single-node cluster, bulk indexing
- **Search Functionality**: Boolean logic, field-specific queries
- **Event Type Descriptions**: Human-readable descriptions for 100+ Event IDs

### Core Features
- Flask-based web application with SQLAlchemy ORM
- Bcrypt password hashing and role-based access
- Celery background task processing with Redis broker
- Real-time progress tracking via Server-Sent Events
- Dashboard with system statistics tiles

### Default Credentials
- Username: `administrator`
- Password: `ChangeMe!` (must be changed on first login)

### System Requirements
- Ubuntu 24.04 LTS (recommended)
- Python 3.10+
- 8GB+ RAM recommended
- Multi-core CPU for optimal performance

---

## Installation

```bash
git clone https://github.com/JustinTDCT/caseScope7.git
cd caseScope7
sudo bash install.sh
```

### Installation Options
1. **Clean Install**: Fresh installation (removes all existing data)
2. **Upgrade**: Preserve database, upgrade code (runs migrations)
3. **Reindex**: Keep database, clear OpenSearch indexes

---

## Architecture

- **Application**: `/opt/casescope/app/`
- **Data**: `/opt/casescope/data/casescope.db`
- **Uploads**: `/opt/casescope/uploads/<case_id>/`
- **Logs**: `/opt/casescope/logs/`
- **SIGMA Rules**: `/opt/casescope/rules/sigma-rules/`
- **Chainsaw**: `/opt/casescope/bin/chainsaw`
- **Virtual Environment**: `/opt/casescope/venv/`

---

## Support

**Email**: casescope@thedubes.net  
**Repository**: https://github.com/JustinTDCT/caseScope7

**Copyright** (c) 2025 Justin Dube. All rights reserved.
