# caseScope 7.x - Changelog

## Version 7.16.6 (2025-10-04)

### Bug Fixes
- **Critical SQL Fix**: Fixed `migrate_case_company.py` failing with "near case: syntax error"
  - ROOT CAUSE: `case` is a reserved SQL keyword in SQLite and must be quoted
  - Changed `PRAGMA table_info(case)` to `PRAGMA table_info("case")`
  - Changed `ALTER TABLE case` to `ALTER TABLE "case"`
  - Audited all migration scripts to ensure no other reserved keyword conflicts exist

---

## Version 7.16.5 (2025-10-04)

### Critical Fixes
- **SSL Certificate Handling**: DFIR-IRIS integration now works with self-signed certificates
  - Disabled SSL verification in both test connection endpoint and IrisClient session
  - Added urllib3 warning suppression to prevent console spam
  - Increased timeout from 5s to 10s for slower internal networks
  - **IMPACT**: DFIR-IRIS integration now production-ready for enterprise deployments

---

## Version 7.16.4 (2025-10-04)

### Major Features
- **DFIR-IRIS Sync UI Integration**: Complete implementation of DFIR-IRIS sync
  - Added "Sync to DFIR-IRIS" button on case dashboard
  - Manual sync with progress feedback
  - Sync status indicators (last synced timestamp, IRIS case ID)
  - Full integration of API client + sync service + UI
  - **IMPACT**: One-click sync of cases, IOCs, and timeline events to DFIR-IRIS

---

## Version 7.16.3 (2025-10-04)

### Major Features
- **DFIR-IRIS Sync Service**: Intelligent 4-step workflow with deduplication
  - Step 1: Company management (create if doesn't exist)
  - Step 2: Case sync (create and bind to company)
  - Step 3: IOC sync (push all case IOCs with type mapping)
  - Step 4: Timeline sync (push tagged events as timeline entries)
  - Comprehensive error handling and logging
  - Intelligent deduplication to prevent duplicates

---

## Version 7.16.2 (2025-10-04)

### Major Features
- **DFIR-IRIS API Client Module**: Complete REST API integration
  - `IrisClient` class with session management
  - Company operations (create/update/list)
  - Case operations (create/update/link to company)
  - IOC operations (add with proper type mapping)
  - Timeline operations (add events with full context)
  - Full error handling and retry logic

---

## Version 7.16.1 (2025-10-04)

### Enhancements
- **Company Field for Cases**: Added company tracking for DFIR-IRIS integration
  - New `company` field in Case model
  - New `iris_company_id`, `iris_case_id`, `iris_synced_at` tracking fields
  - Migration script: `migrate_case_company.py`
  - Company field displayed in case forms
  - **IMPACT**: Cases can now be properly organized by customer/company

---

## Version 7.16.0 (2025-10-04)

### Major Features
- **System Settings Page**: User-friendly configuration interface
  - Navigate to Management → System Settings
  - Configure DFIR-IRIS integration (URL, API key, customer ID)
  - Test connection before enabling
  - Toggle auto-sync on/off
  - New `SystemSettings` database model
  - Migration script: `migrate_system_settings.py`
  - **IMPACT**: Easy setup for DFIR-IRIS integration, no command-line config needed

---

## Version 7.15.x Series (2025-10-04)

### 7.15.6 - IOC Field Extraction Fix
- Fixed IOC hunting field extraction for timestamp and filename
- Added dot notation support for nested field access
- **IMPACT**: IOC matches now properly show event timestamp and source filename

### 7.15.5 - Migration Database Path Fix
- Fixed IOC matches migration database path from `/opt/casescope/` to `/opt/casescope/data/`
- **IMPACT**: Migration runs successfully on all installations

### 7.15.4 - IOC Matches Display
- Added source filename column to IOC matches
- Improved matched field detection and display
- Changed "Detected" column to "Event Date"
- **IMPACT**: Better visibility into which files contain IOC matches

### 7.15.3 - IOC Nested Field Hunting
- **Critical**: Fixed IOC hunting missing values in nested fields
- Added wildcard ALL-field query to catch IOCs in any nested structure
- **IMPACT**: IOC hunting now finds matches in deeply nested JSON (e.g., `EventData.Data_12.#text`)

### 7.15.2 - Event Search Index Errors
- **Critical**: Fixed event search failing on non-existent indices
- Added `ignore_unavailable=True` to both OpenSearch search calls
- **IMPACT**: Search no longer crashes when indices are missing

### 7.15.1 - IOC Hunting Index Errors
- **Critical**: Fixed IOC hunting failing with index_not_found_exception
- Added `ignore_unavailable=True` to IOC hunting queries
- **IMPACT**: IOC hunting gracefully handles missing indices

### 7.15.0 - SQLAlchemy 2.0 Migration
- **MAJOR**: Migrated ALL 86+ queries across entire codebase to SQLAlchemy 2.0 syntax
- Replaced deprecated `Query.get()` with `db.session.get()`
- Replaced `Query.filter_by()` with `db.session.execute(select())`
- **IMPACT**: Future-proof compatibility with SQLAlchemy 2.0+

---

## Version 7.14.x Series (2025-10-03)

### 7.14.11 - IOC Query Migration
- **Critical**: Fixed IOC hunting by updating 14 IOC/IOCMatch queries to SQLAlchemy 2.0 syntax
- **IMPACT**: IOC hunting functional again after 7.15.0 migration

### 7.14.10 - Delete Case Redirect Fix
- Fixed 404 error after case deletion
- Corrected redirect URL from `/case/manage` to `/case-management`
- **IMPACT**: Smooth workflow after deleting cases

### 7.14.9 - Delete Case Query Fix
- **Critical**: Fixed delete case error by updating to SQLAlchemy 2.0 query syntax
- Updated 8 query statements in delete_case function
- **IMPACT**: Case deletion works correctly

### 7.14.8 - Delete Case Button Fix
- **Critical**: Fixed delete case button not appearing
- Corrected role check typo ('Admin' → 'administrator')
- **IMPACT**: Administrators can now delete cases

### 7.14.7 - Table UI Consistency
- Fixed table row border inconsistencies near action buttons
- Removed flexbox from table cells for proper border rendering
- **IMPACT**: Cleaner, more professional table appearance

### 7.14.6 - IOC Page UI Fixes
- Added missing header to IOC Management page
- Fixed modal centering with flexbox display
- **IMPACT**: IOC Management page matches other pages

### 7.14.5 - UI Standardization
- Standardized all page headers (title left, user right)
- Removed green background from version badge
- **IMPACT**: Consistent UI across all pages

### 7.14.4 - Installation Critical Fix
- **Critical**: Removed undefined `@admin_required` decorator causing NameError
- **IMPACT**: Installations no longer break during upgrade

### 7.14.3 - IOC Page Padding
- Fixed IOC Management page missing content div wrapper
- **IMPACT**: Consistent padding with other pages

### 7.14.2 - Changelog Organization
- Reorganized changelog to consistent reverse chronological order
- Fixed 5 more `log_audit` parameter errors
- **IMPACT**: Cleaner version history

### 7.14.1 - Case Deletion Feature
- Added admin case deletion with comprehensive data cleanup
- Fixed close/reopen case errors
- **IMPACT**: Administrators can fully remove cases

### 7.14.0 - IOC Management System
- **MAJOR FEATURE**: Complete IOC Management & Threat Hunting system
  - Add IOCs manually (IPs, hashes, commands, hostnames, FQDNs, usernames)
  - Automatic/manual hunting across all indexed events
  - IOC match tracking with source filename, timestamp, matched field
  - IOC-specific search view showing only tagged events
  - Case-specific IOC management
  - Bulk operations (add multiple, delete all)
  - New database models: `IOC`, `IOCMatch`
  - Migration script: `migrate_ioc_management.py`
  - **IMPACT**: Full threat hunting capabilities integrated into workflow

---

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
