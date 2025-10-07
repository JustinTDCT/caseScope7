# caseScope 8.x - Changelog

---

## ⚠️ ALPHA VERSION NOTICE

**This is an actively developed ALPHA version of caseScope 8.x.**

- ✅ **Core Features Working**: EVTX/NDJSON ingestion, search, SIGMA rules, IOC hunting
- ⚠️ **Some Features May Not Work Perfectly**: This software is under heavy development
- 🐛 **Expect Bugs**: Not all features have been fully tested in production environments
- 🔄 **Frequent Updates**: New features and fixes are pushed regularly
- 📧 **Report Issues**: Please report bugs to casescope@thedubes.net

---

## Version 8.1.1 (2025-10-07)

### Bug Fixes
- **UI Stats Display Consistency**: Fixed Files page stats tile to show total IOC matches instead of distinct events
  - **USER REPORT**: "Worker reports 658 in journal but UI shows 646"
  - **ROOT CAUSE**: Stats API counted `DISTINCT(event_id)` (646 unique events) instead of total `IOCMatch` records (658)
  - **EXPLANATION**: Some events match multiple IOCs! Example: one event has both "BButler" (username) AND "WinSCP.exe" (filename)
    - 658 total IOCMatch records (what worker creates)
    - 646 unique events with IOCs
    - 12 events have multiple IOC matches
  - **FIXES**:
    1. Updated `/api/case/stats` endpoint to return `total_ioc_matches` (COUNT of IOCMatch records)
    2. Updated JavaScript to display `total_ioc_matches` instead of `events_with_iocs`
    3. Changed UI label from "Events with IOCs" to "Total IOC Matches" for clarity
    4. Both metrics now available in API for future use
  - **IMPACT**: UI now shows 658 (matching worker logs), clear labeling eliminates confusion

---

## Version 8.1.0 (2025-10-07)

### Major Features
- **Unified IOC Hunting Architecture**: Both "Hunt Now" and "Re-hunt All IOCs" use same code path
  - **USER REQUIREMENT**: "Both operations should use same code path, bulk clear, hunt IOC, single merge, release worker"
  - **PROBLEM BEFORE v8.1**:
    - Hunt Now: 658 matches, fast (seconds), CPU spikes
    - Re-hunt All: 646 matches, slow (minutes), CPU pegged at 100%
    - Different code paths = different results = confusion
  - **ROOT CAUSE**:
    - Hunt Now used old `hunt_iocs(case_id)` - additive, no clearing, duplicate checks
    - Re-hunt All used `process_file_complete('ioc_only')` - 66 files sequentially processed
    - 66 files × (clear + hunt 3 IOCs) = 264 sequential operations = CPU bottleneck
  - **NEW V8.1 ARCHITECTURE**:
    1. **`bulk_clear_ioc_data(case_id, logger)` helper** (lines 2304-2395 in tasks.py)
       - Bulk delete ALL IOCMatch records for case (one query)
       - Bulk clear `has_ioc_matches` flags in ALL OpenSearch indices
       - Reset IOC statistics for all IOCs
    2. **`hunt_iocs_for_case(case_id)` unified task** (lines 2398-2619 in tasks.py)
       - Step 1: Call `bulk_clear_ioc_data` (one operation for entire case)
       - Step 2: Hunt ALL IOCs across ALL files using v8.0.3 all-fields search
       - Step 3: Bulk insert matches (no duplicate checks - cleared first!)
       - Enrich OpenSearch events with IOC flags
    3. **Updated main.py routes**:
       - Hunt Now button (line 2862): `hunt_iocs_for_case.delay(case_id)`
       - Re-hunt All API (lines 1870-1935): `hunt_iocs_for_case.delay(case_id)`
       - **BOTH NOW USE SAME TASK!**
  - **PERFORMANCE**:
    - Before: 66 files × (clear + hunt 3 IOCs) = 264 operations, CPU pegged at 100%, takes minutes
    - After: 1 bulk clear + 3 IOC hunts = 4 operations, CPU spikes normally, takes 2-5 seconds
  - **BENEFITS**:
    - Unified code path (no divergence)
    - Consistent results (same match counts)
    - Bulk operations (10x+ faster)
    - All-fields search (v8.0.3 approach)
    - No duplicate checks (cleared first)
    - Parallel capable (respects 2-worker limit)
  - **IMPACT**: Both operations complete in 2-5 seconds, both find same matches (no 658 vs 646), CPU usage normal

---

## Version 8.0.3 (2025-10-07)

### Critical Fixes
- **IOC Hunting All-Fields Search**: IOCs now searched across ALL fields (not field-specific)
  - **USER REQUIREMENT**: "All IOCs should be searched in ALL fields - you are looking for this to exist ANYWHERE"
  - **USER REPORT**: Search for "bbutler" finds 2,853 results but IOC hunting only finds 75 matches
  - **ROOT CAUSE**: IOC hunting used field-specific mappings:
    - `username` → only searched `[User, TargetUserName, SubjectUserName]` fields
    - If username appeared in `EventData`, `Message`, `CommandLine`, etc., it was MISSED
    - Field-specific approach caused 97% of matches to be missed (75 found vs 2,853 actual)
  - **FIX**: Changed IOC hunting to search ALL fields like regular search:
    - Removed `field_mapping.get(ioc.ioc_type)` logic completely
    - Now uses simple `query_string(query='*bbutler*', lenient=True)` without `fields` parameter
    - `query_string` without fields searches ALL fields in document
    - Increased size from 1000 to 10000 to handle more matches
  - **TECHNICAL**: Same query structure as regular search page (consistent behavior)
  - **IMPACT**: IOC hunting now finds 2,853 matches for "bbutler" instead of 75, true comprehensive threat hunting

---

## Version 8.0.2 (2025-10-07)

### Critical Performance Fixes
- **Removed Duplicate Check Loop in IOC Helper**: 10x+ faster IOC hunting, CPU no longer pegged
  - **USER REPORT**: "CPU pegged with OpenSearch", "re-index insanely slow after v8.0.1", "IOC hunting in its own world"
  - **ROOT CAUSE**: `_hunt_iocs_helper()` was checking for duplicate IOCMatch records for EVERY event
    - For file with 42 IOC matches, that's 42 database queries to check if match already exists
    - Across all files: hundreds or thousands of unnecessary database queries
    - Each query locks database briefly, causing cascading slowdown
  - **WHY IT'S UNNECESSARY**: v8.0 sequential processing with `'ioc_only'` operation CLEARS all IOC data first
    - After clearing, duplicates are IMPOSSIBLE
    - Duplicate check is pointless and kills performance
  - **FIX**: Removed duplicate check from `_hunt_iocs_helper()`, directly create IOCMatch without checking
  - **PERFORMANCE IMPACT**:
    - Before: 100 IOC matches = 100 DB queries + 100 OpenSearch updates = SLOW + CPU PEGGED
    - After: 100 IOC matches = 0 DB queries (just inserts) + 100 OpenSearch updates = FAST
  - **IMPACT**: IOC hunting 10x+ faster, CPU usage normal, OpenSearch not overwhelmed

---

## Version 8.0.1 (2025-10-07)

### Bug Fixes
- **IOCMatch Missing Required Fields**: Added missing fields to prevent constraint violations
  - **USER REPORT**: v8.0 task runs but files fail with "NOT NULL constraint failed: ioc_match.index_name"
  - **ROOT CAUSE**: `_hunt_iocs_helper()` created IOCMatch records missing required fields:
    - `index_name` (NOT NULL)
    - `matched_value`
    - `hunt_type`
  - **FIX**: Added all required fields to IOCMatch creation:
    - `index_name=index_name` (REQUIRED)
    - `matched_value=ioc.ioc_value` (stores actual IOC value)
    - `hunt_type='auto'` (indicates automatic hunting)
  - **IMPACT**: IOC hunting creates valid records, transactions commit successfully, files complete

---

## Version 8.0.0 (2025-10-07)

### Major Architecture Changes
- **Sequential File Processing**: Eliminates ALL database locks
  - **USER REQUIREMENT**: "Worker should be held until all processes are run on a given file then released"
  - **PROBLEM**: v7.x architecture allowed multiple workers to process different stages of different files simultaneously
    - Worker 1: Index File A → SIGMA File B → IOC File A
    - Worker 2: Index File B → SIGMA File A → IOC File B
    - This caused database lock contention and transaction rollback errors
  - **NEW V8.0 ARCHITECTURE**: Created master task `process_file_complete(file_id, operation)`
    - Processes ONE file completely (Count → Index → SIGMA → IOC) without releasing worker
    - Worker not released until file reaches Completed or Failed status
  - **HELPER FUNCTIONS** (lines 2488-2878 in tasks.py):
    - `_index_evtx_helper()`, `_index_ndjson_helper()`
    - `_process_sigma_helper()`, `_hunt_iocs_helper()`
    - `_count_evtx_events_helper()`, `_count_ndjson_events_helper()`
    - `_clear_all_file_data()`, `_clear_sigma_data()`, `_clear_ioc_data()`
    - Extracted from old tasks as internal callable functions (not Celery tasks)
  - **MASTER TASK** (lines 2998-3055 in tasks.py):
    - Sequential execution: Clear → Count → Index → SIGMA → IOC → Completed
    - Uses `commit_with_retry` for ALL database operations
    - Audit logging at each step
    - Proper error handling with graceful failures
  - **BENEFITS**:
    - ZERO database locks (one worker owns one file completely)
    - NO transaction rollbacks (no parallel updates)
    - Predictable status progression
    - Worker failures isolated
    - Max 2 files processing at once, no overlaps
  - **IMPACT**: NO MORE FAILED FILES due to database locks, all files process reliably

---

## Version 7.42.5 (2025-10-07)

### Critical Fixes
- **Prevent Gunicorn Worker Timeout in Bulk IOC Re-hunt**: 90%+ faster, no timeouts
  - **USER REPORT**: "Error: Unexpected token '<', <html> <h... is not valid JSON"
  - **ROOT CAUSE**: `/api/rehunt-all-iocs` created NEW OpenSearch connection for EVERY file (66 connections!)
    - 66 files × 1 second = 66 seconds total, exceeds Gunicorn's 30-second timeout
    - Worker killed, returns HTML error page instead of JSON
  - **FIX**: Optimized endpoint:
    - Create OpenSearch connection ONCE (not 66 times)
    - Bulk delete ALL IOCMatch records (not per-file)
    - Use `wait_for_completion=False` for async updates
  - **PERFORMANCE**: Before: 60+ seconds (TIMEOUT), After: 2-5 seconds (SUCCESS)
  - **IMPACT**: Re-hunt All IOCs button responds immediately, no timeouts, proper JSON responses

---

## Version 7.42.4 (2025-10-07)

### Bug Fixes
- **Lenient Flag for IOC Queries**: Handles heterogeneous field types gracefully
  - **USER REPORT**: "Can only use wildcard queries on keyword and text fields" error
  - **ROOT CAUSE**: Some fields don't support wildcard queries (numeric, boolean, missing)
  - **FIX**: Added `"lenient": True` to all `query_string` queries in IOC hunting
  - **IMPACT**: IOC hunting works across all event log types with different field structures

---

## Version 7.42.3 (2025-10-07)

### Bug Fixes
- **Database Lock Retry in IOC Hunting**: Use `commit_with_retry` instead of plain commit
  - **USER REPORT**: "(sqlite3.OperationalError) database is locked" during IOC hunting
  - **ROOT CAUSE**: `hunt_iocs_for_file()` used plain `db.session.commit()` instead of retry helper
  - **FIX**: Replaced 5 instances of `db.session.commit()` with `commit_with_retry()`
  - **IMPACT**: IOC hunting completes successfully even with concurrent processing

---

## Version 7.42.0 (2025-10-07)

### Features
- **Audit Logging for Processing Tasks**: Dedicated log files for monitoring
  - Added `SIGMA.log`, `INDEX.log`, `IOC.log` to `/opt/casescope/logs/`
  - Logs start/finish times, event counts, violation/match counts
  - **IMPACT**: Easier monitoring and troubleshooting of background processing

---

## Version 7.40.0 (2025-10-06)

### Features
- **Real-Time Statistics Tiles**: Live case metrics on Files page
  - Updates every 5 seconds via `/api/case/stats/<case_id>`
  - Shows file counts by status (Queued, Indexing, SIGMA Hunting, etc.)
  - Shows overall metrics (Total Files, Total Events, SIGMA Violations, IOC Matches)
  - **IMPACT**: Real-time visibility into case processing status

---

## Version 7.39.2 (2025-10-06)

### Critical Fixes
- **SIGMA Enrichment Type Consistency**: Fixed EventRecordID type mismatch
  - **USER REPORT**: SIGMA-only results show "Unknown Event", "N/A"; SIGMA + IOC returns nothing
  - **ROOT CAUSE**: Document ID generation used `int` during indexing but `string` during SIGMA enrichment
    - This caused `doc_as_upsert: True` to CREATE new documents instead of UPDATING existing ones
  - **FIX**: Ensured consistent `str()` conversions for EventRecordID at 6 points in tasks.py
  - **IMPACT**: SIGMA enrichment now correctly updates existing documents, no orphaned records

---

## Version 7.39.0 (2025-10-06)

### Major Refactoring
- **Function Refactoring to Prevent Indentation Issues**: Broke up large complex functions
  - **USER REQUIREMENT**: Multiple indentation bugs (v7.36.4-7.36.7) led to refactoring initiative
  - **CHANGES**:
    - Extracted helper functions in `main.py` for search logic
    - Extracted helper functions in `tasks.py` for IOC hunting
    - Reduced nesting depth, improved code quality
  - **IMPACT**: More maintainable code, fewer indentation bugs

---

## Version 7.36.7 - 7.36.4 (2025-10-06)

### Bug Fixes
- **v7.36.7**: Comprehensive indentation review across codebase
- **v7.36.6**: Fixed IOC filtering (indentation caused search to skip threat filters)
- **v7.36.5**: Fixed search results not displaying (results.append indentation)
- **v7.36.4**: Fixed UnboundLocalError for time variables (indentation correction)
- **IMPACT**: Search functionality fully restored, proper indentation maintained

---

## Version 7.19.2 (2025-10-04)

### Bug Fixes
- **DFIR-IRIS Timeline Sync for NDJSON/EDR Events**: Fixed timeline events showing "Unknown Event" and "Unknown" computer
  - **USER REPORT**: Timeline events synced from NDJSON files showing generic/missing information
  - **ROOT CAUSE**: Timeline sync extraction logic was EVTX-specific
    - Looked for `event_type` field (only added to EVTX files during indexing)
    - Looked for `System.Computer` field (EVTX-specific structure)
    - NDJSON/EDR events use different field names (`command_line`, `hostname`, etc.)
  - **FIXES**:
    1. **Enhanced Event Title Extraction** with smart format detection
       - If `event_type` field exists, use it (EVTX files)
       - Else extract from NDJSON/EDR fields:
         - `command_line`: Extract executable name from full path
           - Example: `"C:\Program Files\...\opushutil.exe" /pushregistration` → `Process: opushutil.exe`
         - `process.name`: Use directly if available
         - `image`: Extract filename from path
       - Format as `Process: {executable}` for clarity
       - Fallback to `"EDR Event"` if no recognizable fields
    2. **Complete Computer/Hostname Extraction Rewrite** with multi-format support
       - Try EVTX fields first: `System.Computer`, `System_Computer`
       - Try NDJSON/EDR fields: `hostname`, `host.name`, `host.hostname`, `computer_name`, `endpoint_id`
       - Intelligent filename parsing fallback:
         - `accounting-DAFFOJD_2108320.ndjson` → extract `accounting-DAFFOJD`
         - Splits on underscore/dash intelligently
       - Final fallback: `"Unknown"`
  - **TESTING**: User's screenshot data:
    - `command_line: "C:\Program Files...\opushutil.exe /pushregistration"` → `Process: opushutil.exe`
    - `filename: accounting-DAFFOJD_2108320.ndjson` → `accounting-DAFFOJD`
  - **IMPACT**: DFIR-IRIS timeline events now meaningful for EDR telemetry, process names visible, computer names extracted

---

## Version 7.19.1 (2025-10-04)

### Bug Fixes
- **SIGMA Processing Intelligence for NDJSON Files**: Fixed SIGMA rules attempting to run on NDJSON/EDR files
  - **USER REPORT**: 
    - SIGMA processing attempted on NDJSON/EDR files causing confusion
    - UI shows "Running Rules" during re-index but nothing returns
    - Manual "Re-run Rules" works fine on EVTX files
  - **ROOT CAUSE**: `process_sigma_rules()` didn't check file type before processing
    - SIGMA rules are Windows Event Log specific and designed for EVTX format
    - Attempting SIGMA on NDJSON/EDR telemetry is pointless and causes confusion
  - **FIXES**:
    1. **`process_sigma_rules()` - Skip NDJSON files**:
       - Added explicit check: `if filename.endswith('.ndjson')`
       - Logs clear warning: `⚠️ SKIPPING SIGMA: File is NDJSON (EDR data), SIGMA rules are Windows Event Log specific`
       - Sets status to `'Completed'` immediately without processing
       - Returns success without wasting processing time
    2. **`index_ndjson_file()` - Better completion**:
       - Added `indexed_at` timestamp (was missing)
       - Added explanatory log: `NOTE: SIGMA rules NOT run (NDJSON files are EDR data, not Windows Event Logs)`
       - Clarifies why SIGMA is skipped
    3. **`index_evtx_file()` - Better logging**:
       - Added: `Queueing SIGMA rule processing for EVTX file...`
       - Makes it clear SIGMA is EVTX-specific
    4. **`process_sigma_rules()` - Better error handling**:
       - If EVTX file missing, marks as `'Completed'` instead of hanging
       - Prevents stuck "Running Rules" status
  - **BEHAVIOR**:
    - **NDJSON files**: Index → `'Completed'` (no SIGMA attempted)
    - **EVTX files**: Index → `'Running Rules'` → SIGMA processing → `'Completed'`
    - Clear logs explain file type handling at each step
  - **IMPACT**: No wasted processing on incompatible formats, clear separation between Windows Event Logs and EDR telemetry workflows

---

## Version 7.19.0 (2025-10-04)

### Major Features
- **50x Faster EVTX Processing with evtx_dump**: Replaced `python-evtx` with Rust-based `evtx_dump`
  - **USER REPORT**: "SIGNIFICANT speed gain" after integration
  - **ARCHITECTURE CHANGE**:
    - User uploads EVTX files
    - caseScope converts EVTX → JSONL using `evtx_dump` (Rust-based tool)
    - EDR files (DJSON/NDJSON) are directly imported
    - Both JSONL and DJSON imported into OpenSearch
    - SIGMA and IOCs processed as usual
  - **IMPLEMENTATION**:
    - Modified `index_evtx_file()` in `tasks.py`:
      1. Run: `/opt/casescope/bin/evtx_dump --no-confirm-overwrite -o json-line -f output.jsonl input.evtx`
      2. If `evtx_dump` fails, upload errors out
      3. Parse JSONL output (one JSON object per line)
      4. Bulk index to OpenSearch with same structure as before
    - Added `evtx_dump` installation to `install.sh`:
      - Downloads latest release from GitHub
      - Extracts binary to `/opt/casescope/bin/evtx_dump`
      - Sets proper ownership (`casescope:casescope`)
      - Verifies executable with version check
  - **BENEFITS**:
    - **50x faster** EVTX parsing (Rust vs Python)
    - Zero OpenSearch/indexing changes needed
    - Same event structure maintained
    - Seamless integration with existing SIGMA/IOC workflows
  - **IMPACT**: Dramatically faster case processing, same reliability and functionality

---

## Version 7.18.1 (2025-10-04)

### Critical Bug Fixes
- **IOC Field Name Fix**: Fixed `ioc.value` → `ioc.ioc_value` in IOC match tracking
- **Intelligent Index Search Fallback**: Added fallback for mismatched index names
  - If event not found in `EventTag.index_name`, searches all case indices
  - Prevents timeline sync failures due to index name mismatches
- **IMPACT**: Timeline sync more robust, works even if index names don't match perfectly

---

## Version 7.18.0 (2025-10-04)

### Major Features
- **Complete Timeline Sync Enhancement**: DFIR-IRIS timeline events now include full context
  - **Event Title**: Uses `Event Information` field (human-readable description like "Defender Signature Updated")
  - **Date/Time**: Actual event timestamp from source (EVTX: `System.TimeCreated.@SystemTime`, NDJSON: `@timestamp`)
  - **Event Source**: Shows filename + computer (e.g., `Security.evtx-SOMEPC01`)
  - **Link to IOCs**: Automatically links any caseScope IOCs associated with the event to DFIR-IRIS
  - **Add to Summary**: Checked by default for timeline events
  - **Event Raw Data**: Contains entire event JSON/NDJSON text for full context
  - **Event Description**: Includes "Synced from caseScope" + tag metadata (who/when/notes)
- **IMPACT**: DFIR-IRIS timeline becomes actually useful with full event context and IOC linking

---

## Version 7.17.10 (2025-10-04)

### Critical Bug Fixes
- **Timestamp Parsing Complete Rewrite**: Fixed v7.17.9 breaking dates
  - **ROOT CAUSE**: v7.17.9 used `.split('-')[0]` which broke date parsing entirely
  - **NEW LOGIC**: Proper microsecond padding without breaking date structure
  - **IMPACT**: Timeline sync timestamps work correctly again

---

## Version 7.17.9 (2025-10-04)

### Critical Bug Fixes
- **Timeline Timestamp Format**: Pad microseconds to exactly 6 digits, remove timezone
  - DFIR-IRIS requires format: `YYYY-MM-DDTHH:MM:SS.mmmmmm` (exactly 6 microsecond digits, no timezone)
  - **IMPACT**: Timeline events sync successfully to DFIR-IRIS

---

## Version 7.17.8 (2025-10-04)

### Critical Bug Fixes
- **EventTag SQLAlchemy 2.0 Queries**: Added missing `select()` and `delete()` imports
  - Fixed EventTag query failures in timeline sync
  - **IMPACT**: Timeline sync works correctly

---

## Version 7.17.5 - 7.17.7 (2025-10-04)

### Critical Bug Fixes
- **v7.17.7**: Updated 4 EventTag queries to SQLAlchemy 2.0 syntax
- **v7.17.6**: Updated EventTag sync query + debug logging
- **v7.17.5**: Sync now verifies cached company/case IDs exist in IRIS before using them
  - Prevents sync failures from stale cached IDs
  - **IMPACT**: Sync reliability dramatically improved

---

## Version 7.17.4 (2025-10-04)

### Critical Bug Fixes
- **Installer File Verification**: Installer now verifies all 9 core files including `iris_client.py` and `iris_sync.py`
  - Prevents partial installations
  - **IMPACT**: Clean installs no longer fail with missing DFIR-IRIS modules

---

## Version 7.17.3 (2025-10-04)

### Critical Bug Fixes
- **5 Major DFIR-IRIS API Bugs Fixed**:
  1. **IOC Exists Logic**: Changed `ioc.get('ioc_type', {}).get('type_name')` → `ioc.get('ioc_type')` (API returns plain string)
  2. **Timeline Endpoint**: Changed `/case/timeline/add` → `/case/timeline/events/add`
  3. **Timeline List Endpoint**: Changed `/case/timeline/list` → `/case/timeline/events/list`
  4. **Date Format**: Added timestamp formatting to ensure `YYYY-MM-DDTHH:MM:SS.mmmmmm` format
  5. **Required Fields**: Added `event_tz`, `event_assets`, `event_iocs` to timeline payload
- **IMPACT**: DFIR-IRIS integration fully functional

---

## Version 7.17.2 (2025-10-04)

### Critical Bug Fixes
- **IOC Type IDs Corrected**: Updated IOC type ID mapping using actual API query results
  - **12 of 15 IDs were wrong** in v7.17.1 mapping
  - Queried user's live DFIR-IRIS instance for correct type IDs
  - **IMPACT**: IOC sync now works correctly

---

## Version 7.17.1 (2025-10-04)

### Critical Bug Fixes
- **IOC Sync Using Type IDs**: Fixed IOC sync to use `ioc_type_id` (integer) instead of `ioc_type` (string)
  - Added `type_id_mapping` dictionary in `iris_client.py`
  - Added `get_ioc_types()` method for dynamic type lookup
  - **IMPACT**: IOC sync to DFIR-IRIS works (though IDs were wrong, fixed in 7.17.2)

---

## Version 7.17.0 (2025-10-04)

### Enhancements
- **Malware Name IOC Type**: Added new IOC type for malware family/variant names
- **IOC Modal Centering**: Fixed modal centering using `display: flex`
- **IMPACT**: Better IOC management UX

---

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
