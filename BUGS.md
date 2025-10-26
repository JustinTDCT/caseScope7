# caseScope Bug Tracking

**Last Updated:** 2025-10-26  
**Current Version:** v9.0.1

Simple bug tracking - one paragraph per bug, updated with fix date/version when resolved.

---

## Open Bugs

### BUG-008: Search Failing with HTTP Line Too Long Error
**Reported:** 2025-10-26 (v9.0.7)  
**Status:** Open

Search returns error "RequestError(400, 'too_long_http_line_exception', 'An HTTP line is larger than 4096 bytes.')". This occurs when a case has many indexed files (30+ files) and the OpenSearch query URL includes all index names as a comma-separated list. The HTTP GET request line exceeds OpenSearch's 4096 byte limit. Example: With 100 EVTX files, the index list would be case2_file1,case2_file2,case2_file3... which creates a URL over 4KB. OpenSearch rejects this with a 400 error before processing the query.

**Fixed:** _(pending)_

---

### BUG-006: UI Not Auto-Refreshing During File Processing
**Reported:** 2025-10-26 (v9.0.5)  
**Status:** Open

During re-indexing, the UI does not automatically update to show current processing status. Event counts (xx/yyy) sometimes update but other times don't, and files get stuck displaying "Hunting IOCs" status even after processing completes. Users must manually refresh the page (F5) to see the actual "Completed" status and final statistics. This creates confusion about whether files are still processing or have finished. The progress bar and status text should update in real-time without requiring manual page refresh.

**Fixed:** _(pending)_

---

### BUG-007: IOC Search Failing for Command-Line IOCs with Special Characters
**Reported:** 2025-10-26 (v9.0.5)  
**Status:** Open

IOC hunting fails when searching for command-line IOCs that contain special characters like backslashes and quotes. Logs show "RequestError(400, 'search_phase_execution_exception')" with message "Cannot parse '*c:\\windows\\system32\\nltest.exe\" /domain_trusts /all_trusts*': Encountered \" \\\" \\\" \" at line 1". The IOC value "C:\WINDOWS\system32\nltest.exe\" /domain_Trusts /all_trusts" contains backslashes (Windows paths) and quotes that break OpenSearch query parsing. Multiple IOCs with similar patterns are failing: "C:\WINDOWS\system32\nltest.exe\" /dclist:" and "C:\WINDOWS\system32\nltest.exe\" /domain_Trusts /all_trusts". The IOC hunting continues despite errors but these specific IOCs are never matched even if they exist in the data.

**Fixed:** _(pending)_

---

### BUG-001: Search Date Sorting Not Working
**Reported:** 2025-10-26 (v9.0.1)  
**Status:** Open

Search results are not sorting correctly by date. When user selects "Oldest → Newest" or "Newest → Oldest", the events do not display in chronological order. Additionally, the sort order does not persist across pagination - page 2 shows events in random order instead of continuing the sort from page 1. This makes timeline analysis impossible and breaks the investigation workflow. For example, with 20K events spanning 10/23-10/25, sorting oldest→newest should show all 10/23 events on page 1, then 10/24-10/25 events on subsequent pages, but instead events appear randomly mixed across all pages.

**Fixed:** _(pending)_

---

### BUG-002: Date Range Filtering Not Working  
**Reported:** 2025-10-26 (v9.0.1)  
**Status:** Open

Date range filters (24h, 7d, 30d, custom date range) have no effect on search results. When a user selects "Last 24 hours", all events from the entire case timeline are returned instead of just events from the last 24 hours. The custom date picker also doesn't filter results. This prevents analysts from narrowing their investigation to specific time periods and causes performance issues since the system searches through all events instead of the requested subset.

**Fixed:** _(pending)_

---

### BUG-003: File Delete Endpoints Return 500 Errors
**Reported:** 2025-10-26 (v9.0.1)  
**Status:** Open  

File deletion endpoints (`/api/file/1330`, `/api/file/1287`, `/api/file/1283`, `/api/file/999`) are returning 500 Internal Server Error instead of successfully deleting files. The delete button triggers the API call but the server crashes with a 500 error. Additionally, there is no progress indicator shown to the user during bulk delete operations, so users don't know if the deletion is in progress or has failed. The delete functionality was recently implemented in v8.6.1 but appears to have broken during the v9.0.0 refactoring or has issues with the new modular code structure.

**Fixed:** _(pending)_

---

## Fixed Bugs

### BUG-005: SIGMA and IOC Processing Failing After Indexing
**Reported:** 2025-10-26 (v9.0.3)  
**Status:** Fixed

After files indexed successfully, SIGMA rule processing crashed with "TypeError: process_sigma_rules() missing 1 required positional argument: 'index_name'". Files indexed correctly and showed event counts, but then failed before SIGMA processing could start. The error occurred in tasks_queue.py line 83 where process_sigma_rules was called with only file_id, but the function signature required both file_id and index_name parameters. This caused the entire processing pipeline to fail after indexing, so no SIGMA violations were detected and IOC hunting never ran. Files ended up in "Completed" status but with 0 violations and 0 IOC matches even when IOCs were known to exist in the data.

**Fixed:** 2025-10-26 (v9.0.4) - Extract index_name from index_result and pass both file_id and index_name to process_sigma_rules(); added validation for index_name existence; initialized sigma_result for NDJSON files; fixed all 'indexed_events' → 'event_count' references.

---

### BUG-REINDEX: Re-index Button Passing Extra Argument
**Reported:** 2025-10-26 (v9.0.4)  
**Status:** Fixed

Re-index button (single and bulk) were passing 2 arguments to process_file_complete: args=[file_id, 'reindex'], but the function only accepts 1 argument (plus self). This caused "TypeError: process_file_complete() takes 2 positional arguments but 3 were given" and all re-index operations failed immediately. Files stuck in "Queued" status indefinitely. The 'reindex' string was a legacy parameter no longer used.

**Fixed:** 2025-10-26 (v9.0.5) - Removed 'reindex' parameter from both single file re-index (line 1756) and bulk re-index (line 2371) endpoints; both now correctly pass args=[file_id] only.

---

### BUG-004: ZIP Files Not Extracting via Chunked Upload
**Reported:** 2025-10-26 (v9.0.2)  
**Status:** Fixed

ZIP files uploaded via the chunked upload system were being queued to Celery as-is without extraction, causing them to fail with "Unsupported file type" errors. The worker saw "desktop-jsqt9gm.zip" and "draftsite10.zip" files and rejected them because Celery tasks only process EVTX or NDJSON files. The chunked upload finalize endpoint created a CaseFile record for the ZIP and queued it directly to Celery without checking if it needed extraction first. This broke the ZIP upload feature that worked in v8.5.0+. All uploaded ZIP files showed as "Failed" status and extracted EVTX files never appeared in the files list.

**Fixed:** 2025-10-26 (v9.0.3) - Added ZIP file detection to upload_finalize() endpoint; if .zip detected, calls extract_and_process_zip() to extract all EVTX files; each extracted EVTX file gets its own CaseFile record and queued individually; ZIP file deleted after successful extraction; returns extraction count to user.

---

### BUG-INS: Installer Missing Files After v9.0.0 Refactor
**Reported:** 2025-10-26 (v9.0.0)  
**Status:** Fixed

After v9.0.0 refactoring, the installer was looking for `ConvertEVTXtoJSON.sh` and `enable_threat_hunting_rules.py` which had been moved to the archive folder. The installer also wasn't copying the new `models.py` and `utils.py` modules that were created during the refactoring. This caused warnings during installation: "WARNING: ✗ ConvertEVTXtoJSON.sh not found" and "enable_threat_hunting_rules.py: [Errno 2] No such file or directory". New installations would fail to copy critical application files.

**Fixed:** 2025-10-26 (v9.0.1) - Updated installer file list to include models.py and utils.py, removed archived files from copy list, removed enable_threat_hunting_rules.py script call (rules now enabled via SIGMA import).

---

## Bug Tracking Guidelines

**Reporting a Bug:**
- Date and version when discovered
- Simple paragraph describing the issue
- Include what's broken and the impact

**Updating When Fixed:**
- Add "Fixed: YYYY-MM-DD (vX.X.X)" line
- Include brief description of the fix
- Only mark as fixed when user confirms it works

**Status Values:**
- **Open** - Bug confirmed, awaiting fix
- **Fixed** - Bug resolved and deployed (user confirmed)

---

**Maintained By:** Development Team  
**Updated:** After each bug report or fix confirmation
