# caseScope Bug Tracking

**Last Updated:** 2025-10-26  
**Current Version:** v9.0.1

Simple bug tracking - one paragraph per bug, updated with fix date/version when resolved.

---

## Open Bugs

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

### BUG-004: Installer Missing Files After v9.0.0 Refactor
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
