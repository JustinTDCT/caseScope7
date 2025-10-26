# caseScope Bug Tracking

**Last Updated:** 2025-10-26  
**Current Version:** v9.0.0

This document tracks known bugs and issues in caseScope that need to be fixed.

---

## Critical Bugs (Fix Immediately)

### BUG-001: Search Date Sorting Not Working
**Status:** Open  
**Priority:** Critical  
**Reported:** 2025-10-26  
**Affects:** All search pages (simple, advanced, emergency)  

**Description:**  
Date sorting (newest→oldest, oldest→newest) is not working correctly in search results. Additionally, sort order does not persist across pagination.

**Expected Behavior:**
- User selects "Oldest → Newest" sort
- System sorts ALL events in the case by timestamp (not just the 10K displayed)
- Displays first 10,000 events in oldest-to-newest order
- Pagination maintains sort order (page 2 shows events 10,001-20,000 in same order)
- For 20K events spanning 10/23-10/25:
  - Oldest→Newest: Page 1 shows 10/23 events, page 2 shows 10/24-10/25 events
  - Newest→Oldest: Page 1 shows 10/25 events, page 2 shows 10/24-10/23 events

**Actual Behavior:**
- Sort order does not apply correctly
- Pagination breaks sort order (page 2 shows random order)
- Events appear in inconsistent order

**Root Cause:**
OpenSearch query is not properly applying sort parameter, or pagination is not maintaining sort state.

**Impact:**
- High - Analysts cannot review events chronologically
- Timeline analysis is impossible
- Critical for incident investigation workflow

**Files Affected:**
- `main.py` - Search route functions (lines ~7000-9000)
- OpenSearch query building functions
- Frontend JavaScript for sort controls

**Steps to Reproduce:**
1. Open a case with 20K+ events spanning multiple days
2. Go to Simple Search
3. Select "Oldest → Newest" sort
4. Observe event order on page 1
5. Click "Next Page" for page 2
6. Observe events are not in chronological order

**Proposed Fix:**
```python
# In search query building:
query_body = {
    "query": { ... },
    "sort": [
        {"@timestamp": {"order": "asc"}}  # or "desc" for newest first
    ],
    "size": 10000,
    "from": (page - 1) * 10000  # For pagination
}

# Store sort order in session:
session['search_sort_order'] = sort_order  # 'asc' or 'desc'

# Apply sort order from session on pagination:
sort_order = session.get('search_sort_order', 'desc')
```

**Testing Checklist:**
- [ ] Sort works on simple search
- [ ] Sort works on advanced search
- [ ] Sort works on emergency search
- [ ] Sort persists across pagination
- [ ] Page 2 continues sort order from page 1
- [ ] Verify with 20K+ event dataset
- [ ] Test oldest→newest sort
- [ ] Test newest→oldest sort

---

### BUG-002: Date Range Filtering Not Working
**Status:** Open  
**Priority:** Critical  
**Reported:** 2025-10-26  
**Affects:** All search pages with date range filters  

**Description:**  
Date range filtering does not work in any form. Users cannot filter events by time range (24h, 7d, 30d, custom range).

**Expected Behavior:**
- User selects "Last 24 hours" filter
- System queries only events with `@timestamp` in last 24 hours
- Results show only events from selected time range
- Custom date range allows user to specify exact start/end dates
- Time range filter combines with search query (AND condition)

**Actual Behavior:**
- Date range filter has no effect
- All events are returned regardless of selected time range
- Custom date picker doesn't filter results

**Root Cause:**
OpenSearch query is not including date range filter in the query body, or date parsing is incorrect.

**Impact:**
- High - Analysts cannot narrow down investigation to specific time periods
- All search results include entire case timeline
- Performance impact (searching all events instead of subset)

**Files Affected:**
- `main.py` - `build_time_filter_query()` function (around line 873)
- Search route handlers
- Frontend date picker components

**Steps to Reproduce:**
1. Open a case with events spanning multiple days
2. Go to Search page
3. Select "Last 24 hours" from time range dropdown
4. Submit search query
5. Observe results include events older than 24 hours

**Current Code Issue:**
```python
# Line 873 in main.py:
def build_time_filter_query(time_range, custom_start=None, custom_end=None):
    """Build OpenSearch time filter query"""
    # This function may not be correctly constructing the date filter
    # or may not be called at all in search queries
```

**Proposed Fix:**
```python
def build_time_filter_query(time_range, custom_start=None, custom_end=None):
    """Build OpenSearch time filter query"""
    from datetime import datetime, timedelta
    
    now = datetime.utcnow()
    
    time_filters = {
        '24h': now - timedelta(hours=24),
        '7d': now - timedelta(days=7),
        '30d': now - timedelta(days=30),
        '90d': now - timedelta(days=90),
    }
    
    if time_range == 'custom' and custom_start and custom_end:
        # User-specified custom range
        return {
            "range": {
                "@timestamp": {
                    "gte": custom_start.isoformat(),
                    "lte": custom_end.isoformat()
                }
            }
        }
    elif time_range in time_filters:
        # Predefined time range
        start_time = time_filters[time_range]
        return {
            "range": {
                "@timestamp": {
                    "gte": start_time.isoformat()
                }
            }
        }
    else:
        # No time filter (all time)
        return None

# In search query building:
query_body = {
    "query": {
        "bool": {
            "must": [
                # Search query
                { ... },
            ],
            "filter": []
        }
    }
}

# Add time filter if provided:
time_filter = build_time_filter_query(time_range, custom_start, custom_end)
if time_filter:
    query_body["query"]["bool"]["filter"].append(time_filter)
```

**Testing Checklist:**
- [ ] "Last 24 hours" filter works
- [ ] "Last 7 days" filter works
- [ ] "Last 30 days" filter works
- [ ] "Last 90 days" filter works
- [ ] Custom date range filter works
- [ ] Time filter combines with search query
- [ ] Time filter works with sort order
- [ ] Time filter persists across pagination
- [ ] Test with timezone edge cases
- [ ] Verify with multi-day datasets

---

## High Priority Bugs

### BUG-003: Installer Missing Files After v9.0.0 Refactor
**Status:** Fixed  
**Priority:** High  
**Reported:** 2025-10-26  
**Fixed In:** v9.0.1 (pending)  

**Description:**  
After v9.0.0 refactoring, installer looks for `ConvertEVTXtoJSON.sh` and `enable_threat_hunting_rules.py` which were moved to archive.

**Fix Applied:**
- Removed `ConvertEVTXtoJSON.sh` from installer file list
- Added `models.py` and `utils.py` to installer file list
- Removed call to `enable_threat_hunting_rules.py` (rules now enabled via SIGMA import)

**Files Modified:**
- `install.sh` - Updated file copy list and removed archived script calls

---

## Medium Priority Bugs

_(None currently reported)_

---

## Low Priority Bugs

_(None currently reported)_

---

## Bug Reporting Template

When reporting a new bug, please use this template:

```markdown
### BUG-XXX: [Short Description]
**Status:** Open  
**Priority:** Critical / High / Medium / Low  
**Reported:** YYYY-MM-DD  
**Affects:** [Component/Page affected]  

**Description:**  
[Detailed description of the bug]

**Expected Behavior:**  
[What should happen]

**Actual Behavior:**  
[What actually happens]

**Root Cause:**  
[If known, what's causing the bug]

**Impact:**  
[How this affects users]

**Files Affected:**  
- filename.py - specific functions or lines

**Steps to Reproduce:**  
1. Step one
2. Step two
3. Observe issue

**Proposed Fix:**  
[Code snippets or approach to fix]

**Testing Checklist:**  
- [ ] Test case 1
- [ ] Test case 2
```

---

## Bug Status Definitions

- **Open:** Bug confirmed and awaiting fix
- **In Progress:** Developer actively working on fix
- **Fixed:** Fix implemented and tested
- **Verified:** Fix deployed and verified in production
- **Closed:** Bug resolved and closed

## Priority Definitions

- **Critical:** System broken, blocks core functionality
- **High:** Significant feature broken, impacts workflow
- **Medium:** Feature partially broken, workaround exists
- **Low:** Minor issue, cosmetic, or edge case

---

**Maintained By:** Development Team  
**Review Frequency:** Daily during active development  
**Triage Process:** New bugs reviewed within 24 hours

