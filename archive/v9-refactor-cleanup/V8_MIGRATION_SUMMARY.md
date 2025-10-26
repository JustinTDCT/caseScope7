# V8.0 Migration - Sequential Processing Architecture

## Status: IN PROGRESS

**Backup Branch:** `backup-pre-v8-sequential-processing`

---

## ✅ COMPLETED:

### 1. Helper Functions Added to tasks.py (Lines 2479-2865)

**Indexing Helpers:**
- `_index_evtx_helper()` - Index EVTX file to OpenSearch
- `_index_ndjson_helper()` - Index NDJSON file to OpenSearch  
- `_count_evtx_events_helper()` - Count events in EVTX
- `_count_ndjson_events_helper()` - Count events in NDJSON

**Processing Helpers:**
- `_process_sigma_helper()` - Run SIGMA rules with Chainsaw
- `_hunt_iocs_helper()` - Hunt for IOCs in indexed events
- `_find_matching_rule()` - Find SIGMA rule in database

**Data Clearing Helpers:**
- `_clear_all_file_data()` - Clear everything (reindex)
- `_clear_sigma_data()` - Clear only SIGMA (re-run rules)
- `_clear_ioc_data()` - Clear only IOC (re-hunt)

### 2. Master Task Added (Lines 2930-3050+)

`process_file_complete(file_id, operation='full|reindex|sigma_only|ioc_only')`

**Sequential Flow:**
```
1. Validate file exists
2. Determine file type (EVTX vs NDJSON)
3. Clear data based on operation type
4. Count events (if full/reindex)
5. Index events (if full/reindex)
6. Process SIGMA (if EVTX and not ioc_only)
7. Hunt IOCs (always)
8. Mark Completed
9. Release worker
```

**Benefits:**
- ✅ One worker owns one file completely
- ✅ No database locks from parallel processing
- ✅ No transaction rollbacks
- ✅ Predictable status progression
- ✅ Audit logs for each step
- ✅ Worker failure isolated to single file

### 3. Celery Configuration Updated

**celery_app.py:**
- Already has `worker_prefetch_multiplier=1` ✅
- Already has `worker_concurrency=2` (in systemd) ✅
- Added v8.0 documentation comment

---

## ⏳ REMAINING WORK:

### 4. Update main.py Queuing Logic

**Locations to update:**

| Location | Current Task | New Task | Operation |
|----------|--------------|----------|-----------|
| File upload (after save) | `start_file_indexing` | `process_file_complete` | `'full'` |
| Re-index single file | `start_file_indexing` | `process_file_complete` | `'reindex'` |
| Re-index All Files (bulk) | `start_file_indexing` | `process_file_complete` | `'reindex'` |
| Re-run Rules single | `process_sigma_rules` | `process_file_complete` | `'sigma_only'` |
| Re-run All Rules (bulk) | `process_sigma_rules` | `process_file_complete` | `'sigma_only'` |
| Re-hunt IOCs single | `hunt_iocs_for_file` | `process_file_complete` | `'ioc_only'` |
| Re-hunt All IOCs (bulk) | `hunt_iocs_for_file` | `process_file_complete` | `'ioc_only'` |

### 5. Test Each Operation

- Single file upload
- Re-index single file
- Re-index All Files
- Re-run Rules single
- Re-run All Rules  
- Re-hunt IOCs single
- Re-hunt All IOCs

### 6. Validate

- No database lock errors
- No transaction rollbacks
- Proper status progression
- Audit logs working
- All files complete successfully

---

## ⚠️ RISK ASSESSMENT:

**Low Risk:**
- Helper functions are extracted from proven code ✅
- Master task logic is straightforward ✅
- Celery config already optimized ✅

**Medium Risk:**
- main.py has 7+ locations to update
- Each location needs careful testing
- One mistake breaks uploads

**Mitigation:**
- Update one endpoint at a time
- Test after each change
- Keep old tasks for rollback
- Use backup branch if needed

---

## NEXT STEPS:

1. Update main.py queuing logic (7 locations)
2. Compile and validate
3. Commit v8.0.0
4. Deploy to server
5. Test single file upload
6. Test all bulk operations
7. Monitor logs for database locks (should be zero)

---

**Current Token Usage:** ~253k / 1M (25%)
**Estimated Remaining:** ~50k for main.py updates + testing

