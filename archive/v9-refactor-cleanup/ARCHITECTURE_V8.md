# caseScope v8.0 - Sequential File Processing Architecture

## Problem Statement

**Current (v7.x) - PARALLEL processing causes database locks:**
```
Worker 1: Index File A → [release] → SIGMA File B → [release] → IOC File A
Worker 2: Index File B → [release] → SIGMA File A → [release] → IOC File B
↓
Multiple workers updating same database tables simultaneously
↓
Database locks, transaction rollbacks, failed files
```

**Goal (v8.0) - SEQUENTIAL processing eliminates overlaps:**
```
Worker 1: File A [Index → SIGMA → IOC] → [release]
Worker 2: File B [Index → SIGMA → IOC] → [release]
↓
One worker owns one file completely
↓
No overlaps, no database locks
```

---

## New Architecture

### Master Task: `process_file_complete`

**Single entry point for all file processing:**

```python
@celery_app.task(bind=True, name='tasks.process_file_complete')
def process_file_complete(self, file_id, operation='full'):
    """
    Master task - processes file from start to finish without releasing worker
    
    Args:
        file_id: CaseFile ID
        operation: 'full', 'reindex', 'sigma_only', 'ioc_only'
    
    Workflow:
        1. Check if file exists
        2. Determine file type (EVTX vs NDJSON)
        3. Execute operation type:
           - full/reindex: Count → Index → SIGMA → IOC
           - sigma_only: SIGMA → IOC
           - ioc_only: IOC
        4. Update status at each step
        5. Handle errors gracefully
        6. Mark completed/failed
        7. Release worker
    """
```

### Helper Functions (Not Celery Tasks)

**Extract core logic into callable functions:**

```python
# Counting
def _count_evtx_events_internal(file_path) → int
def _count_ndjson_events_internal(file_path) → int

# Indexing  
def _index_evtx_events_internal(file_id, file_path, index_name) → dict
def _index_ndjson_events_internal(file_id, file_path, index_name) → dict

# SIGMA
def _process_sigma_rules_internal(file_id, file_path, index_name) → dict

# IOC
def _hunt_iocs_internal(file_id, index_name) → dict
```

### Queue Management

**Celery configuration:**
```python
# celery_app.py
worker_prefetch_multiplier = 1  # Process one task at a time
worker_concurrency = 2  # Max 2 workers
```

**Status-based queueing:**
```python
# Before queuing - check active tasks
active_tasks = count tasks with status in ['Estimating', 'Indexing', 'SIGMA Hunting', 'IOC Hunting']

if active_tasks >= 2:
    file.indexing_status = 'Queued'
    # Don't queue task yet
else:
    file.indexing_status = 'Queued'
    queue process_file_complete(file_id, operation)
```

---

## Operation Types

### 1. Full Processing (New Upload)
```
Queued → Estimating → Indexing → SIGMA Hunting → IOC Hunting → Completed
```

### 2. Re-index
```
Clear all → Queued → Estimating → Indexing → SIGMA Hunting → IOC Hunting → Completed
```

### 3. Re-run SIGMA Only
```
Clear SIGMA → Queued → SIGMA Hunting → IOC Hunting → Completed
```

### 4. Re-hunt IOCs Only
```
Clear IOC → Queued → IOC Hunting → Completed
```

---

## Benefits

1. ✅ **No database locks** - One worker owns one file completely
2. ✅ **Predictable** - Sequential processing, clear status progression
3. ✅ **Reliable** - Worker failure only affects one file
4. ✅ **Efficient** - No context switching between files
5. ✅ **Simple** - One task does everything, not 4 separate tasks
6. ✅ **Maintainable** - Helper functions are testable
7. ✅ **Scalable** - Add more workers without database contention

---

## Migration Path

1. Create new `process_file_complete` master task
2. Extract helpers from existing tasks
3. Keep old tasks for backwards compatibility (deprecate later)
4. Update upload/re-index/re-run endpoints to use new master task
5. Set Celery concurrency limits
6. Test with single file, then bulk operations
7. Monitor for database lock errors (should be zero)

---

## Rollback Plan

Backup branch: `backup-pre-v8-sequential-processing`

If issues occur:
```bash
git checkout backup-pre-v8-sequential-processing
```

