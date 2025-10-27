# Code Consolidation Plan v9.7.0

## Executive Summary
After deep analysis, found significant code duplication across 7 core files:
- **Total functions analyzed**: 159
- **Duplicate function names**: 3 (with multiple implementations each)
- **Estimated redundant code**: ~5,000 lines (25% of codebase)
- **Target reduction**: main.py (-35%), tasks.py (-43%)

## Phase 1: Utility Consolidation (IMMEDIATE - LOW RISK) ✅

### Duplicate Utilities Found:
1. **`sanitize_filename()`** - 3 copies
   - `utils.py` (line 88) - KEEP (security-focused, path traversal protection)
   - `tasks.py` (line 275) - REMOVE (for OpenSearch index names)
   - `tasks.py` (line 1328) - REMOVE (duplicate)

2. **`make_index_name()`** - 2 copies
   - `utils.py` (line 115) - KEEP (most complete)
   - `tasks.py` (line 294) - REMOVE

3. **`flatten_event()`** - 2 copies
   - `tasks.py` (line 468) - KEEP (has max_depth protection)
   - `tasks.py` (line 1340) - REMOVE (simpler version)

### Actions:
```python
# In tasks.py, add at top:
from utils import sanitize_filename, make_index_name

# Remove duplicate definitions in tasks.py:
# - Lines 275-292 (sanitize_filename v1)
# - Lines 294-317 (make_index_name)
# - Lines 1328-1337 (sanitize_filename v2)
# - Lines 1340-1370 (flatten_event v2)
```

**Impact**: -100 lines from tasks.py, cleaner imports

---

## Phase 2: Deprecate Old Upload Code (AFTER v9.6 STABLE - MEDIUM RISK)

### OLD Upload System (main.py):
- `upload_files()` POST handler - Lines ~1182-1361 (~180 lines)
- `extract_and_process_zip()` - ~150 lines
- **Status**: Replaced by v9.6.0 unified pipeline

### NEW Upload System:
- `upload_pipeline.py` - Staging, extraction, dedup, filtering
- `upload_integration.py` - Flask route handlers
- **Status**: Active since v9.6.1

### Deprecated Files:
- `local_uploads.py` - Check if still used, likely superseded

### Actions (after 1 week stability):
```python
# main.py: Remove old upload_files() POST logic (keep GET for form)
# main.py: Remove extract_and_process_zip()
# tasks.py: Remove process_local_uploads() if unused
# Delete: local_uploads.py (if confirmed unused)
```

**Impact**: -400 lines from main.py

---

## Phase 3: Deprecate Old Indexing Code (AFTER v9.7 STABLE - HIGH RISK)

### OLD Indexing System (tasks.py):
- `index_evtx_file(self, file_id)` - Full Celery task
- `_index_evtx_helper()` - Helper function
- **Status**: Replaced by file_processing.py modular architecture (v9.5.0)

### NEW Indexing System:
- `file_processing.py::index_file()` - Modular indexing
- `tasks.py::process_file_v9()` - Orchestrator
- **Status**: Active since v9.5.0

### Actions (after proving v9.5+ stable):
```python
# tasks.py: Remove index_evtx_file()
# tasks.py: Remove _index_evtx_helper()
# tasks.py: Keep bulk_index_events() (utility function)
```

**Impact**: -300 lines from tasks.py

---

## Phase 4: Modular Architecture (FUTURE - MAJOR REFACTOR)

### Create Dedicated Modules:

**indexing.py**
```python
# All OpenSearch indexing logic
- index_file()
- bulk_index_events()
- create_index_mapping()
```

**sigma_processing.py**
```python
# SIGMA/Chainsaw integration
- process_sigma_rules()
- parse_chainsaw_output()
- create_violation_records()
```

**ioc_hunting.py**
```python
# IOC hunting logic
- hunt_iocs()
- search_ioc_in_events()
- create_ioc_matches()
```

**file_operations.py**
```python
# File handling utilities
- hash_file()
- extract_zip()
- convert_evtx_to_json()
- count_events()
```

### Actions:
1. Extract functions from tasks.py
2. Extract functions from file_processing.py
3. Update imports across codebase
4. Test thoroughly

**Impact**: 
- main.py: 12,268 → ~8,000 lines
- tasks.py: ~3,500 → ~2,000 lines
- New modules: +2,000 lines
- **Net reduction**: -5,000 lines (-25%)

---

## Implementation Timeline

### Week 1: Phase 1 (Utility Consolidation)
- ✅ Analyze duplication
- 🔄 Consolidate utils
- 🔄 Update imports
- 🔄 Test + Deploy v9.7.0

### Week 2-3: Monitor v9.6.x Stability
- Monitor upload pipeline
- Monitor file processing
- Collect metrics

### Week 4: Phase 2 (Remove Old Upload Code)
- Remove old upload handlers
- Remove extract_and_process_zip()
- Delete local_uploads.py
- Test + Deploy v9.8.0

### Month 2: Phase 3 (Remove Old Indexing)
- Remove old index_evtx_file()
- Consolidate helpers
- Test + Deploy v9.9.0

### Month 3: Phase 4 (Modular Architecture)
- Create new modules
- Extract and reorganize
- Comprehensive testing
- Deploy v10.0.0

---

## Success Metrics

### Code Quality:
- ✅ Reduce duplicate functions from 3 to 0
- ✅ Reduce main.py by 35%
- ✅ Reduce tasks.py by 43%
- ✅ Improve maintainability score

### Reliability:
- ✅ Fewer bugs from inconsistent implementations
- ✅ Easier debugging (single source of truth)
- ✅ Faster onboarding for contributors

### Performance:
- ✅ Faster startup (fewer imports)
- ✅ Better memory usage (no duplicate code in memory)
- ✅ Easier profiling and optimization

---

## Rollback Plan

Each phase will be a separate git commit/tag:
- `v9.7.0` - Phase 1 (utils consolidation)
- `v9.8.0` - Phase 2 (remove old uploads)
- `v9.9.0` - Phase 3 (remove old indexing)
- `v10.0.0` - Phase 4 (modular architecture)

If issues arise, can revert to previous version.

---

## Risk Assessment

| Phase | Risk Level | Mitigation |
|-------|-----------|------------|
| Phase 1 | **LOW** | Functions are utilities, well-tested |
| Phase 2 | **MEDIUM** | Need 1 week of v9.6 stability proof |
| Phase 3 | **HIGH** | Need extensive testing, rollback plan |
| Phase 4 | **VERY HIGH** | Major refactor, comprehensive QA needed |

---

Generated: 2025-10-27
Status: READY FOR PHASE 1 IMPLEMENTATION

