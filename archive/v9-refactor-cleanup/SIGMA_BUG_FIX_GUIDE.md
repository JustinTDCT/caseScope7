# SIGMA Filtering Bug - Fix Guide

**Version:** v7.40.0  
**Issue:** SIGMA Only/SIGMA or IOC/SIGMA + IOC filters show "Unknown Event" and "N/A" for all fields  
**Status:** Fix committed in v7.39.2, needs testing

---

## 🔍 Problem Summary

### What's Broken
1. ❌ **SIGMA Only** - Shows "Unknown Event", "N/A" for Event ID, Timestamp, Computer, Source File
2. ❌ **SIGMA or IOC** - Same issue as SIGMA Only
3. ❌ **SIGMA + IOC (Both)** - Returns no results despite overlapping events
4. ✅ **IOC Only** - Works correctly

### Debug Output (from v7.39.1)
```
[Search] DEBUG - Threat filter sigma result keys: ['sigma_detections', 'has_violations', 'violation_count']
[Search] DEBUG - NO _casescope_metadata field!
[Search] DEBUG - Document ID: c9cea28c1b7ae68d
```

**Documents only have 3 fields** - missing ALL event data!

---

## 🎯 Root Cause

**Type Mismatch in Document ID Generation**

**The Problem:**
- EventRecordID from XML: `123` (int)
- EventRecordID from Chainsaw: `"123"` (string) or int
- Python hashing: `sha256("56_123")` ≠ `sha256("56_" + str(123))`

**The Result:**
- Indexing creates doc with ID: `abc123def456`
- SIGMA enrichment tries to update doc with ID: `xyz789ghi012` (different!)
- OpenSearch `doc_as_upsert: True` creates **NEW document** with only SIGMA fields
- Original document remains untouched
- SIGMA-only document returned by searches

**Identical to v7.32.2 bug** - same symptoms, same root cause, different trigger

---

## ✅ The Fix (v7.39.2)

**6 str() conversions** added to ensure consistent type handling:

1. **Line 522** (bulk_index_events): `str(record_num)` before hashing
2. **Line 345** (enrich_events_with_detections): `str(record_num)` before hashing
3. **Line 697** (index_evtx_file): Convert event_record_id to string
4. **Line 707** (metadata): Store record_number as string
5. **Line 1042** (process_sigma_rules): Convert EventRecordID to string
6. **Line 1090** (detections dict): Use string keys

---

## 🧪 Testing Steps

### Step 1: Restart Worker (CRITICAL)
```bash
sudo systemctl restart casescope-worker
sudo systemctl status casescope-worker
```

**Why:** Worker must pick up new code with str() conversions

### Step 2: Re-run SIGMA Rules (One File)
1. Go to **Files** page
2. Find a file with SIGMA violations
3. Click **"⚡ Re-run Rules"**
4. Wait for completion

**Why:** Re-running rules will re-enrich with correct doc IDs

### Step 3: Check Worker Logs
```bash
sudo journalctl -u casescope-worker -f --since "1 minute ago"
```

**Look for (if fix is working):**
```
[SIGMA Enrichment] file_id=56, record_num=12345, doc_id=abc123def456
[SIGMA Enrichment] ✓ Successfully enriched 100 events with NO errors
```

**Red flags (if fix not working):**
```
[SIGMA Enrichment] Bulk update had errors!
[SIGMA Enrichment] Update error: document_missing_exception
```

### Step 4: Test SIGMA Filtering
1. Go to **Search** page
2. Select **"SIGMA Only"** from Threat Filtering dropdown
3. Click **Search**
4. Check if results show:
   - ✅ Event ID (not "N/A")
   - ✅ Timestamp (not "N/A")
   - ✅ Computer name (not "N/A")
   - ✅ Event Type (not "Unknown Event")

### Step 5: Test Combined Filters
1. Test **"SIGMA or IOC"** - should show events
2. Test **"SIGMA + IOC (Both)"** - should show overlapping events

---

## 🔧 If Fix Doesn't Work

### Scenario A: Worker Logs Show Errors
**Symptom:** `document_missing_exception` or other update errors

**Action:**
1. Copy error messages
2. Check if doc_id from enrichment matches actual OpenSearch doc _id
3. May need to investigate further

### Scenario B: No Debug Output in Logs
**Symptom:** No "[SIGMA Enrichment]" messages in worker logs

**Action:**
1. Worker didn't pick up new code
2. Try: `sudo systemctl daemon-reload && sudo systemctl restart casescope-worker`
3. Check which version of tasks.py worker is using

### Scenario C: Still Shows 3 Fields
**Symptom:** SIGMA results still only have `['sigma_detections', 'has_violations', 'violation_count']`

**Action:**
1. These are OLD orphaned documents
2. Need to **Re-index** (not just Re-run Rules)
3. Re-index creates fresh documents with v7.39.2 code

---

## 📊 Expected Behavior After Fix

### For Newly Processed Files
✅ Upload → Index → SIGMA → Enrichment updates existing docs
✅ SIGMA filtering shows complete event data

### For Existing Files
⚠️ Old orphaned SIGMA-only documents remain
✅ Re-run Rules → Re-enriches with correct doc IDs
✅ OR Re-index → Creates fresh documents

---

## 🎯 Success Criteria

1. ✅ Worker logs show successful enrichment (no errors)
2. ✅ SIGMA Only filter displays Event ID, Timestamp, Computer
3. ✅ SIGMA or IOC filter returns results
4. ✅ SIGMA + IOC (Both) filter finds overlapping events
5. ✅ Event details expand and show full data

---

## 📝 Notes

- **Fix is in v7.39.2** - Already committed
- **Requires worker restart** - Must pick up new code
- **Existing files** - May need Re-run Rules or Re-index
- **New files** - Will work immediately after worker restart

---

## 🚀 Quick Test Command

```bash
# On server
sudo systemctl restart casescope-worker
# Wait 5 seconds, then check status
sudo systemctl status casescope-worker

# Watch worker logs during Re-run Rules
sudo journalctl -u casescope-worker -f
```

Then in UI:
1. Files → Re-run Rules on one file
2. Wait for completion
3. Search → SIGMA Only
4. Check if Event ID/Timestamp/Computer display correctly

---

**Current Version:** v7.40.0 (includes v7.39.2 SIGMA fix)  
**Backup Available:** `backup-pre-refactor-v7.36.7`  
**Status:** Ready for testing

