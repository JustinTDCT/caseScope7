# v9.6.0 Integration Guide

## Overview
This guide shows how to integrate the new unified upload pipeline into `main.py`.

## Files Added
- `upload_pipeline.py` - Core pipeline logic
- `upload_integration.py` - Flask integration helpers
- `V96_INTEGRATION_GUIDE.md` - This file

## Integration Steps

### Step 1: Add Import at Top of main.py

```python
# Add after existing imports (around line 20-30)
from upload_integration import (
    handle_http_upload_v96,
    handle_bulk_upload_v96, 
    handle_chunked_upload_finalize_v96
)
```

### Step 2: Replace HTTP Upload Route

Find the `@app.route('/upload', methods=['GET', 'POST'])` route (around line 1114).

**OLD CODE** (lines ~1117-1350):
```python
def upload_files():
    """File upload for active case"""
    # ... existing complex upload logic ...
```

**NEW CODE**:
```python
def upload_files():
    """File upload for active case (v9.6.0 unified pipeline)"""
    clear_search_filters()
    
    if request.method == 'GET':
        # Render upload page (keep existing GET logic)
        cases = db.session.query(Case).filter_by(is_closed=False).order_by(Case.created_at.desc()).all()
        return render_template('upload.html', cases=cases)
    
    # POST: Handle file upload via v9.6.0 pipeline
    files = request.files.getlist('files')
    if not files:
        flash('No files selected', 'error')
        return redirect(url_for('upload_files'))
    
    result = handle_http_upload_v96(
        app=app,
        db=db,
        Case=Case,
        CaseFile=CaseFile,
        SkippedFile=SkippedFile,
        celery_app=celery_app,
        current_user=current_user,
        uploaded_files=files
    )
    
    if result.get_json()['success']:
        flash(result.get_json()['message'], 'success')
    else:
        flash(result.get_json()['error'], 'error')
    
    return redirect(url_for('case_dashboard', case_id=request.form.get('case_id')))
```

### Step 3: Replace Chunked Upload Finalize

Find the `@app.route('/api/upload-finalize', methods=['POST'])` route (around line 1419).

**OLD CODE** (lines ~1421-1630):
```python
def upload_finalize():
    """Finalize chunked upload by assembling chunks into complete file"""
    # ... existing assembly and processing logic ...
```

**NEW CODE**:
```python
def upload_finalize():
    """Finalize chunked upload (v9.6.0 unified pipeline)"""
    try:
        data = request.get_json()
        upload_id = data.get('upload_id')
        filename = data.get('filename')
        case_id = data.get('case_id')
        
        if not all([upload_id, filename, case_id]):
            return jsonify({'success': False, 'error': 'Missing required fields'}), 400
        
        chunks_folder = f"/tmp/chunks_{upload_id}"
        
        return handle_chunked_upload_finalize_v96(
            app=app,
            db=db,
            Case=Case,
            CaseFile=CaseFile,
            SkippedFile=SkippedFile,
            celery_app=celery_app,
            current_user=current_user,
            upload_id=upload_id,
            filename=filename,
            case_id=int(case_id),
            chunks_folder=chunks_folder
        )
        
    except Exception as e:
        app.logger.error(f"[Upload Finalize] Error: {e}")
        return jsonify({'success': False, 'error': str(e)}), 500
```

### Step 4: Replace Local/Bulk Upload Handler

Find the `_process_local_uploads_with_progress` function (around line 2696).

**OLD CODE**:
```python
def _process_local_uploads_with_progress(task_id, case_id, local_folder):
    """v9.4.8: Background function to process local uploads..."""
    with app.app_context():
        try:
            from local_uploads import process_local_uploads_two_phase
            # ... existing logic ...
```

**NEW CODE**:
```python
def _process_local_uploads_with_progress(task_id, case_id, local_folder):
    """v9.6.0: Background function using unified pipeline"""
    with app.app_context():
        try:
            result = handle_bulk_upload_v96(
                app=app,
                db=db,
                Case=Case,
                CaseFile=CaseFile,
                SkippedFile=SkippedFile,
                celery_app=celery_app,
                case_id=case_id,
                local_folder=local_folder
            )
            
            # Update Redis with final status
            import redis
            r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
            r.setex(f'local_upload_progress:{task_id}', 3600, json.dumps({
                'status': 'complete' if result['success'] else 'error',
                'files_queued': result.get('files_queued', 0),
                'duplicates_skipped': result.get('duplicates_skipped', 0),
                'zero_events_skipped': result.get('zero_events_skipped', 0),
                'message': result['message']
            }))
            
        except Exception as e:
            app.logger.error(f"[Local Upload] Error: {e}")
            import redis, json
            r = redis.Redis(host='localhost', port=6379, db=0, decode_responses=True)
            r.setex(f'local_upload_progress:{task_id}', 3600, json.dumps({
                'status': 'error',
                'message': str(e)
            }))
```

## Testing Checklist

After making these changes:

- [ ] HTTP single file upload
- [ ] HTTP multiple file upload
- [ ] HTTP ZIP file upload
- [ ] Chunked upload (large files)
- [ ] Bulk folder upload
- [ ] Duplicate detection (re-upload same file)
- [ ] Zero-event file handling
- [ ] Stats tiles update correctly
- [ ] No errors in logs

## Rollback Plan

If issues occur, revert to the commit before these changes:
```bash
git log --oneline | head -5  # Find commit before v9.6.0
git revert <commit-hash>
```

## Benefits of v9.6.0

✅ Single staging area for all uploads  
✅ No race conditions  
✅ No duplicate processing  
✅ Clean duplicate detection  
✅ Proper 0-event file archiving  
✅ Accurate statistics  
✅ Simplified code paths  

## Support

If you encounter issues, check:
1. `/opt/casescope/logs/gunicorn.log` - Main app logs
2. `/opt/casescope/logs/celery_worker.log` - Worker logs
3. `journalctl -u casescope-web -f` - Live web service logs
4. `journalctl -u casescope-worker -f` - Live worker logs

