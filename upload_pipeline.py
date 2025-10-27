#!/usr/bin/env python3
"""
UNIFIED UPLOAD PIPELINE (v9.6.0)

Single staging area for ALL uploads (HTTP + Bulk)
Clean, linear workflow with proper duplicate detection
"""

import os
import sys
import shutil
import zipfile
import json
import hashlib
import subprocess
import tempfile
from typing import List, Dict, Tuple, Optional
from datetime import datetime

# Will be imported when called from Flask
logger = None


def init_logger(flask_logger):
    """Initialize logger from Flask app"""
    global logger
    logger = flask_logger


# ============================================================================
# STAGING AREA MANAGEMENT
# ============================================================================

def get_staging_path(case_id: int) -> str:
    """Get staging directory for a case"""
    return f"/opt/casescope/staging/{case_id}"


def get_final_upload_path(case_id: int) -> str:
    """Get final upload directory for a case"""
    return f"/opt/casescope/uploads/{case_id}"


def ensure_staging_exists(case_id: int) -> str:
    """Create staging directory if it doesn't exist"""
    staging_dir = get_staging_path(case_id)
    os.makedirs(staging_dir, exist_ok=True)
    return staging_dir


def clear_staging(case_id: int):
    """Clear all files from staging directory"""
    staging_dir = get_staging_path(case_id)
    if os.path.exists(staging_dir):
        shutil.rmtree(staging_dir)
        os.makedirs(staging_dir, exist_ok=True)
    logger.info(f"[STAGING] Cleared: {staging_dir}")


# ============================================================================
# STEP 1: STAGE FILES (HTTP or Bulk)
# ============================================================================

def stage_http_upload(case_id: int, uploaded_file, filename: str) -> Dict:
    """
    Stage a file from HTTP upload
    
    Args:
        case_id: Case ID
        uploaded_file: Flask file object
        filename: Original filename
    
    Returns:
        dict: {'success': bool, 'file_path': str, 'message': str}
    """
    staging_dir = ensure_staging_exists(case_id)
    dest_path = os.path.join(staging_dir, filename)
    
    try:
        uploaded_file.save(dest_path)
        file_size = os.path.getsize(dest_path)
        logger.info(f"[STAGE] HTTP upload: {filename} ({file_size:,} bytes)")
        
        return {
            'success': True,
            'file_path': dest_path,
            'file_size': file_size,
            'message': f'Staged: {filename}'
        }
    except Exception as e:
        logger.error(f"[STAGE] Failed to stage {filename}: {e}")
        return {
            'success': False,
            'file_path': None,
            'file_size': 0,
            'message': f'Error: {str(e)}'
        }


def stage_bulk_upload(case_id: int, source_folder: str, cleanup_after: bool = True) -> Dict:
    """
    Stage files from bulk upload folder (e.g. /opt/casescope/local_uploads)
    
    Args:
        case_id: Case ID
        source_folder: Path to bulk upload folder
        cleanup_after: If True, delete original files after successful copy (default: True)
    
    Returns:
        dict: {'success': bool, 'files_staged': int, 'message': str}
    """
    staging_dir = ensure_staging_exists(case_id)
    
    if not os.path.exists(source_folder):
        return {
            'success': False,
            'files_staged': 0,
            'message': f'Source folder not found: {source_folder}'
        }
    
    files_staged = 0
    staged_files = []  # Track successfully staged files for cleanup
    
    for filename in os.listdir(source_folder):
        source_path = os.path.join(source_folder, filename)
        
        if not os.path.isfile(source_path):
            continue
        
        dest_path = os.path.join(staging_dir, filename)
        
        try:
            shutil.copy2(source_path, dest_path)
            files_staged += 1
            staged_files.append(source_path)
            logger.info(f"[STAGE] Bulk upload: {filename}")
        except Exception as e:
            logger.error(f"[STAGE] Failed to stage {filename}: {e}")
            continue
    
    # Cleanup: Delete originals after successful staging
    if cleanup_after and files_staged > 0:
        for source_path in staged_files:
            try:
                os.remove(source_path)
                logger.info(f"[CLEANUP] Removed: {os.path.basename(source_path)}")
            except Exception as e:
                logger.warning(f"[CLEANUP] Failed to remove {source_path}: {e}")
    
    return {
        'success': True,
        'files_staged': files_staged,
        'message': f'Staged {files_staged} files from bulk upload' + (' (originals cleaned up)' if cleanup_after else '')
    }


# ============================================================================
# STEP 2: EXTRACT ZIP FILES
# ============================================================================

def extract_zips_in_staging(case_id: int) -> Dict:
    """
    Extract all ZIP files in staging, prepend filenames, delete ZIPs
    
    Returns:
        dict: {
            'zips_processed': int,
            'files_extracted': int,
            'zips_deleted': int
        }
    """
    staging_dir = get_staging_path(case_id)
    stats = {
        'zips_processed': 0,
        'files_extracted': 0,
        'zips_deleted': 0
    }
    
    logger.info("="*80)
    logger.info("[EXTRACT] Starting ZIP extraction in staging")
    logger.info("="*80)
    
    # Find all ZIP files
    zip_files = [f for f in os.listdir(staging_dir) if f.lower().endswith('.zip')]
    
    if not zip_files:
        logger.info("[EXTRACT] No ZIP files found")
        return stats
    
    logger.info(f"[EXTRACT] Found {len(zip_files)} ZIP file(s)")
    
    for zip_filename in zip_files:
        zip_path = os.path.join(staging_dir, zip_filename)
        zip_name = os.path.splitext(zip_filename)[0]  # Remove .zip extension
        
        try:
            logger.info(f"[EXTRACT] Processing: {zip_filename}")
            
            with zipfile.ZipFile(zip_path, 'r') as zip_ref:
                for zip_info in zip_ref.filelist:
                    if zip_info.filename.lower().endswith(('.evtx', '.ndjson', '.json')):
                        # Extract to temp location
                        zip_ref.extract(zip_info, staging_dir)
                        original_path = os.path.join(staging_dir, zip_info.filename)
                        
                        # Create prefixed filename: "ZIPNAME_original.evtx"
                        original_name = os.path.basename(zip_info.filename)
                        prefixed_name = f"{zip_name}_{original_name}"
                        prefixed_path = os.path.join(staging_dir, prefixed_name)
                        
                        # Rename with prefix
                        shutil.move(original_path, prefixed_path)
                        stats['files_extracted'] += 1
                        
                        logger.info(f"[EXTRACT]   → {prefixed_name}")
                        
                        # Clean up nested directories from extraction
                        parent_dir = os.path.dirname(original_path)
                        while parent_dir != staging_dir and os.path.exists(parent_dir):
                            try:
                                if not os.listdir(parent_dir):
                                    os.rmdir(parent_dir)
                                    parent_dir = os.path.dirname(parent_dir)
                                else:
                                    break
                            except:
                                break
            
            # Delete ZIP after successful extraction
            os.remove(zip_path)
            stats['zips_deleted'] += 1
            stats['zips_processed'] += 1
            logger.info(f"[EXTRACT] ✓ Extracted {stats['files_extracted']} files, deleted ZIP")
            
        except Exception as e:
            logger.error(f"[EXTRACT] Failed to process {zip_filename}: {e}")
            continue
    
    logger.info("="*80)
    logger.info(f"[EXTRACT] Complete: {stats['zips_processed']} ZIPs, {stats['files_extracted']} files extracted")
    logger.info("="*80)
    
    return stats


# ============================================================================
# STEP 3: BUILD FILE QUEUE (Deduplicate + Hash)
# ============================================================================

def hash_file_fast(file_path: str) -> str:
    """Fast SHA256 hash using chunked reading"""
    sha256 = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(8192):
            sha256.update(chunk)
    return sha256.hexdigest()


def build_file_queue(db, CaseFile, SkippedFile, case_id: int) -> Dict:
    """
    Build queue of files to process, checking for duplicates
    
    Process:
    1. Scan all files in staging
    2. For each file: hash + check if (hash + filename) exists in DB
    3. If duplicate (exists in CaseFile or SkippedFile): 
       - Just delete file and skip (DON'T add to SkippedFile again)
       - Already processed or already skipped, no need to log again
    4. If new: create DB record, add to queue
    
    Returns:
        dict: {
            'files_found': int,
            'files_queued': int,
            'duplicates_skipped': int,
            'zero_bytes_skipped': int,
            'queue': [(file_id, filename, file_path), ...]
        }
    """
    staging_dir = get_staging_path(case_id)
    final_dir = get_final_upload_path(case_id)
    os.makedirs(final_dir, exist_ok=True)
    
    stats = {
        'files_found': 0,
        'files_queued': 0,
        'duplicates_skipped': 0,
        'zero_bytes_skipped': 0,
        'queue': []
    }
    
    logger.info("="*80)
    logger.info("[QUEUE] Building file queue with duplicate detection")
    logger.info("="*80)
    
    # Get all files in staging
    all_files = [f for f in os.listdir(staging_dir) 
                 if os.path.isfile(os.path.join(staging_dir, f))]
    
    stats['files_found'] = len(all_files)
    logger.info(f"[QUEUE] Found {len(all_files)} file(s) in staging")
    
    for filename in all_files:
        staging_path = os.path.join(staging_dir, filename)
        file_size = os.path.getsize(staging_path)
        
        # Skip zero-byte files
        if file_size == 0:
            logger.warning(f"[QUEUE] Skipping zero-byte file: {filename}")
            os.remove(staging_path)
            stats['zero_bytes_skipped'] += 1
            continue
        
        # Hash file
        file_hash = hash_file_fast(staging_path)
        
        # Check if (hash + filename) exists in CaseFile
        existing_case_file = db.session.query(CaseFile).filter_by(
            case_id=case_id,
            original_filename=filename,
            file_hash=file_hash
        ).first()
        
        if existing_case_file:
            # Already processed or in queue - just delete and skip
            logger.info(f"[QUEUE] Duplicate skipped: {filename} (already in CaseFile, file_id {existing_case_file.id})")
            os.remove(staging_path)
            stats['duplicates_skipped'] += 1
            continue
        
        # Check if (hash + filename) exists in SkippedFile
        existing_skipped = db.session.query(SkippedFile).filter_by(
            case_id=case_id,
            filename=filename,
            file_hash=file_hash
        ).first()
        
        if existing_skipped:
            # Already skipped before - just delete and skip
            logger.info(f"[QUEUE] Duplicate skipped: {filename} (already in SkippedFile, reason: {existing_skipped.skip_reason})")
            os.remove(staging_path)
            stats['duplicates_skipped'] += 1
            continue
        
        # NEW FILE - Move to final upload directory
        final_path = os.path.join(final_dir, filename)
        shutil.move(staging_path, final_path)
        
        # Create CaseFile record (status: Queued)
        case_file = CaseFile(
            case_id=case_id,
            filename=filename,
            original_filename=filename,
            file_path=final_path,
            file_size=file_size,
            file_hash=file_hash,
            mime_type='application/octet-stream',
            uploaded_by=1,  # Will be overridden by caller
            indexing_status='Queued',
            upload_type='staging',
            is_indexed=False
        )
        db.session.add(case_file)
        db.session.flush()  # Get ID without committing
        
        stats['queue'].append((case_file.id, filename, final_path))
        stats['files_queued'] += 1
        logger.info(f"[QUEUE] Queued: {filename} (file_id={case_file.id})")
    
    # Commit all DB changes
    db.session.commit()
    
    logger.info("="*80)
    logger.info(f"[QUEUE] Complete:")
    logger.info(f"  Files found: {stats['files_found']}")
    logger.info(f"  Files queued: {stats['files_queued']}")
    logger.info(f"  Duplicates skipped: {stats['duplicates_skipped']}")
    logger.info(f"  Zero-byte skipped: {stats['zero_bytes_skipped']}")
    logger.info("="*80)
    
    return stats


# ============================================================================
# STEP 4: FILTER ZERO-EVENT FILES
# ============================================================================

def filter_zero_event_files(db, CaseFile, SkippedFile, queue: List[Tuple], case_id: int) -> Dict:
    """
    Convert EVTX to JSON, get event counts, handle 0-event files
    
    For 0-event files:
    1. Create CaseFile record (for audit trail)
    2. Mark as hidden in UI
    3. Archive EVTX to /opt/casescope/archive/{case_id}/
    4. Add to SkippedFile table
    5. Remove from processing queue
    
    Args:
        queue: List of (file_id, filename, file_path) tuples
        case_id: Case ID for archive folder
    
    Returns:
        dict: {
            'processed': int,
            'zero_events': int,
            'valid_files': int,
            'filtered_queue': [(file_id, filename, file_path, event_count), ...]
        }
    """
    stats = {
        'processed': 0,
        'zero_events': 0,
        'valid_files': 0,
        'filtered_queue': []
    }
    
    # Create archive directory
    archive_dir = f"/opt/casescope/archive/{case_id}"
    os.makedirs(archive_dir, exist_ok=True)
    
    logger.info("="*80)
    logger.info("[FILTER] Checking for zero-event files")
    logger.info("="*80)
    
    for file_id, filename, file_path in queue:
        stats['processed'] += 1
        
        # Only check EVTX files
        if not filename.lower().endswith('.evtx'):
            # NDJSON/JSON files: assume valid, will get counted during indexing
            stats['filtered_queue'].append((file_id, filename, file_path, None))
            stats['valid_files'] += 1
            continue
        
        try:
            # Run evtx_dump to get event count
            cmd = ['/opt/casescope/bin/evtx_dump', '-t', '1', '--no-confirm-overwrite', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            
            if result.returncode != 0:
                logger.warning(f"[FILTER] evtx_dump failed for {filename}, assuming valid")
                stats['filtered_queue'].append((file_id, filename, file_path, None))
                stats['valid_files'] += 1
                continue
            
            # Count events from output
            event_count = result.stdout.count('Event') if result.stdout else 0
            
            if event_count == 0:
                logger.warning(f"[FILTER] Zero events: {filename}")
                
                # Get CaseFile record
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    # Update CaseFile: keep record for audit, but mark as hidden
                    case_file.event_count = 0
                    case_file.indexing_status = 'Completed'
                    case_file.is_indexed = True
                    case_file.is_hidden = True  # Hidden from UI
                    
                    # Archive the EVTX file (for audit purposes)
                    archive_path = os.path.join(archive_dir, filename)
                    shutil.move(file_path, archive_path)
                    case_file.file_path = archive_path  # Update path to archive location
                    logger.info(f"[FILTER]   Archived to: {archive_path}")
                    
                    # Add to SkippedFile (for reporting)
                    skipped = SkippedFile(
                        case_id=case_id,
                        filename=filename,
                        file_size=case_file.file_size,
                        file_hash=case_file.file_hash,
                        skip_reason='zero_events',
                        skip_details='EVTX file has 0 events (archived for audit)',
                        upload_type='staging'
                    )
                    db.session.add(skipped)
                
                stats['zero_events'] += 1
                # DO NOT add to filtered_queue - file won't be processed
            else:
                # Valid file with events - add to queue for processing
                stats['filtered_queue'].append((file_id, filename, file_path, event_count))
                stats['valid_files'] += 1
                logger.info(f"[FILTER] Valid: {filename} ({event_count} events)")
        
        except Exception as e:
            logger.error(f"[FILTER] Error processing {filename}: {e}")
            # Assume valid on error - better to process than skip
            stats['filtered_queue'].append((file_id, filename, file_path, None))
            stats['valid_files'] += 1
    
    db.session.commit()
    
    logger.info("="*80)
    logger.info(f"[FILTER] Complete:")
    logger.info(f"  Files processed: {stats['processed']}")
    logger.info(f"  Zero-event files: {stats['zero_events']} (archived)")
    logger.info(f"  Valid files: {stats['valid_files']}")
    logger.info("="*80)
    
    return stats


# ============================================================================
# MAIN PIPELINE ORCHESTRATION
# ============================================================================

def process_upload_pipeline(db, CaseFile, SkippedFile, case_id: int, 
                           upload_source: str, celery_app=None) -> Dict:
    """
    Main pipeline orchestrator
    
    Args:
        db: Database session
        CaseFile: CaseFile model
        SkippedFile: SkippedFile model
        case_id: Case ID
        upload_source: 'http' or 'bulk' or 'staging' (if files already in staging)
        celery_app: Celery app for task queuing
    
    Returns:
        dict: Complete pipeline statistics
    """
    pipeline_stats = {
        'stage': 'starting',
        'files_found': 0,
        'files_queued': 0,
        'duplicates_skipped': 0,
        'zero_bytes_skipped': 0,
        'zero_events_skipped': 0,
        'files_ready': 0,
        'zips_extracted': 0
    }
    
    try:
        # STEP 2: Extract ZIPs
        extract_stats = extract_zips_in_staging(case_id)
        pipeline_stats['stage'] = 'extracted'
        pipeline_stats['zips_extracted'] = extract_stats['files_extracted']
        
        # STEP 3: Build queue (deduplicate)
        queue_stats = build_file_queue(db, CaseFile, SkippedFile, case_id)
        pipeline_stats['stage'] = 'queued'
        pipeline_stats['files_found'] = queue_stats['files_found']
        pipeline_stats['files_queued'] = queue_stats['files_queued']
        pipeline_stats['duplicates_skipped'] = queue_stats['duplicates_skipped']
        pipeline_stats['zero_bytes_skipped'] = queue_stats['zero_bytes_skipped']
        
        # STEP 4: Filter zero-event files
        filter_stats = filter_zero_event_files(db, CaseFile, SkippedFile, queue_stats['queue'], case_id)
        pipeline_stats['stage'] = 'filtered'
        pipeline_stats['zero_events_skipped'] = filter_stats['zero_events']
        pipeline_stats['files_ready'] = filter_stats['valid_files']
        
        # STEP 5: Queue files for processing
        if celery_app and filter_stats['filtered_queue']:
            for file_id, filename, file_path, event_count in filter_stats['filtered_queue']:
                celery_app.send_task('tasks.process_file_v9', args=[file_id, 'full'])
                logger.info(f"[PIPELINE] Queued for processing: {filename} (file_id={file_id})")
        
        pipeline_stats['stage'] = 'complete'
        pipeline_stats['success'] = True
        
    except Exception as e:
        logger.error(f"[PIPELINE] Error: {e}")
        import traceback
        traceback.print_exc()
        pipeline_stats['stage'] = 'error'
        pipeline_stats['success'] = False
        pipeline_stats['error'] = str(e)
    
    return pipeline_stats

