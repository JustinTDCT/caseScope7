#!/usr/bin/env python3
"""
caseScope v9.4.6 - Local Upload Folder Processing
Copyright (c) 2025 Justin Dube <casescope@thedubes.net>

Handles bulk file uploads from local server folder.
TWO-PHASE PROCESSING:
  Phase 1: Extract & Register (shows ALL files in UI immediately)
  Phase 2: Queue for Ingestion (parallel processing)
"""

import os
import shutil
import zipfile
import hashlib
import logging
from typing import List, Tuple, Dict, Any

logger = logging.getLogger(__name__)


def scan_local_folder(local_folder: str) -> List[Tuple[str, str]]:
    """
    Scan local upload folder for files.
    
    Args:
        local_folder: Path to local upload folder
    
    Returns:
        List of (filename, file_path) tuples
    """
    files = []
    for filename in os.listdir(local_folder):
        file_path = os.path.join(local_folder, filename)
        if os.path.isfile(file_path):
            files.append((filename, file_path))
    return files


def hash_file_chunked(file_path: str, chunk_size: int = 8192) -> str:
    """
    Calculate SHA256 hash of file using chunked reading (memory-efficient).
    
    Args:
        file_path: Path to file
        chunk_size: Size of chunks to read (default 8KB)
    
    Returns:
        SHA256 hex digest
    """
    file_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        while chunk := f.read(chunk_size):
            file_hash.update(chunk)
    return file_hash.hexdigest()


def extract_evtx_from_zip(zip_path: str, zip_name: str, extract_dir: str) -> List[Tuple[str, str, int]]:
    """
    Extract all EVTX files from ZIP, renaming with ZIP prefix.
    
    Args:
        zip_path: Path to ZIP file
        zip_name: Name of ZIP file (without extension)
        extract_dir: Directory to extract to
    
    Returns:
        List of (prefixed_name, extracted_path, file_size) tuples
    """
    extracted_files = []
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        for zip_info in zip_ref.filelist:
            if zip_info.filename.lower().endswith('.evtx'):
                # Extract to temp location
                zip_ref.extract(zip_info, extract_dir)
                original_path = os.path.join(extract_dir, zip_info.filename)
                
                # Create prefixed filename: "ZIPNAME_original.evtx"
                original_name = os.path.basename(zip_info.filename)
                prefixed_name = f"{zip_name}_{original_name}"
                prefixed_path = os.path.join(extract_dir, prefixed_name)
                
                # Rename with prefix
                shutil.move(original_path, prefixed_path)
                
                # Clean up nested directories from extraction
                # Walk up the directory tree and remove empty dirs
                extracted_dir = os.path.dirname(original_path)
                while extracted_dir != extract_dir and os.path.exists(extracted_dir):
                    try:
                        os.rmdir(extracted_dir)  # Only removes if empty
                        extracted_dir = os.path.dirname(extracted_dir)  # Move up one level
                    except OSError:
                        break  # Directory not empty or error, stop trying
                
                file_size = os.path.getsize(prefixed_path)
                extracted_files.append((prefixed_name, prefixed_path, file_size))
    
    return extracted_files


def create_casefile_record(db, CaseFile, case_id: int, filename: str, file_path: str, 
                          file_size: int, file_hash: str, mime_type: str, 
                          upload_type: str = 'local') -> Any:
    """
    Create CaseFile database record.
    
    Args:
        db: SQLAlchemy database instance
        CaseFile: CaseFile model class
        case_id: Case ID
        filename: Storage filename
        file_path: Full path to file
        file_size: File size in bytes
        file_hash: SHA256 hash
        mime_type: MIME type
        upload_type: 'local' or 'http'
    
    Returns:
        Created CaseFile instance
    """
    from utils import sanitize_filename
    
    case_file = CaseFile(
        case_id=case_id,
        filename=filename,
        original_filename=sanitize_filename(os.path.basename(filename)),
        file_path=file_path,
        file_size=file_size,
        file_hash=file_hash,
        mime_type=mime_type,
        uploaded_by=1,  # System user
        indexing_status='Queued',
        upload_type=upload_type
    )
    db.session.add(case_file)
    return case_file


def log_skipped_file(db, SkippedFile, case_id: int, filename: str, file_size: int,
                     file_hash: str, skip_reason: str, skip_details: str = None,
                     upload_type: str = 'local') -> None:
    """
    Log a skipped file to the audit database.
    
    Args:
        db: SQLAlchemy database instance
        SkippedFile: SkippedFile model class
        case_id: Case ID
        filename: Filename that was skipped
        file_size: File size in bytes
        file_hash: SHA256 hash (if calculated)
        skip_reason: Reason for skipping (duplicate_hash, zero_bytes, zero_events, corrupt)
        skip_details: Additional details about why it was skipped
        upload_type: 'local' or 'http'
    """
    skipped = SkippedFile(
        case_id=case_id,
        filename=filename,
        file_size=file_size,
        file_hash=file_hash,
        skip_reason=skip_reason,
        skip_details=skip_details,
        upload_type=upload_type
    )
    db.session.add(skipped)
    db.session.commit()
    logger.info(f"Audit: Skipped file logged - {filename} ({skip_reason})")


def process_local_uploads_two_phase(case_id: int, local_folder: str, 
                                    db, Case, CaseFile, celery_app, 
                                    log_audit_func, SkippedFile=None, progress_callback=None) -> Dict[str, Any]:
    """
    TWO-PHASE LOCAL UPLOAD PROCESSING (v9.4.8: with progress callback)
    
    Phase 1: Extract all ZIPs, rename files, create ALL CaseFile records
             → All files visible in UI immediately!
    
    Phase 2: Queue all files for processing at once
             → Parallel processing, accurate counts
    
    Args:
        case_id: Case ID to associate files with
        local_folder: Path to local upload folder
        db: SQLAlchemy database instance
        Case: Case model class
        CaseFile: CaseFile model class
        celery_app: Celery app instance
        log_audit_func: Audit logging function
        progress_callback: Optional callback(status, current_zip, zips_processed, total_zips, files_extracted, files_registered)
    
    Returns:
        Dict with status, message, and statistics
    """
    logger.info("="*80)
    logger.info("LOCAL UPLOAD PROCESSING v9.4.9 - TWO-PHASE (STRICT SEQUENTIAL)")
    logger.info(f"Case ID: {case_id}")
    logger.info("="*80)
    
    # Get case
    case = db.session.get(Case, case_id)
    if not case:
        logger.error(f"Case {case_id} not found")
        return {'status': 'error', 'message': 'Case not found', 'files_processed': 0}
    
    # v9.4.12: Capture case.id IMMEDIATELY (before any expunge_all() calls)
    # This prevents "Instance is not bound to a Session" errors when processing multiple ZIPs
    case_id_safe = case.id
    
    # Validate folder exists
    if not os.path.exists(local_folder):
        logger.warning(f"Local upload folder does not exist: {local_folder}")
        return {'status': 'error', 'message': f'Folder not found: {local_folder}', 'files_processed': 0}
    
    # Scan for files
    logger.info(f"Scanning folder: {local_folder}")
    source_files = scan_local_folder(local_folder)
    
    if not source_files:
        logger.info("No files found in local upload folder")
        return {'status': 'success', 'message': 'No files to process', 'files_processed': 0}
    
    logger.info(f"Found {len(source_files)} files in local folder")
    
    # Case upload directory (use case_id_safe, not case.id!)
    case_upload_dir = f"/opt/casescope/uploads/{case_id_safe}"
    os.makedirs(case_upload_dir, exist_ok=True)
    
    # Stats
    stats = {
        'zips_processed': 0,
        'evtx_from_zips': 0,
        'direct_evtx': 0,
        'direct_json': 0,
        'files_queued': 0,
        'files_failed': 0,
        'duplicates_skipped': 0
    }
    
    files_to_queue = []  # Will hold CaseFile IDs to queue in Phase 2
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 1: EXTRACT & REGISTER (Shows all files in UI immediately!)
    # ═══════════════════════════════════════════════════════════════════
    logger.info("="*80)
    logger.info("PHASE 1: EXTRACTING & REGISTERING FILES")
    logger.info("="*80)
    
    # ──────────────────────────────────────────────────────────────────
    # STEP 1.1: Extract ALL ZIP files first (unzip everything!)
    # ──────────────────────────────────────────────────────────────────
    zip_files = [f for f in source_files if f[0].lower().endswith('.zip')]
    total_zips = len(zip_files)
    
    if total_zips > 0:
        logger.info(f"STEP 1.1: Extracting {total_zips} ZIP file(s)...")
        
        for filename, file_path in zip_files:
            try:
                zip_name = os.path.splitext(filename)[0]  # Remove .zip extension
                logger.info(f"Extracting ZIP: {filename}")
                
                # Extract all EVTX files with ZIP prefix
                extracted_files = extract_evtx_from_zip(file_path, zip_name, case_upload_dir)
                
                if not extracted_files:
                    logger.warning(f"No EVTX files found in ZIP: {filename}")
                    stats['files_failed'] += 1
                    os.remove(file_path)
                    continue
                
                logger.info(f"Extracted {len(extracted_files)} EVTX files from {filename}")
                stats['zips_processed'] += 1
                
                # Register each extracted EVTX in database
                for prefixed_name, evtx_path, evtx_size in extracted_files:
                    # Skip zero-byte files
                    if evtx_size == 0:
                        logger.warning(f"Skipping zero-byte file: {prefixed_name}")
                        
                        # v9.4.13: Log zero-byte file to audit database
                        if SkippedFile:
                            log_skipped_file(
                                db, SkippedFile, case_id_safe, prefixed_name, 0,
                                None, 'zero_bytes',
                                f'File extracted from {filename} but is 0 bytes',
                                'local'
                            )
                        
                        os.remove(evtx_path)
                        stats['files_failed'] += 1
                        continue
                    
                    # Hash file
                    evtx_hash = hash_file_chunked(evtx_path)
                    
                    # Check for duplicate
                    existing = db.session.query(CaseFile).filter_by(
                        case_id=case_id_safe, 
                        file_hash=evtx_hash
                    ).first()
                    
                    if existing:
                        logger.info(f"Duplicate skipped: {prefixed_name}")
                        
                        # v9.4.13: Log skipped file to audit database
                        if SkippedFile:
                            log_skipped_file(
                                db, SkippedFile, case_id_safe, prefixed_name, evtx_size,
                                evtx_hash, 'duplicate_hash',
                                f'Duplicate of file_id {existing.id} ({existing.filename})',
                                'local'
                            )
                        
                        os.remove(evtx_path)
                        stats['duplicates_skipped'] += 1
                        continue
                    
                    # Create CaseFile record
                    case_file = create_casefile_record(
                        db, CaseFile, case_id_safe, prefixed_name, evtx_path, 
                        evtx_size, evtx_hash, 'application/evtx', 'local'
                    )
                    db.session.commit()
                    
                    # v9.4.7: Capture ID immediately after commit (before expunge!)
                    file_id = case_file.id
                    
                    # Add to queue list for Phase 2
                    files_to_queue.append((file_id, prefixed_name))
                    stats['evtx_from_zips'] += 1
                    logger.info(f"Registered: {prefixed_name}")
                
                # Clean up memory after each ZIP
                db.session.expunge_all()
                import gc
                gc.collect()
                
                # Delete original ZIP
                os.remove(file_path)
                logger.info(f"Deleted original ZIP: {filename}")
                
                # v9.4.8: Update progress after each ZIP
                if progress_callback:
                    progress_callback(
                        status='extracting',
                        current_zip=filename,
                        zips_processed=stats['zips_processed'],
                        total_zips=total_zips,
                        files_extracted=len(extracted_files),
                        files_registered=stats['evtx_from_zips']
                    )
                
            except Exception as e:
                logger.error(f"Failed to process ZIP {filename}: {e}")
                stats['files_failed'] += 1
                continue
    
    # ──────────────────────────────────────────────────────────────────
    # STEP 1.2: Register direct EVTX/JSON files (after ALL ZIPs done!)
    # ──────────────────────────────────────────────────────────────────
    non_zip_files = [f for f in source_files if not f[0].lower().endswith('.zip')]
    
    if non_zip_files:
        logger.info(f"STEP 1.2: Registering {len(non_zip_files)} direct EVTX/JSON file(s)...")
        
        for filename, file_path in non_zip_files:
            try:
                file_ext = filename.lower().split('.')[-1]
                logger.info(f"Processing: {filename} ({file_ext})")
                
                # ──────────────────────────────────────────────────────────
                # HANDLE DIRECT EVTX FILES
                # ──────────────────────────────────────────────────────────
                if file_ext == 'evtx':
                    # Move to case folder
                    dest_path = os.path.join(case_upload_dir, filename)
                    shutil.move(file_path, dest_path)
                    
                    file_size = os.path.getsize(dest_path)
                    
                    # Skip zero-byte files
                    if file_size == 0:
                        logger.warning(f"Skipping zero-byte EVTX: {filename}")
                        
                        # v9.4.13: Log zero-byte file to audit database
                        if SkippedFile:
                            log_skipped_file(
                                db, SkippedFile, case_id_safe, filename, 0,
                                None, 'zero_bytes',
                                'File is 0 bytes (corrupt or empty)',
                                'local'
                            )
                        
                        os.remove(dest_path)
                        stats['files_failed'] += 1
                        continue
                    
                    # Hash file
                    file_hash = hash_file_chunked(dest_path)
                    
                    # Check for duplicate
                    existing = db.session.query(CaseFile).filter_by(
                        case_id=case_id_safe, 
                        file_hash=file_hash
                    ).first()
                    
                    if existing:
                        logger.info(f"Duplicate skipped: {filename}")
                        
                        # v9.4.13: Log skipped file to audit database
                        if SkippedFile:
                            log_skipped_file(
                                db, SkippedFile, case_id_safe, filename, file_size,
                                file_hash, 'duplicate_hash',
                                f'Duplicate of file_id {existing.id} ({existing.filename})',
                                'local'
                            )
                        
                        os.remove(dest_path)
                        stats['duplicates_skipped'] += 1
                        continue
                    
                    # Create CaseFile record
                    case_file = create_casefile_record(
                        db, CaseFile, case_id_safe, filename, dest_path, 
                        file_size, file_hash, 'application/evtx', 'local'
                    )
                    db.session.commit()
                    
                    # v9.4.7: Capture ID immediately after commit (before expunge!)
                    file_id = case_file.id
                    
                    # Add to queue list for Phase 2
                    files_to_queue.append((file_id, filename))
                    stats['direct_evtx'] += 1
                    logger.info(f"Registered: {filename}")
                    
                    # Clean up memory
                    db.session.expunge_all()
                    import gc
                    gc.collect()
                
                # ──────────────────────────────────────────────────────────
                # HANDLE JSON/NDJSON FILES
                # ──────────────────────────────────────────────────────────
                elif file_ext in ['json', 'ndjson']:
                    # Move to case folder
                    dest_path = os.path.join(case_upload_dir, filename)
                    shutil.move(file_path, dest_path)
                    
                    file_size = os.path.getsize(dest_path)
                    
                    # Skip zero-byte files
                    if file_size == 0:
                        logger.warning(f"Skipping zero-byte JSON: {filename}")
                        
                        # v9.4.13: Log zero-byte file to audit database
                        if SkippedFile:
                            log_skipped_file(
                                db, SkippedFile, case_id_safe, filename, 0,
                                None, 'zero_bytes',
                                'File is 0 bytes (corrupt or empty)',
                                'local'
                            )
                        
                        os.remove(dest_path)
                        stats['files_failed'] += 1
                        continue
                    
                    # Hash file
                    file_hash = hash_file_chunked(dest_path)
                    
                    # Check for duplicate
                    existing = db.session.query(CaseFile).filter_by(
                        case_id=case_id_safe, 
                        file_hash=file_hash
                    ).first()
                    
                    if existing:
                        logger.info(f"Duplicate skipped: {filename}")
                        
                        # v9.4.13: Log skipped file to audit database
                        if SkippedFile:
                            log_skipped_file(
                                db, SkippedFile, case_id_safe, filename, file_size,
                                file_hash, 'duplicate_hash',
                                f'Duplicate of file_id {existing.id} ({existing.filename})',
                                'local'
                            )
                        
                        os.remove(dest_path)
                        stats['duplicates_skipped'] += 1
                        continue
                    
                    # Create CaseFile record
                    case_file = create_casefile_record(
                        db, CaseFile, case_id_safe, filename, dest_path, 
                        file_size, file_hash, 'application/json', 'local'
                    )
                    db.session.commit()
                    
                    # v9.4.7: Capture ID immediately after commit (before expunge!)
                    file_id = case_file.id
                    
                    # Add to queue list for Phase 2
                    files_to_queue.append((file_id, filename))
                    stats['direct_json'] += 1
                    logger.info(f"Registered: {filename}")
                    
                    # Clean up memory
                    db.session.expunge_all()
                    import gc
                    gc.collect()
                
                else:
                    logger.warning(f"Unsupported file type: {filename}")
                    stats['files_failed'] += 1
            
            except Exception as e:
                logger.error(f"Error processing {filename}: {e}")
                stats['files_failed'] += 1
                continue
    
    # ═══════════════════════════════════════════════════════════════════
    # PHASE 2: QUEUE ALL FILES FOR INGESTION (Parallel processing!)
    # ═══════════════════════════════════════════════════════════════════
    logger.info("="*80)
    logger.info("PHASE 2: QUEUING FILES FOR INGESTION")
    logger.info(f"Total files to queue: {len(files_to_queue)}")
    logger.info("="*80)
    
    # v9.4.8: Notify frontend that queueing has started
    if progress_callback:
        progress_callback(
            status='queueing',
            current_zip='',
            zips_processed=stats['zips_processed'],
            total_zips=stats['zips_processed'],
            files_extracted=0,
            files_registered=len(files_to_queue)
        )
    
    for file_id, filename in files_to_queue:
        try:
            celery_app.send_task('tasks.process_file_complete', args=[file_id])
            stats['files_queued'] += 1
            logger.debug(f"Queued: {filename} (ID: {file_id})")
        except Exception as e:
            logger.error(f"Failed to queue {filename}: {e}")
            stats['files_failed'] += 1
    
    # Log audit trail
    log_audit_func(
        'local_upload',
        'file',
        f"Processed {len(source_files)} source files: "
        f"{stats['zips_processed']} ZIPs ({stats['evtx_from_zips']} EVTX extracted), "
        f"{stats['direct_evtx']} direct EVTX, "
        f"{stats['direct_json']} JSON, "
        f"{stats['files_queued']} queued for ingestion, "
        f"{stats['duplicates_skipped']} duplicates skipped, "
        f"{stats['files_failed']} failed"
    )
    
    logger.info("="*80)
    logger.info("LOCAL UPLOAD PROCESSING COMPLETED")
    logger.info(f"ZIPs Processed: {stats['zips_processed']}")
    logger.info(f"EVTX from ZIPs: {stats['evtx_from_zips']}")
    logger.info(f"Direct EVTX: {stats['direct_evtx']}")
    logger.info(f"Direct JSON: {stats['direct_json']}")
    logger.info(f"Files Queued: {stats['files_queued']}")
    logger.info(f"Duplicates Skipped: {stats['duplicates_skipped']}")
    logger.info(f"Failed: {stats['files_failed']}")
    logger.info("="*80)
    
    return {
        'status': 'success',
        'message': f"Processed {len(source_files)} source files, queued {stats['files_queued']} for ingestion",
        **stats
    }

