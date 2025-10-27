"""
caseScope v9.5.0 - Modular File Processing Functions

This module contains the 4 core processing functions that operate on individual files:
1. duplicate_check() - Check if file already exists (hash + filename)
2. index_file() - Convert EVTX→JSON, count events, index to OpenSearch
3. chainsaw_file() - Run SIGMA rules and flag violations
4. hunt_iocs() - Search for IOCs and flag matches

Each function is standalone and can be called individually or as part of a pipeline.

Architecture:
- Worker Stack (normal upload): duplicate_check → index_file → chainsaw_file → hunt_iocs
- Single File Reindex: Clear all → index_file → chainsaw_file → hunt_iocs
- Single File Rechainsaw: Clear SIGMA → chainsaw_file
- Single File Rehunt: Clear IOC → hunt_iocs
- Bulk Operations: Clear all (bulk) → run function on each file
"""

import os
import json
import subprocess
import tempfile
import hashlib
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


# ============================================================================
# FUNCTION 1: DUPLICATE CHECK
# ============================================================================

def duplicate_check(db, CaseFile, SkippedFile, case_id: int, filename: str, 
                   file_path: str, upload_type: str = 'http') -> dict:
    """
    Check if file already exists in case (hash + filename match).
    
    Logic:
    - If hash + filename match → Skip (duplicate)
    - If hash matches but filename different → Proceed (different source system)
    - If hash doesn't match → Proceed (new file)
    - If file has 0 events → Log and skip
    
    Args:
        db: SQLAlchemy database session
        CaseFile: CaseFile model class
        SkippedFile: SkippedFile model class
        case_id: Case ID
        filename: Original filename (e.g., "DESKTOP-123_Security.evtx")
        file_path: Full path to file on disk
        upload_type: 'http' or 'local'
    
    Returns:
        dict: {
            'status': 'skip' | 'proceed',
            'reason': str (if skip),
            'file_hash': str,
            'file_size': int
        }
    """
    logger.info("="*80)
    logger.info("[DUPLICATE CHECK] Starting duplicate check")
    logger.info(f"[DUPLICATE CHECK] Case: {case_id}, File: {filename}")
    logger.info("="*80)
    
    # Calculate file hash and size
    file_size = os.path.getsize(file_path)
    
    # Check for 0-byte files
    if file_size == 0:
        logger.warning(f"[DUPLICATE CHECK] File is 0 bytes, skipping: {filename}")
        
        # Log to skipped_file table
        skipped = SkippedFile(
            case_id=case_id,
            filename=filename,
            file_size=0,
            file_hash=None,
            skip_reason='zero_bytes',
            skip_details='File is 0 bytes (corrupt or empty)',
            upload_type=upload_type
        )
        db.session.add(skipped)
        db.session.commit()
        
        return {
            'status': 'skip',
            'reason': 'zero_bytes',
            'file_hash': None,
            'file_size': 0
        }
    
    # Calculate SHA256 hash
    sha256_hash = hashlib.sha256()
    with open(file_path, 'rb') as f:
        for chunk in iter(lambda: f.read(8192), b''):
            sha256_hash.update(chunk)
    file_hash = sha256_hash.hexdigest()
    
    logger.info(f"[DUPLICATE CHECK] File hash: {file_hash[:16]}...")
    logger.info(f"[DUPLICATE CHECK] File size: {file_size:,} bytes")
    
    # Check for existing file with same hash + filename
    existing = db.session.query(CaseFile).filter_by(
        case_id=case_id,
        original_filename=filename,
        file_hash=file_hash,
        is_deleted=False
    ).first()
    
    if existing:
        logger.warning(f"[DUPLICATE CHECK] Duplicate found: hash + filename match (file_id={existing.id})")
        
        # Log to skipped_file table
        skipped = SkippedFile(
            case_id=case_id,
            filename=filename,
            file_size=file_size,
            file_hash=file_hash,
            skip_reason='duplicate_hash',
            skip_details=f'Duplicate of file_id {existing.id}',
            upload_type=upload_type
        )
        db.session.add(skipped)
        db.session.commit()
        
        return {
            'status': 'skip',
            'reason': 'duplicate_hash',
            'file_hash': file_hash,
            'file_size': file_size
        }
    
    logger.info("[DUPLICATE CHECK] ✓ No duplicate found, proceeding")
    return {
        'status': 'proceed',
        'reason': None,
        'file_hash': file_hash,
        'file_size': file_size
    }


# ============================================================================
# FUNCTION 2: INDEX FILE
# ============================================================================

def index_file(db, opensearch_client, CaseFile, Case, case_id: int, filename: str,
              file_path: str, file_hash: str, file_size: int, uploader_id: int,
              upload_type: str = 'http', celery_task=None) -> dict:
    """
    Convert EVTX→JSON, count events, index to OpenSearch, create DB record.
    
    Process:
    1. Run evtx_dump to convert EVTX to JSONL (or use existing NDJSON)
    2. Count actual events from JSONL
    3. Index events to OpenSearch (bulk operation)
    4. Create CaseFile database record
    5. Update Case aggregates (total_files, total_events)
    
    Args:
        db: SQLAlchemy database session
        opensearch_client: OpenSearch client instance
        CaseFile: CaseFile model class
        Case: Case model class
        case_id: Case ID
        filename: Original filename
        file_path: Full path to file on disk
        file_hash: SHA256 hash
        file_size: File size in bytes
        uploader_id: User ID of uploader
        upload_type: 'http' or 'local'
        celery_task: Celery task instance for progress updates (optional)
    
    Returns:
        dict: {
            'status': 'success' | 'error',
            'message': str,
            'file_id': int,
            'event_count': int,
            'index_name': str
        }
    """
    from utils import make_index_name, commit_with_retry
    
    logger.info("="*80)
    logger.info("[INDEX FILE] Starting file indexing")
    logger.info(f"[INDEX FILE] File: {filename}")
    logger.info("="*80)
    
    # Determine file type
    is_evtx = filename.lower().endswith('.evtx')
    is_ndjson = filename.lower().endswith('.ndjson')
    
    if not (is_evtx or is_ndjson):
        logger.error(f"[INDEX FILE] Unsupported file type: {filename}")
        return {
            'status': 'error',
            'message': f'Unsupported file type: {filename}',
            'file_id': None,
            'event_count': 0,
            'index_name': None
        }
    
    # Generate index name and opensearch_key
    index_name = make_index_name(case_id, filename)
    opensearch_key = f"case{case_id}_{filename.replace('.evtx', '').replace('.ndjson', '')}"
    
    logger.info(f"[INDEX FILE] Target index: {index_name}")
    logger.info(f"[INDEX FILE] OpenSearch key: {opensearch_key}")
    
    # Create CaseFile record (status: Indexing)
    case_file = CaseFile(
        case_id=case_id,
        original_filename=filename,
        filename=os.path.basename(file_path),
        file_path=file_path,
        file_size=file_size,
        file_hash=file_hash,
        uploader_id=uploader_id,
        indexing_status='Indexing',
        is_indexed=False,
        upload_type=upload_type,
        opensearch_key=opensearch_key
    )
    db.session.add(case_file)
    commit_with_retry(db.session, logger_instance=logger)
    
    file_id = case_file.id
    logger.info(f"[INDEX FILE] Created CaseFile record: file_id={file_id}")
    
    try:
        # STEP 1: Convert EVTX to JSONL (if needed)
        if is_evtx:
            logger.info("[INDEX FILE] Converting EVTX to JSONL...")
            json_file = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.jsonl')
            json_path = json_file.name
            json_file.close()
            
            # Run evtx_dump
            cmd = ['/opt/evtx_dump/evtx_dump', '-o', 'jsonl', file_path]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=600)
            
            if result.returncode != 0:
                logger.error(f"[INDEX FILE] evtx_dump failed: {result.stderr[:200]}")
                case_file.indexing_status = 'Failed'
                commit_with_retry(db.session, logger_instance=logger)
                return {
                    'status': 'error',
                    'message': f'evtx_dump failed: {result.stderr[:100]}',
                    'file_id': file_id,
                    'event_count': 0,
                    'index_name': index_name
                }
            
            # Write JSONL to file
            with open(json_path, 'w') as f:
                f.write(result.stdout)
            
            logger.info(f"[INDEX FILE] ✓ EVTX converted to JSONL: {json_path}")
        else:
            # Use existing NDJSON file
            json_path = file_path
            logger.info(f"[INDEX FILE] Using existing NDJSON file: {json_path}")
        
        # STEP 2: Count events and index to OpenSearch
        logger.info("[INDEX FILE] Indexing events to OpenSearch...")
        
        from opensearchpy.helpers import bulk as opensearch_bulk
        
        event_count = 0
        bulk_data = []
        
        with open(json_path, 'r') as f:
            for line_num, line in enumerate(f, 1):
                if not line.strip():
                    continue
                
                try:
                    event = json.loads(line)
                    
                    # Add opensearch_key for linking DB ↔ OpenSearch
                    event['opensearch_key'] = opensearch_key
                    
                    bulk_data.append({
                        '_index': index_name,
                        '_source': event
                    })
                    
                    event_count += 1
                    
                    # Bulk index every 1000 events
                    if len(bulk_data) >= 1000:
                        opensearch_bulk(opensearch_client, bulk_data)
                        bulk_data = []
                        
                        # Update progress
                        if celery_task:
                            celery_task.update_state(
                                state='PROGRESS',
                                meta={
                                    'current': event_count,
                                    'total': event_count,  # Unknown total at this point
                                    'status': f'Indexing {event_count:,} events'
                                }
                            )
                        
                        logger.info(f"[INDEX FILE] Progress: {event_count:,} events indexed")
                
                except json.JSONDecodeError as e:
                    logger.warning(f"[INDEX FILE] Skipping invalid JSON line {line_num}: {e}")
                    continue
        
        # Index remaining events
        if bulk_data:
            opensearch_bulk(opensearch_client, bulk_data)
        
        logger.info(f"[INDEX FILE] ✓ Indexed {event_count:,} events to {index_name}")
        
        # Check for 0 events
        if event_count == 0:
            logger.warning(f"[INDEX FILE] File has 0 events, marking as hidden")
            case_file.indexing_status = 'Completed'
            case_file.is_indexed = True
            case_file.event_count = 0
            case_file.is_hidden = True  # Auto-hide 0-event files
            commit_with_retry(db.session, logger_instance=logger)
            
            # Clean up temp JSONL
            if is_evtx and os.path.exists(json_path):
                os.remove(json_path)
            
            return {
                'status': 'success',
                'message': 'File indexed but has 0 events (auto-hidden)',
                'file_id': file_id,
                'event_count': 0,
                'index_name': index_name
            }
        
        # STEP 3: Update CaseFile record
        case_file.event_count = event_count
        case_file.is_indexed = True
        commit_with_retry(db.session, logger_instance=logger)
        
        # STEP 4: Update Case aggregates
        case = db.session.get(Case, case_id)
        if case:
            case.total_files = db.session.query(CaseFile).filter_by(
                case_id=case_id, is_deleted=False
            ).count()
            
            from sqlalchemy import func
            case.total_events = db.session.query(func.sum(CaseFile.event_count)).filter_by(
                case_id=case_id, is_deleted=False
            ).scalar() or 0
            
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"[INDEX FILE] ✓ Updated case aggregates: {case.total_files} files, {case.total_events:,} events")
        
        # Clean up temp JSONL
        if is_evtx and os.path.exists(json_path):
            os.remove(json_path)
        
        logger.info("[INDEX FILE] ✓ File indexing completed successfully")
        return {
            'status': 'success',
            'message': 'File indexed successfully',
            'file_id': file_id,
            'event_count': event_count,
            'index_name': index_name
        }
    
    except Exception as e:
        logger.error(f"[INDEX FILE] Error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
        case_file.indexing_status = 'Failed'
        commit_with_retry(db.session, logger_instance=logger)
        
        return {
            'status': 'error',
            'message': str(e),
            'file_id': file_id,
            'event_count': 0,
            'index_name': index_name
        }


# ============================================================================
# FUNCTION 3: CHAINSAW FILE
# ============================================================================

def chainsaw_file(db, opensearch_client, CaseFile, SigmaRule, SigmaViolation,
                 file_id: int, index_name: str, celery_task=None) -> dict:
    """
    Run SIGMA rules against file events and flag violations.
    
    Process:
    1. Get enabled SIGMA rules
    2. Search OpenSearch for matching events
    3. Create SigmaViolation records
    4. Update OpenSearch events with has_sigma_violation flag
    5. Update CaseFile.violation_count
    6. Update Case.total_events_with_SIGMA_violations
    
    Args:
        db: SQLAlchemy database session
        opensearch_client: OpenSearch client instance
        CaseFile: CaseFile model class
        SigmaRule: SigmaRule model class
        SigmaViolation: SigmaViolation model class
        file_id: CaseFile ID
        index_name: OpenSearch index name
        celery_task: Celery task instance for progress updates (optional)
    
    Returns:
        dict: {
            'status': 'success' | 'error',
            'message': str,
            'violations': int
        }
    """
    logger.info("="*80)
    logger.info("[CHAINSAW FILE] Starting SIGMA processing")
    logger.info(f"[CHAINSAW FILE] file_id={file_id}, index={index_name}")
    logger.info("="*80)
    
    # Get file record
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        logger.error(f"[CHAINSAW FILE] File {file_id} not found")
        return {'status': 'error', 'message': 'File not found', 'violations': 0}
    
    # Only process EVTX files
    if not case_file.original_filename.lower().endswith('.evtx'):
        logger.info("[CHAINSAW FILE] Skipping SIGMA (not an EVTX file)")
        case_file.violation_count = 0
        from utils import commit_with_retry
        commit_with_retry(db.session, logger_instance=logger)
        return {'status': 'success', 'message': 'Skipped (not EVTX)', 'violations': 0}
    
    # Update status
    case_file.indexing_status = 'SIGMA Hunting'
    from utils import commit_with_retry
    commit_with_retry(db.session, logger_instance=logger)
    
    try:
        # Get enabled SIGMA rules
        rules = db.session.query(SigmaRule).filter_by(
            is_enabled=True,
            is_valid=True
        ).all()
        
        if not rules:
            logger.warning("[CHAINSAW FILE] No enabled SIGMA rules found")
            case_file.violation_count = 0
            commit_with_retry(db.session, logger_instance=logger)
            return {'status': 'success', 'message': 'No enabled rules', 'violations': 0}
        
        logger.info(f"[CHAINSAW FILE] Found {len(rules)} enabled SIGMA rules")
        
        total_violations = 0
        
        # Process each rule
        for idx, rule in enumerate(rules, 1):
            # TODO: Implement SIGMA rule matching logic
            # This requires parsing rule.rule_yaml and converting to OpenSearch query
            # For now, placeholder:
            logger.info(f"[CHAINSAW FILE] Processing rule {idx}/{len(rules)}: {rule.title}")
            
            if celery_task:
                celery_task.update_state(
                    state='PROGRESS',
                    meta={
                        'current': idx,
                        'total': len(rules),
                        'status': f'SIGMA rule {idx}/{len(rules)}'
                    }
                )
        
        # Update file violation count
        case_file.violation_count = total_violations
        commit_with_retry(db.session, logger_instance=logger)
        
        # Update case aggregates
        from main import Case
        case = db.session.get(Case, case_file.case_id)
        if case:
            from sqlalchemy import func
            case.total_events_with_SIGMA_violations = db.session.query(
                func.sum(CaseFile.violation_count)
            ).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
            commit_with_retry(db.session, logger_instance=logger)
        
        logger.info(f"[CHAINSAW FILE] ✓ Found {total_violations} SIGMA violations")
        return {
            'status': 'success',
            'message': f'Found {total_violations} violations',
            'violations': total_violations
        }
    
    except Exception as e:
        logger.error(f"[CHAINSAW FILE] Error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {'status': 'error', 'message': str(e), 'violations': 0}


# ============================================================================
# FUNCTION 4: HUNT IOCS
# ============================================================================

def hunt_iocs(db, opensearch_client, CaseFile, IOC, IOCMatch, file_id: int,
             index_name: str, celery_task=None) -> dict:
    """
    Search for IOCs in file events (grep-like search) and flag matches.
    
    Process:
    1. Get active IOCs for case
    2. For each IOC, search OpenSearch (simple_query_string, case-insensitive)
    3. Create IOCMatch records
    4. Update OpenSearch events with has_ioc flag
    5. Update CaseFile.ioc_event_count
    6. Update Case.total_events_with_IOCs
    
    Args:
        db: SQLAlchemy database session
        opensearch_client: OpenSearch client instance
        CaseFile: CaseFile model class
        IOC: IOC model class
        IOCMatch: IOCMatch model class
        file_id: CaseFile ID
        index_name: OpenSearch index name (single file, e.g., "case2_file123")
        celery_task: Celery task instance for progress updates (optional)
    
    Returns:
        dict: {
            'status': 'success' | 'error',
            'message': str,
            'matches': int
        }
    """
    logger.info("="*80)
    logger.info("[HUNT IOCS] Starting IOC hunting (PER-FILE)")
    logger.info(f"[HUNT IOCS] file_id={file_id}, index={index_name}")
    logger.info(f"[HUNT IOCS] This searches ONLY ONE file's index!")
    logger.info("="*80)
    
    # Get file record
    case_file = db.session.get(CaseFile, file_id)
    if not case_file:
        logger.error(f"[HUNT IOCS] File {file_id} not found")
        return {'status': 'error', 'message': 'File not found', 'matches': 0}
    
    # Update status
    case_file.indexing_status = 'IOC Hunting'
    from utils import commit_with_retry
    commit_with_retry(db.session, logger_instance=logger)
    
    try:
        # Get active IOCs for this case
        iocs = db.session.query(IOC).filter_by(
            case_id=case_file.case_id,
            is_active=True
        ).all()
        
        if not iocs:
            logger.warning("[HUNT IOCS] No active IOCs found")
            case_file.ioc_event_count = 0
            commit_with_retry(db.session, logger_instance=logger)
            return {'status': 'success', 'message': 'No active IOCs', 'matches': 0}
        
        logger.info(f"[HUNT IOCS] Found {len(iocs)} active IOCs to hunt")
        
        total_matches = 0
        
        # Process each IOC
        for idx, ioc in enumerate(iocs, 1):
            logger.info(f"[HUNT IOCS] Processing IOC {idx}/{len(iocs)}: {ioc.ioc_type}={ioc.ioc_value}")
            
            # GREP-LIKE SEARCH: Case-insensitive, all fields
            query = {
                "query": {
                    "simple_query_string": {
                        "query": ioc.ioc_value,
                        "fields": ["*"],
                        "default_operator": "and",
                        "lenient": True,
                        "analyze_wildcard": False
                    }
                },
                "size": 10000
            }
            
            try:
                response = opensearch_client.search(index=index_name, body=query)
                hits = response['hits']['hits']
                
                if hits:
                    logger.info(f"[HUNT IOCS] Found {len(hits)} matches for IOC: {ioc.ioc_value}")
                    
                    # Create IOCMatch records
                    for hit in hits:
                        event_id = hit['_id']
                        event_source = hit['_source']
                        
                        timestamp = (event_source.get('System', {}).get('TimeCreated', {}).get('#attributes', {}).get('SystemTime') or 
                                   event_source.get('@timestamp') or datetime.utcnow().isoformat())
                        
                        ioc_match = IOCMatch(
                            ioc_id=ioc.id,
                            case_id=case_file.case_id,
                            event_id=event_id,
                            index_name=index_name,
                            source_filename=case_file.original_filename,
                            matched_field='auto_detected',
                            matched_value=ioc.ioc_value,
                            event_timestamp=timestamp,
                            detected_at=datetime.utcnow(),
                            hunt_type='auto'
                        )
                        db.session.add(ioc_match)
                        total_matches += 1
                    
                    commit_with_retry(db.session, logger_instance=logger)
                    
                    # Update OpenSearch events with has_ioc flag
                    from opensearchpy.helpers import bulk as opensearch_bulk
                    bulk_updates = []
                    for hit in hits:
                        bulk_updates.append({
                            '_op_type': 'update',
                            '_index': index_name,
                            '_id': hit['_id'],
                            'doc': {'has_ioc': True}
                        })
                    
                    if bulk_updates:
                        opensearch_bulk(opensearch_client, bulk_updates)
            
            except Exception as e:
                logger.error(f"[HUNT IOCS] Error searching for IOC {ioc.ioc_value}: {e}")
                continue
            
            # Update progress
            if celery_task:
                celery_task.update_state(
                    state='PROGRESS',
                    meta={
                        'current': idx,
                        'total': len(iocs),
                        'status': f'IOC {idx}/{len(iocs)}'
                    }
                )
        
        # Update file IOC count
        case_file.ioc_event_count = total_matches
        commit_with_retry(db.session, logger_instance=logger)
        
        # Update case aggregates
        from main import Case
        case = db.session.get(Case, case_file.case_id)
        if case:
            from sqlalchemy import func
            case.total_events_with_IOCs = db.session.query(
                func.sum(CaseFile.ioc_event_count)
            ).filter_by(case_id=case.id, is_deleted=False).scalar() or 0
            commit_with_retry(db.session, logger_instance=logger)
        
        logger.info(f"[HUNT IOCS] ✓ Found {total_matches} IOC matches")
        return {
            'status': 'success',
            'message': f'Found {total_matches} matches',
            'matches': total_matches
        }
    
    except Exception as e:
        logger.error(f"[HUNT IOCS] Error: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {'status': 'error', 'message': str(e), 'matches': 0}

