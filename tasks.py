#!/usr/bin/env python3
"""
caseScope 7.1 - Background Tasks
EVTX parsing, indexing, and SIGMA rule processing
"""

import os
import sys
import time
import json
import logging
from datetime import datetime
from celery_app import celery_app
from opensearchpy import OpenSearch, helpers
# REMOVED in v7.19.0: Replaced python-evtx with evtx_dump binary for 50x faster parsing
# import Evtx.Evtx as evtx
# import xmltodict

# SIGMA processing imports
from sigma.collection import SigmaCollection
from sigma.backends.opensearch import OpensearchLuceneBackend
from sigma.processing.pipeline import ProcessingPipeline, ProcessingItem
from sigma.processing.transformations import FieldMappingTransformation
from sigma.exceptions import SigmaError

# Setup logging
logging.basicConfig(
    level=logging.DEBUG,
    format='[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s',
    stream=sys.stdout
)
logger = logging.getLogger(__name__)

logger.info("="*80)
logger.info("TASKS MODULE LOADED")
logger.info("="*80)

# ══════════════════════════════════════════════════════════════════════════════
# AUDIT PROCESSING LOGS
# ══════════════════════════════════════════════════════════════════════════════

def write_audit_log(log_type, case_name, filename, message):
    """
    Write to dedicated audit processing log files.
    
    Args:
        log_type: 'SIGMA', 'INDEX', or 'IOC'
        case_name: Name of the case
        filename: Name of the file being processed
        message: Log message (e.g., 'Started SIGMA processing est. 1000 events')
    
    Log Format:
        <DATE/TIME> - <CASE> - <FILE> <MESSAGE>
    
    Example:
        2025-10-07 13:45:23 - Case Alpha - Security.evtx Started indexing est. 5000 events
        2025-10-07 13:46:01 - Case Alpha - Security.evtx Finished indexing, 5000 events indexed
        2025-10-07 13:46:05 - Case Alpha - Security.evtx Started SIGMA processing est. 5000 events
        2025-10-07 13:46:42 - Case Alpha - Security.evtx Finished SIGMA processing, 5000 events with 23 violations
        2025-10-07 13:46:45 - Case Alpha - Security.evtx Started IOC hunting est. 5000 events
        2025-10-07 13:47:12 - Case Alpha - Security.evtx Finished IOC hunting, 5000 events with 7 IOC matches
        2025-10-07 13:50:15 - Case Beta - Application.evtx ERROR: Failed to index: Connection timeout
    """
    try:
        log_dir = '/opt/casescope/logs'
        
        # Ensure logs directory exists
        os.makedirs(log_dir, exist_ok=True)
        
        # Map log type to filename
        log_files = {
            'SIGMA': f'{log_dir}/SIGMA.log',
            'INDEX': f'{log_dir}/INDEX.log',
            'IOC': f'{log_dir}/IOC.log'
        }
        
        if log_type not in log_files:
            logger.error(f"[Audit Log] Invalid log type: {log_type}")
            return
        
        log_path = log_files[log_type]
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        
        # Format: <DATE/TIME> - <CASE> - <FILE> <MESSAGE>
        log_line = f"{timestamp} - {case_name} - {filename} {message}\n"
        
        # Append to log file (thread-safe with 'a' mode)
        with open(log_path, 'a', encoding='utf-8') as f:
            f.write(log_line)
        
    except Exception as e:
        # Don't crash on audit log failures, just log to main logger
        logger.error(f"[Audit Log] Failed to write to {log_type}.log: {e}")

def commit_with_retry(session, max_retries=5, initial_delay=0.1, logger_instance=None):
    """
    Commit database session with automatic retry on lock errors.
    
    Args:
        session: SQLAlchemy session to commit
        max_retries: Maximum number of retry attempts
        initial_delay: Initial delay in seconds (doubles each retry)
        logger_instance: Logger for output messages
    
    Raises:
        Exception: Re-raises the exception if non-retryable or max retries exceeded
    """
    log = logger_instance or logger
    delay = initial_delay
    
    for attempt in range(max_retries):
        try:
            session.commit()
            return  # Success
        except Exception as e:
            error_str = str(e).lower()
            is_lock_error = 'database is locked' in error_str or 'pendingrollbackerror' in error_str
            
            if is_lock_error and attempt < max_retries - 1:
                log.warning(f"Database lock during commit (attempt {attempt + 1}/{max_retries}). Retrying in {delay}s...")
                session.rollback()
                time.sleep(delay)
                delay *= 2
                continue
            
            # Non-retryable error or max retries exceeded
            log.error(f"Failed to commit transaction: {e}")
            session.rollback()
            raise

# Add app directory to path for imports
sys.path.insert(0, '/opt/casescope/app')
logger.info("Importing Flask app and database models...")
from main import app, db, CaseFile, Case, SigmaRule, SigmaViolation
logger.info("Flask app and models imported successfully")

# Enable SQLite WAL mode for Celery worker (same as web app)
logger.info("Configuring SQLite for better concurrency...")
with app.app_context():
    with db.engine.connect() as conn:
        result = conn.execute(db.text('PRAGMA journal_mode=WAL'))
        mode = result.scalar()
        logger.info(f"SQLite journal mode: {mode}")
        conn.execute(db.text('PRAGMA busy_timeout=30000'))  # 30 second timeout
        logger.info("SQLite busy_timeout set to 30s")
        conn.commit()
logger.info("SQLite configuration complete")

# Import Celery chain for task chaining
from celery import chain
import time

# Database operation retry decorator for handling lock contention
def retry_on_db_lock(max_retries=5, base_delay=0.1):
    """
    Decorator to retry database operations when lock errors occur
    
    Args:
        max_retries: Maximum number of retry attempts
        base_delay: Initial delay in seconds (doubles each retry)
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            delay = base_delay
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except Exception as e:
                    error_str = str(e).lower()
                    if 'database is locked' in error_str or 'pendingrollbackerror' in error_str:
                        if attempt < max_retries - 1:
                            logger.warning(f"Database lock detected (attempt {attempt + 1}/{max_retries}). Retrying in {delay}s...")
                            # Rollback the failed transaction
                            try:
                                db.session.rollback()
                            except:
                                pass
                            time.sleep(delay)
                            delay *= 2  # Exponential backoff
                            continue
                    # Non-retryable error or max retries exceeded
                    raise
            return None
        return wrapper
    return decorator

# OpenSearch connection with extended timeouts for complex SIGMA queries
logger.info("Initializing OpenSearch client...")
from opensearchpy import RequestsHttpConnection

opensearch_client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False,
    connection_class=RequestsHttpConnection,
    timeout=60,  # Default connect+read timeout
    max_retries=3,
    retry_on_timeout=True
)
logger.info("OpenSearch client initialized")

# caseScope SIGMA Field Mapping
# Maps standard Sigma field names to our flattened EVTX structure
# Note: After v7.30.6 normalization, .#text suffixes are enforced for consistency
CASESCOPE_FIELD_MAPPING = {
    # System fields
    'EventID': 'System.EventID.#text',
    'Provider_Name': 'System.Provider.#attributes.Name',
    'Computer': 'System.Computer',
    'Channel': 'System.Channel',
    'Level': 'System.Level',
    'Task': 'System.Task',
    'Keywords': 'System.Keywords',
    'TimeCreated': 'System.TimeCreated.#attributes.SystemTime',
    
    # Common EventData fields (Sysmon & Security)
    'CommandLine': 'EventData.CommandLine',
    'Image': 'EventData.Image',
    'ParentImage': 'EventData.ParentImage',
    'ParentCommandLine': 'EventData.ParentCommandLine',
    'TargetFilename': 'EventData.TargetFilename',
    'SourceIp': 'EventData.SourceIp',
    'DestinationIp': 'EventData.DestinationIp',
    'User': 'EventData.User',
    'TargetUserName': 'EventData.TargetUserName',
    'SubjectUserName': 'EventData.SubjectUserName',
    'LogonType': 'EventData.LogonType',
    'IpAddress': 'EventData.IpAddress',
    'WorkstationName': 'EventData.WorkstationName',
    'TargetObject': 'EventData.TargetObject',
    'Details': 'EventData.Details',
    'ProcessId': 'EventData.ProcessId',
    'ParentProcessId': 'EventData.ParentProcessId',
    'SourcePort': 'EventData.SourcePort',
    'DestinationPort': 'EventData.DestinationPort',
    'Protocol': 'EventData.Protocol',
    'Initiated': 'EventData.Initiated',
    'SourceHostname': 'EventData.SourceHostname',
    'DestinationHostname': 'EventData.DestinationHostname',
    'Hashes': 'EventData.Hashes',
    'IntegrityLevel': 'EventData.IntegrityLevel',
    'OriginalFileName': 'EventData.OriginalFileName',
    'Product': 'EventData.Product',
    'Company': 'EventData.Company',
    'Description': 'EventData.Description',
    'FileVersion': 'EventData.FileVersion',
    'TargetUser': 'EventData.TargetUser',
    'ServiceName': 'EventData.ServiceName',
    'ServiceFileName': 'EventData.ServiceFileName',
    'ScriptBlockText': 'EventData.ScriptBlockText',
    'Path': 'EventData.Path',
    'Destination': 'EventData.Destination',
    'Query': 'EventData.Query',
    'QueryName': 'EventData.QueryName',
    'QueryResults': 'EventData.QueryResults',
    'RegistryKey': 'EventData.TargetObject',
    'RegistryValue': 'EventData.Details',
    'ImagePath': 'EventData.ImagePath',
    'ShareName': 'EventData.ShareName',
    'RelativeTargetName': 'EventData.RelativeTargetName',
    'Device': 'EventData.Device',
    'AccountName': 'EventData.AccountName',
    'AccountDomain': 'EventData.AccountDomain',
    'ClientAddress': 'EventData.ClientAddress',
    'FailureCode': 'EventData.FailureCode',
    'Status': 'EventData.Status',
    'SubStatus': 'EventData.SubStatus',
}

def sanitize_filename(filename):
    """
    Sanitize filename for use in OpenSearch index names
    Shared function to ensure consistent index naming across all code paths
    
    Args:
        filename: Original filename (may include extension)
    
    Returns:
        Sanitized lowercase string suitable for index names
    """
    import os
    # Remove extension
    name = os.path.splitext(filename)[0]
    # Replace problematic characters
    name = name.replace('%', '_').replace(' ', '_').replace('-', '_').lower()
    # Limit length to prevent overly long index names
    return name[:100]

def make_index_name(case_id, original_filename):
    """
    Generate OpenSearch index name from case ID and filename
    SINGLE SOURCE OF TRUTH for index naming - used by all routes and tasks
    
    Args:
        case_id: Database ID of the case
        original_filename: Original filename of the EVTX file
    
    Returns:
        Index name in format: case{ID}_{sanitized_filename}
    """
    sanitized = sanitize_filename(original_filename)
    return f"case{case_id}_{sanitized}"

def create_casescope_pipeline():
    """
    DEPRECATED in v7.2.0 - Replaced by Chainsaw
    Kept for backward compatibility during transition
    """
    field_mapping = FieldMappingTransformation(CASESCOPE_FIELD_MAPPING)
    
    pipeline = ProcessingPipeline(
        name="caseScope EVTX Pipeline",
        priority=50,
        items=[
            ProcessingItem(
                identifier="casescope-field-mapping",
                transformation=field_mapping,
                rule_conditions=[]
            )
        ]
    )
    
    return pipeline

def export_events_to_json(index_name, output_path):
    """
    Export all events from OpenSearch index to JSON file for Chainsaw processing
    
    Args:
        index_name: OpenSearch index name
        output_path: Path to write JSON file
    
    Returns:
        Number of events exported
    """
    logger.info(f"Exporting events from index '{index_name}' to {output_path}...")
    
    export_count = 0
    
    with open(output_path, 'w') as f:
        # Use scroll API to export all events efficiently
        response = opensearch_client.search(
            index=index_name,
            scroll='5m',
            size=1000,
            body={"query": {"match_all": {}}}
        )
        
        scroll_id = response['_scroll_id']
        hits = response['hits']['hits']
        
        # Write each event as a JSON object (one per line - JSONL format)
        for hit in hits:
            event = hit['_source']
            f.write(json.dumps(event) + '\n')
            export_count += 1
        
        # Continue scrolling until all events exported
        while len(hits) > 0:
            response = opensearch_client.scroll(scroll_id=scroll_id, scroll='5m')
            scroll_id = response['_scroll_id']
            hits = response['hits']['hits']
            
            for hit in hits:
                event = hit['_source']
                f.write(json.dumps(event) + '\n')
                export_count += 1
        
        # Clean up scroll
        try:
            opensearch_client.clear_scroll(scroll_id=scroll_id)
        except:
            pass
    
    logger.info(f"✓ Exported {export_count:,} events to {output_path}")
    return export_count

def enrich_events_with_detections(index_name, detections_by_record_number, file_id):
    """
    Enrich indexed events with SIGMA detection metadata by EventRecordID
    Adds 'sigma_detections' and 'has_violations' fields to matching events
    
    Args:
        index_name: OpenSearch index name
        detections_by_record_number: Dict mapping EventRecordID -> list of detections
        file_id: File ID to generate correct document IDs
    """
    logger.info(f"Enriching {len(detections_by_record_number)} events with detection metadata...")
    
    # Use the same hash-based ID generation as indexing
    # Indexing creates doc_id = hashlib.sha256(f"{file_id}_{record_num}").hexdigest()[:16]
    import hashlib
    
    bulk_actions = []
    for record_num, detections in detections_by_record_number.items():
        # Generate the same doc ID that was created during indexing
        # CRITICAL: Ensure record_num is same type (str) as during indexing
        record_num_str = str(record_num)
        doc_id = hashlib.sha256(f"{file_id}_{record_num_str}".encode()).hexdigest()[:16]
        
        # DEBUG: Log doc ID generation
        logger.debug(f"Enrichment doc_id for EventRecordID {record_num}: {doc_id}")
        
        action = {
            "update": {
                "_index": index_name,
                "_id": doc_id
            }
        }
        doc = {
            "doc": {
                "sigma_detections": detections,
                "has_violations": True,
                "violation_count": len(detections)
            },
            "doc_as_upsert": True,
            "detect_noop": False
        }
        
        bulk_actions.append(json.dumps(action))
        bulk_actions.append(json.dumps(doc))
    
    if bulk_actions:
        # Send bulk update request
        bulk_body = '\n'.join(bulk_actions) + '\n'
        
        try:
            response = opensearch_client.bulk(
                body=bulk_body,
                index=index_name,
                timeout=60
            )
            
            if response.get('errors'):
                logger.error(f"[SIGMA Enrichment] Bulk update had errors!")
                for item in response.get('items', []):
                    if 'update' in item and 'error' in item['update']:
                        logger.error(f"[SIGMA Enrichment] Update error: {item['update']['error']}")
                logger.warning(f"[SIGMA Enrichment] Full response: {response}")
            else:
                # Log details of what actually happened (created vs updated)
                items = response.get('items', [])
                created_count = sum(1 for item in items if 'update' in item and item['update'].get('result') == 'created')
                updated_count = sum(1 for item in items if 'update' in item and item['update'].get('result') == 'updated')
                noop_count = sum(1 for item in items if 'update' in item and item['update'].get('result') == 'noop')
                
                logger.info(f"[SIGMA Enrichment] ✓ Bulk operation completed: {created_count} created, {updated_count} updated, {noop_count} noop")
                
                if created_count > 0:
                    logger.warning(f"[SIGMA Enrichment] WARNING: {created_count} documents were CREATED (should be 0 - means doc IDs don't match!)")
                    # Log first few created docs for debugging
                    created_docs = [item['update'] for item in items if 'update' in item and item['update'].get('result') == 'created'][:3]
                    for doc in created_docs:
                        logger.warning(f"[SIGMA Enrichment] Created doc_id: {doc.get('_id')} in index: {doc.get('_index')}")
                elif updated_count > 0:
                    logger.info(f"[SIGMA Enrichment] ✅ All {updated_count} documents were UPDATED (correct behavior)")
                
                logger.info(f"[SIGMA Enrichment] Total processed: {len(detections_by_record_number)} events")
        except Exception as e:
            logger.error(f"Failed to enrich events: {e}")
            raise

def flatten_event(event_data, prefix='', max_depth=10, current_depth=0):
    """
    Flatten nested event structure for OpenSearch indexing with safety guards
    
    Args:
        event_data: Event dictionary from xmltodict
        prefix: Current key prefix for nested fields
        max_depth: Maximum recursion depth to prevent stack overflow
        current_depth: Current recursion level
    
    Returns:
        Flattened dictionary with dot-notation keys
    """
    flat = {}
    
    # Safety guard: prevent infinite recursion
    if current_depth >= max_depth:
        logger.warning(f"Max recursion depth ({max_depth}) reached while flattening event")
        return flat
    
    if not isinstance(event_data, dict):
        return {prefix: event_data} if prefix else {}
    
    for key, value in event_data.items():
        # Preserve XML special keys to match CASESCOPE_FIELD_MAPPING
        # Keep @ and # prefixes so fields like 'System.EventID.#text' match the mapping
        new_key = key
        
        full_key = f"{prefix}.{new_key}" if prefix else new_key
        
        # Safety guard: limit key length to prevent memory issues
        if len(full_key) > 256:
            logger.warning(f"Skipping oversized key: {full_key[:100]}...")
            continue
        
        if isinstance(value, dict):
            # Recursively flatten nested dicts
            nested = flatten_event(value, full_key, max_depth, current_depth + 1)
            flat.update(nested)
        elif isinstance(value, list):
            # Safety guard: limit list size
            if len(value) > 1000:
                logger.warning(f"Truncating large list at {full_key}: {len(value)} items -> 1000")
                value = value[:1000]
            
            # Handle lists by indexing or joining
            if all(isinstance(item, str) for item in value):
                # Join string lists
                flat[full_key] = ', '.join(value[:100])  # Limit joined strings
            else:
                # Index non-string lists
                for idx, item in enumerate(value):
                    if isinstance(item, dict):
                        nested = flatten_event(item, f"{full_key}_{idx}", max_depth, current_depth + 1)
                        flat.update(nested)
                    else:
                        flat[f"{full_key}_{idx}"] = str(item)[:1000]  # Limit string size
        else:
            # Safety guard: limit value size to prevent log/memory explosion
            str_value = str(value)
            if len(str_value) > 10000:
                logger.debug(f"Truncating large value at {full_key}: {len(str_value)} chars -> 10000")
                str_value = str_value[:10000] + "...[truncated]"
            flat[full_key] = str_value
    
    return flat

def normalize_event_fields(flat_event):
    """
    Normalize event fields to ensure consistent types across all events.
    
    Problem: evtx_dump sometimes outputs System.EventID as {"#text": "4624"}
    and sometimes as just "4624", causing OpenSearch mapping conflicts.
    
    Solution: Ensure ALL events use the .#text structure for consistency.
    If System.EventID exists without .#text, move value to System.EventID.#text
    
    This preserves the intentional double-mapping where EventID can be searched
    both as a specific field (System.EventID.#text:4624) and via plain text.
    """
    normalized = {}
    
    # Fields that should have .#text structure for consistency
    # These are typically simple XML elements that can vary in structure
    text_required_prefixes = ['System.EventID', 'System.Level', 'System.Task', 
                             'System.Version', 'System.Opcode']
    
    for key, value in flat_event.items():
        added = False
        
        # Check if this is a field that should have .#text but doesn't
        for prefix in text_required_prefixes:
            if key == prefix and not isinstance(value, dict):
                # This field should have .#text - add it
                normalized[f"{key}.#text"] = value
                added = True
                break
        
        if not added:
            # Keep field as-is
            normalized[key] = value
    
    return normalized

# Removed complex index mapping function - using OpenSearch auto-detection
# Let OpenSearch automatically detect field types for simplicity

def bulk_index_events(index_name, events):
    """
    Bulk index events to OpenSearch with retry logic and idempotency
    
    Args:
        index_name: OpenSearch index name
        events: List of event dictionaries to index
    """
    import hashlib
    
    if not events:
        return
    
    # Prepare bulk actions with idempotent doc IDs
    actions = []
    for event in events:
        # Create idempotent document ID from record_number + file_id
        metadata = event.get('_casescope_metadata', {})
        record_num = metadata.get('record_number', 0)
        file_id = metadata.get('file_id', 0)
        
        # Hash-based ID to prevent duplicates on retries
        # CRITICAL: Convert to str to ensure consistent hashing with enrichment
        doc_id = hashlib.sha256(f"{file_id}_{str(record_num)}".encode()).hexdigest()[:16]
        
        # DEBUG: Log first few doc IDs
        if len(actions) < 3:
            logger.debug(f"Indexing doc_id for file_id={file_id}, record_num={record_num}: {doc_id}")
        
        action = {
            '_index': index_name,
            '_id': doc_id,  # Idempotent ID
            '_source': event
        }
        actions.append(action)
    
    # Retry logic with exponential backoff for 429/5xx errors
    max_retries = 3
    retry_delay = 1  # seconds
    
    for attempt in range(max_retries):
        try:
            # Use helpers.bulk with bounded chunks and extended timeout
            success, failed = helpers.bulk(
                opensearch_client,
                actions,
                chunk_size=1000,  # Keep memory bounded
                max_retries=3,
                request_timeout=120,  # Extended timeout for large batches
                raise_on_error=False,  # Don't raise, we'll check failed
                raise_on_exception=False
            )
            
            if failed:
                logger.warning(f"Bulk index: {len(failed)} events failed out of {len(actions)}")
                for failure in failed[:5]:  # Log first 5 failures
                    logger.warning(f"Failed event: {failure}")
            
            logger.debug(f"Successfully indexed {success} events to {index_name}")
            return success
            
        except Exception as e:
            error_str = str(e).lower()
            
            # Retry on 429 (too many requests) or 5xx server errors
            if any(code in error_str for code in ['429', '502', '503', '504']):
                if attempt < max_retries - 1:
                    logger.warning(f"Bulk index failed (attempt {attempt + 1}/{max_retries}): {e}. Retrying in {retry_delay}s...")
                    time.sleep(retry_delay)
                    retry_delay *= 2  # Exponential backoff
                    continue
            
            # Non-retryable error or max retries exceeded
            logger.error(f"Bulk index failed permanently: {e}")
            raise

@celery_app.task(bind=True, name='tasks.index_evtx_file')
def index_evtx_file(self, file_id):
    """
    Parse and index an EVTX file to OpenSearch using evtx_dump
    
    NEW IN v7.19.0: Uses evtx_dump (Rust) for 50x faster parsing
    - Converts EVTX to JSONL with evtx_dump
    - Reads JSONL line-by-line (same format as xmltodict output)
    - All existing code (flatten, SIGMA, IOC) works unchanged
    
    Args:
        file_id: Database ID of the CaseFile to process
    """
    import time
    import subprocess
    import tempfile
    import json
    
    task_start_time = time.time()
    
    logger.info("="*80)
    logger.info(f"EVTX INDEXING TASK RECEIVED")
    logger.info(f"Task ID: {self.request.id}")
    logger.info(f"File ID: {file_id}")
    logger.info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*80)
    
    with app.app_context():
        jsonl_file = None
        try:
            # Get file record
            logger.info(f"Querying database for file ID {file_id}...")
            case_file = db.session.get(CaseFile, file_id)
            if not case_file:
                logger.error(f"File ID {file_id} not found in database")
                return {'status': 'error', 'message': f'File ID {file_id} not found'}
            
            case = db.session.get(Case, case_file.case_id)
            if not case:
                return {'status': 'error', 'message': f'Case ID {case_file.case_id} not found'}
            
            # Update status to Indexing
            case_file.indexing_status = 'Indexing'
            db.session.commit()
            
            # Generate index name using shared helper
            index_name = make_index_name(case.id, case_file.original_filename)
            
            logger.info(f"TASK SUMMARY: TaskID={self.request.id}, FileID={file_id}, Filename={case_file.original_filename}, Index={index_name}")
            
            # AUDIT LOG: Started indexing
            estimated_events = case_file.estimated_event_count or 'unknown'
            write_audit_log('INDEX', case.name, case_file.original_filename, 
                          f"Started indexing est. {estimated_events} events")
            
            # Check if file exists
            if not os.path.exists(case_file.file_path):
                case_file.indexing_status = 'Failed'
                db.session.commit()
                return {'status': 'error', 'message': f'File not found: {case_file.file_path}'}
            
            # Convert EVTX to JSONL using evtx_dump (FAST!)
            logger.info(f"Converting EVTX to JSONL with evtx_dump: {case_file.original_filename}")
            logger.info(f"File path: {case_file.file_path}")
            logger.info(f"Index name: {index_name}")
            
            jsonl_file = tempfile.mktemp(suffix='.jsonl')
            
            logger.info("Running evtx_dump...")
            result = subprocess.run([
                '/opt/casescope/bin/evtx_dump',
                '-t', '1',           # Single thread
                '-o', 'jsonl',       # JSONL output
                '-f', jsonl_file,    # Output file
                case_file.file_path  # Input EVTX
            ], check=True, capture_output=True, text=True)
            
            logger.info(f"evtx_dump completed, JSONL saved to: {jsonl_file}")
            
            # Parse JSONL and index events
            logger.info(f"Starting JSONL parsing and indexing...")
            events = []
            event_count = 0
            record_number = 0
            last_progress_update = time.time()  # Track last progress update time for 5s intervals
            
            with open(jsonl_file, 'r', encoding='utf-8') as f:
                for line in f:
                    record_number += 1
                    try:
                        # Parse JSON line (same structure as xmltodict output!)
                        event_dict = json.loads(line)
                        
                        # Extract Event data
                        if 'Event' in event_dict:
                            event_data = event_dict['Event']
                            
                            # Flatten the structure for easier searching
                            flat_event = flatten_event(event_data)
                            
                            # Normalize fields to ensure consistent types (e.g., enforce System.EventID.#text structure)
                            flat_event = normalize_event_fields(flat_event)
                            
                            # Get Event ID for description (now consistently at System.EventID.#text)
                            event_id = (flat_event.get('System.EventID.#text') or 
                                       flat_event.get('System_EventID_#text') or 
                                       flat_event.get('System.EventID') or 'N/A')
                            channel = (flat_event.get('System.Channel') or 
                                      flat_event.get('System_Channel') or '')
                            provider = (flat_event.get('System.Provider.#attributes.Name') or 
                                       flat_event.get('System.Provider.@Name') or 
                                       flat_event.get('System_Provider_@Name') or 
                                       flat_event.get('System.Provider') or '')
                            
                            # Add Event Type description for searchability
                            from main import get_event_description
                            event_description = get_event_description(event_id, channel, provider, flat_event)
                            flat_event['event_type'] = event_description
                            
                            # Get EventRecordID from event (used for SIGMA enrichment matching)
                            # For EVTX: Use actual Windows EventRecordID from System data
                            # For NDJSON/EDR: Fall back to sequential counter
                            event_record_id = (flat_event.get('System.EventRecordID') or 
                                             flat_event.get('System_EventRecordID') or 
                                             record_number)
                            
                            # CRITICAL: Ensure record_number is stored as string for consistent hashing
                            event_record_id_str = str(event_record_id)
                            
                            # Add metadata
                            flat_event['_casescope_metadata'] = {
                                'case_id': case.id,
                                'case_name': case.name,
                                'file_id': case_file.id,
                                'filename': case_file.original_filename,
                                'indexed_at': datetime.utcnow().isoformat(),
                                'record_number': event_record_id_str,  # Store as string for consistent hashing
                                'source_type': 'evtx'
                            }
                            
                            events.append(flat_event)
                            event_count += 1
                            
                            # Bulk index every 100 events for faster UI updates
                            if len(events) >= 100:
                                bulk_index_events(index_name, events)
                                events = []
                                
                                # Update progress every 5 seconds (time-based)
                                current_time = time.time()
                                if current_time - last_progress_update >= 5.0:
                                    case_file.event_count = event_count
                                    db.session.commit()
                                    
                                    # Update task progress with current and total counts
                                    self.update_state(
                                        state='PROGRESS',
                                        meta={
                                            'current': event_count, 
                                            'total': case_file.estimated_event_count or event_count,
                                            'status': f'{event_count:,} / {case_file.estimated_event_count:,} events' if case_file.estimated_event_count else f'{event_count:,} events'
                                        }
                                    )
                                    
                                    logger.info(f"Progress: {event_count:,} / {case_file.estimated_event_count:,} events indexed")
                                    last_progress_update = current_time
                    
                    except json.JSONDecodeError as e:
                        logger.warning(f"Error parsing JSON line {record_number}: {e}")
                        continue
                    except Exception as e:
                        logger.warning(f"Error processing record {record_number}: {e}")
                        continue
            
            # Index remaining events
            if events:
                bulk_index_events(index_name, events)
            
            # Update file record
            case_file.event_count = event_count
            case_file.indexed_at = datetime.utcnow()
            case_file.is_indexed = True
            case_file.indexing_status = 'SIGMA Hunting'
            db.session.commit()
            
            logger.info("="*80)
            logger.info(f"INDEXING COMPLETED: {event_count:,} events indexed from {case_file.original_filename}")
            logger.info("="*80)
            
            # AUDIT LOG: Finished indexing
            write_audit_log('INDEX', case.name, case_file.original_filename, 
                          f"Finished indexing, {event_count} events indexed")
            
            # Queue SIGMA rule processing for EVTX files only
            # SIGMA rules are Windows Event Log specific and don't apply to NDJSON/EDR data
            logger.info("Queueing SIGMA rule processing for EVTX file...")
            process_sigma_rules.delay(file_id, index_name)
            
            # Calculate task duration
            task_duration = time.time() - task_start_time
            
            logger.info("="*80)
            logger.info(f"EVTX INDEXING COMPLETED: {event_count:,} events indexed")
            logger.info(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info(f"Duration: {task_duration:.2f} seconds ({task_duration/60:.2f} minutes)")
            logger.info("="*80)
            
            return {
                'status': 'success',
                'message': f'Indexed {event_count:,} events',
                'event_count': event_count,
                'index_name': index_name
            }
        
        except subprocess.CalledProcessError as e:
            logger.error("="*80)
            logger.error(f"evtx_dump FAILED: {e}")
            logger.error(f"stdout: {e.stdout}")
            logger.error(f"stderr: {e.stderr}")
            logger.error("="*80)
            
            # Update status to Failed
            case_file = db.session.get(CaseFile, file_id)
            if case_file:
                case_file.indexing_status = 'Failed'
                case = db.session.get(Case, case_file.case_id)
                if case:
                    # AUDIT LOG: Error during indexing
                    write_audit_log('INDEX', case.name, case_file.original_filename, 
                                  f"ERROR: evtx_dump failed - {str(e.stderr)[:100]}")
                db.session.commit()
            
            return {'status': 'error', 'message': f'evtx_dump failed: {e.stderr}'}
        
        except Exception as e:
            logger.error("="*80)
            logger.error(f"INDEXING FAILED: {e}")
            logger.error("="*80)
            import traceback
            logger.error(traceback.format_exc())
            
            # Update status to Failed
            case_file = db.session.get(CaseFile, file_id)
            if case_file:
                case_file.indexing_status = 'Failed'
                case = db.session.get(Case, case_file.case_id)
                if case:
                    # AUDIT LOG: Error during indexing
                    write_audit_log('INDEX', case.name, case_file.original_filename, 
                                  f"ERROR: {str(e)[:100]}")
                db.session.commit()
            
            return {'status': 'error', 'message': str(e)}
        
        finally:
            # Clean up temporary JSONL file
            if jsonl_file and os.path.exists(jsonl_file):
                try:
                    os.remove(jsonl_file)
                    logger.debug(f"Cleaned up temporary file: {jsonl_file}")
                except Exception as e:
                    logger.warning(f"Failed to clean up {jsonl_file}: {e}")


@celery_app.task(bind=True, name='tasks.process_sigma_rules')
def process_sigma_rules(self, file_id, index_name):
    """
    Run SIGMA rules against indexed events using Chainsaw
    
    NEW IN v7.2.0: Complete architectural rewrite
    - Uses Chainsaw CLI (battle-tested SIGMA engine) instead of pySigma
    - Exports events from OpenSearch to JSON
    - Runs Chainsaw hunt with all enabled SIGMA rules
    - Parses Chainsaw detections and creates violation records
    - Enriches indexed events with detection metadata
    
    Args:
        file_id: Database ID of the CaseFile
        index_name: OpenSearch index containing events
    """
    import time
    import subprocess
    import tempfile
    import shutil
    task_start_time = time.time()
    
    logger.info("="*80)
    logger.info(f"CHAINSAW SIGMA PROCESSING TASK RECEIVED")
    logger.info(f"Task ID: {self.request.id}")
    logger.info(f"File ID: {file_id}")
    logger.info(f"Index Name: {index_name}")
    logger.info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*80)
    
    with app.app_context():
        temp_dir = None
        try:
            logger.info(f"Querying database for CaseFile ID {file_id}...")
            case_file = db.session.get(CaseFile, file_id)
            if not case_file:
                logger.error(f"File ID {file_id} not found in database")
                return {'status': 'error', 'message': f'File ID {file_id} not found'}
            
            logger.info(f"Found file: {case_file.original_filename}, Case ID: {case_file.case_id}")
            logger.info(f"Current status: {case_file.indexing_status}, Indexed: {case_file.is_indexed}")
            
            case = db.session.get(Case, case_file.case_id)
            if not case:
                logger.error(f"Case ID {case_file.case_id} not found in database")
                return {'status': 'error', 'message': f'Case ID {case_file.case_id} not found'}
            
            logger.info(f"Processing rules for case: {case.name}")
            
            # AUDIT LOG: Started SIGMA processing
            estimated_events = case_file.event_count or case_file.estimated_event_count or 'unknown'
            write_audit_log('SIGMA', case.name, case_file.original_filename, 
                          f"Started SIGMA processing est. {estimated_events} events")
            
            # SIGMA rules only work on Windows Event Logs (EVTX format)
            # Skip SIGMA processing for NDJSON/EDR files
            if case_file.original_filename.lower().endswith('.ndjson'):
                logger.warning("="*80)
                logger.warning(f"SKIPPING SIGMA PROCESSING: File is NDJSON (EDR data)")
                logger.warning(f"SIGMA rules are Windows Event Log specific")
                logger.warning(f"File: {case_file.original_filename}")
                logger.warning("="*80)
                case_file.indexing_status = 'Completed'
                db.session.commit()
                return {'status': 'success', 'message': 'SIGMA skipped for NDJSON file', 'violations': 0}
            
            # Delete existing violations for this file (handles re-index and re-run scenarios)
            logger.info("Checking for existing violations...")
            existing_violations = db.session.query(SigmaViolation).filter_by(file_id=file_id).all()
            if existing_violations:
                logger.info(f"Deleting {len(existing_violations)} existing violation(s) for file ID {file_id}")
                for violation in existing_violations:
                    db.session.delete(violation)
                commit_with_retry(db.session, logger_instance=logger)
                logger.info("✓ Existing violations cleared")
            
            # Get all enabled SIGMA rules
            logger.info("Querying for enabled SIGMA rules...")
            enabled_rules = db.session.query(SigmaRule).filter_by(is_enabled=True).all()
            total_rules = db.session.query(SigmaRule).count()
            logger.info(f"Found {len(enabled_rules)} enabled SIGMA rules (out of {total_rules} total)")
            logger.info(f"TASK SUMMARY: TaskID={self.request.id}, FileID={file_id}, Index={index_name}, Rules={len(enabled_rules)}/{total_rules}")
            
            if not enabled_rules:
                logger.warning(f"No enabled rules found! Total rules in DB: {total_rules}. Marking as completed.")
                case_file.indexing_status = 'Completed'
                db.session.commit()
                return {'status': 'success', 'message': 'No enabled rules', 'violations': 0}
            
            # Verify EVTX file exists
            if not os.path.exists(case_file.file_path):
                logger.error(f"EVTX file not found: {case_file.file_path}")
                case_file.indexing_status = 'Completed'  # Mark as complete even if file missing
                db.session.commit()
                return {'status': 'error', 'message': f'EVTX file not found: {case_file.file_path}'}
            
            logger.info(f"EVTX file path: {case_file.file_path}")
            
            # Create temporary directory for Chainsaw processing
            temp_dir = tempfile.mkdtemp(prefix='casescope_chainsaw_')
            logger.info(f"Created temporary directory: {temp_dir}")
            
            # Step 1: Export enabled SIGMA rules to temporary directory
            rules_dir = os.path.join(temp_dir, 'sigma_rules')
            os.makedirs(rules_dir, exist_ok=True)
            logger.info(f"Exporting {len(enabled_rules)} enabled SIGMA rules to {rules_dir}...")
            
            for rule in enabled_rules:
                rule_file = os.path.join(rules_dir, f"{rule.id}_{sanitize_filename(rule.title)}.yml")
                with open(rule_file, 'w') as f:
                    f.write(rule.rule_yaml)
            
            logger.info(f"✓ Exported {len(enabled_rules)} rules")
            
            # Step 2: Run Chainsaw hunt against original EVTX file
            chainsaw_output_path = os.path.join(temp_dir, 'chainsaw_detections.json')
            logger.info(f"Running Chainsaw hunt...")
            logger.info(f"  EVTX file: {case_file.file_path}")
            logger.info(f"  Rules: {rules_dir}")
            logger.info(f"  Output: {chainsaw_output_path}")
            
            # Use Chainsaw's built-in sigma-event-logs-all.yml mapping
            # This is maintained by the Chainsaw team and covers all Windows EVTX fields
            chainsaw_mapping = '/opt/casescope/chainsaw/mappings/sigma-event-logs-all.yml'
            
            # Chainsaw v2.12 syntax: chainsaw hunt <evtx_path> --sigma <rules_dir> --mapping <mapping> --json --output <output>
            # Chainsaw processes the original EVTX file, outputs detections as JSON
            chainsaw_cmd = [
                '/opt/casescope/bin/chainsaw',
                'hunt',
                case_file.file_path,  # Original EVTX file
                '--sigma', rules_dir,  # SIGMA rules directory
                '--mapping', chainsaw_mapping,
                '--json',
                '--output', chainsaw_output_path
            ]
            
            logger.info(f"Executing: {' '.join(chainsaw_cmd)}")
            
            result = subprocess.run(
                chainsaw_cmd,
                capture_output=True,
                text=True,
                timeout=600  # 10 minute timeout for large files
            )
            
            if result.returncode != 0:
                logger.error(f"Chainsaw failed with return code {result.returncode}")
                logger.error(f"STDOUT: {result.stdout}")
                logger.error(f"STDERR: {result.stderr}")
                raise Exception(f"Chainsaw hunt failed: {result.stderr}")
            
            logger.info(f"✓ Chainsaw hunt completed successfully")
            logger.info(f"Chainsaw output: {result.stdout[:500]}")  # First 500 chars
            
            # Step 3: Parse Chainsaw detections and create violation records
            logger.info(f"Parsing Chainsaw detections from {chainsaw_output_path}...")
            
            total_violations = 0
            detections_by_record_number = {}  # Map EventRecordID -> list of detections
            
            # Parse Chainsaw JSON output
            if os.path.exists(chainsaw_output_path) and os.path.getsize(chainsaw_output_path) > 0:
                with open(chainsaw_output_path, 'r') as f:
                    chainsaw_results = json.load(f)
                
                logger.info(f"Chainsaw returned {len(chainsaw_results)} detection(s)")
                
                # Debug: Log first detection to understand structure
                if chainsaw_results and len(chainsaw_results) > 0:
                    logger.info(f"DEBUG: First detection structure: {json.dumps(chainsaw_results[0], indent=2)[:1000]}")
                
                # Chainsaw v2.12.2 JSON format: Each object is a rule match
                # Structure: {name, id, level, document: {event data}, group, kind, authors, tags, etc.}
                # Disable autoflush to prevent lock contention during violation creation loop
                total_detections = len(chainsaw_results)
                processed_count = 0
                last_progress_update = time.time()  # Track last progress update time for 5s intervals
                
                with db.session.no_autoflush:
                    for detection in chainsaw_results:
                        processed_count += 1
                        
                        # Update progress every 5 seconds (time-based)
                        current_time = time.time()
                        if current_time - last_progress_update >= 5.0:
                            self.update_state(
                                state='PROGRESS',
                                meta={
                                    'current': processed_count,
                                    'total': total_detections,
                                    'event_count': case_file.event_count or 0,
                                    'status': f'SIGMA Hunting: {processed_count:,} / {total_detections:,} detections processed',
                                    'violations': total_violations
                                }
                            )
                            logger.info(f"SIGMA Progress: {processed_count:,} / {total_detections:,} detections processed, {total_violations} violations found")
                            last_progress_update = current_time
                        try:
                            # Each detection IS a rule match - extract rule metadata directly
                            rule_name = detection.get('name', 'Unknown Rule')
                            rule_id_from_yaml = detection.get('id', '')
                            rule_level = detection.get('level', 'medium')
                            doc = detection.get('document', {})
                            
                            if not doc:
                                logger.warning(f"Detection has no document: {rule_name}")
                                continue
                            
                            # Extract event identifiers from the matched event document
                            # Chainsaw document structure: {kind, path, data: {Event: {System, EventData}}}
                            data = doc.get('data', {})
                            event = data.get('Event', {})
                            system = event.get('System', {})
                            
                            # EventRecordID is in System - can be a string or int
                            event_record_id = system.get('EventRecordID')
                            
                            if not event_record_id:
                                # Debug: Show document structure to find correct path
                                logger.warning(f"Could not extract EventRecordID from detection for rule {rule_name}")
                                logger.info(f"DEBUG: Document keys: {list(doc.keys())}")
                                logger.info(f"DEBUG: System keys: {list(system.keys())[:10] if system else 'No System'}")
                                logger.info(f"DEBUG: Document sample: {json.dumps(doc, indent=2)[:500]}")
                                continue
                            
                            # CRITICAL: Convert EventRecordID to string for consistent hashing
                            event_record_id_str = str(event_record_id)
                            
                            # Create a unique event ID (same format as indexing uses)
                            import hashlib
                            event_id = hashlib.sha256(f"{file_id}_{event_record_id_str}".encode()).hexdigest()[:16]
                            
                            # Find matching SigmaRule in database by comparing rule name or YAML ID
                            matching_rule = None
                            for db_rule in enabled_rules:
                                # Match by title (exact) or YAML ID
                                if db_rule.title == rule_name or rule_id_from_yaml in db_rule.rule_yaml:
                                    matching_rule = db_rule
                                    break
                            
                            if not matching_rule:
                                logger.warning(f"Could not find database rule for Chainsaw detection: {rule_name} (ID: {rule_id_from_yaml})")
                                continue
                            
                            # Check if violation already exists
                            existing = db.session.query(SigmaViolation).filter_by(
                                file_id=file_id,
                                rule_id=matching_rule.id,
                                event_id=event_id
                            ).first()
                            
                            if not existing:
                                # Create new violation record
                                violation = SigmaViolation(
                                    case_id=case.id,
                                    file_id=file_id,
                                    rule_id=matching_rule.id,
                                    event_id=event_id,
                                    event_data=json.dumps(data),  # Store the actual event data, not the wrapper
                                    matched_fields=json.dumps({
                                        'rule_name': rule_name,
                                        'rule_id': rule_id_from_yaml,
                                        'level': rule_level,
                                        'tags': detection.get('tags', []),
                                        'authors': detection.get('authors', [])
                                    }),
                                    severity=rule_level
                                )
                                db.session.add(violation)
                                total_violations += 1
                                
                                # Track detections for enrichment by EventRecordID (use string version)
                                if event_record_id_str not in detections_by_record_number:
                                    detections_by_record_number[event_record_id_str] = []
                                detections_by_record_number[event_record_id_str].append({
                                    'rule_name': rule_name,
                                    'rule_id': matching_rule.id,
                                    'level': rule_level,
                                    'sigma_id': rule_id_from_yaml
                                })
                            
                        except Exception as e:
                            logger.warning(f"Error processing Chainsaw detection: {e}")
                            continue
                
                # Commit all violations with retry logic
                logger.info(f"Saving {total_violations} violation records to database...")
                commit_with_retry(db.session, logger_instance=logger)
                logger.info(f"✓ Created {total_violations} violation records")
            else:
                logger.info("No detections found by Chainsaw (empty output file)")
            
            # Step 5: Enrich indexed events with detection metadata
            if detections_by_record_number:
                logger.info(f"Enriching {len(detections_by_record_number)} events with detection metadata...")
                enrich_events_with_detections(index_name, detections_by_record_number, file_id)
                logger.info(f"✓ Events enriched with detection flags")
            
            # Update file record with violation count and mark as completed
            case_file.violation_count = total_violations
            case_file.indexing_status = 'Completed'
            case_file.celery_task_id = None  # Clear task ID on completion
            commit_with_retry(db.session, logger_instance=logger)
            
            # Clean up temporary directory
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir)
                logger.info(f"✓ Cleaned up temporary directory")
            
            # Calculate task duration
            task_duration = time.time() - task_start_time
            
            logger.info("="*80)
            logger.info(f"CHAINSAW SIGMA PROCESSING COMPLETED: {total_violations} violations found")
            logger.info(f"Rules checked: {len(enabled_rules)}")
            logger.info(f"Events scanned: {case_file.event_count:,}")
            logger.info(f"Finished at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
            logger.info(f"Duration: {task_duration:.2f} seconds ({task_duration/60:.2f} minutes)")
            logger.info("="*80)
            
            # AUDIT LOG: Finished SIGMA processing
            events_processed = case_file.event_count or 0
            write_audit_log('SIGMA', case.name, case_file.original_filename, 
                          f"Finished SIGMA processing, {events_processed} events with {total_violations} violations")
            
            return {
                'status': 'success',
                'message': f'Chainsaw processed {len(enabled_rules)} rules, found {total_violations} violations',
                'violations': total_violations,
                'rules_processed': len(enabled_rules),
                'rules_failed': 0
            }
        
        except Exception as e:
            logger.error("="*80)
            logger.error(f"CHAINSAW SIGMA PROCESSING FAILED: {e}")
            logger.error("="*80)
            import traceback
            logger.error(traceback.format_exc())
            
            # Clean up temporary directory on failure
            if temp_dir and os.path.exists(temp_dir):
                try:
                    shutil.rmtree(temp_dir)
                except:
                    pass
            
            # Rollback any failed transactions before trying to update
            try:
                db.session.rollback()
            except:
                pass
            
            try:
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    case_file.indexing_status = 'Failed'
                    case_file.celery_task_id = None  # Clear task ID on failure
                    case = db.session.get(Case, case_file.case_id)
                    if case:
                        # AUDIT LOG: Error during SIGMA processing
                        write_audit_log('SIGMA', case.name, case_file.original_filename, 
                                      f"ERROR: {str(e)[:100]}")
                    commit_with_retry(db.session, logger_instance=logger)
            except Exception as db_err:
                logger.error(f"Failed to update case_file status: {db_err}")
            
            return {'status': 'error', 'message': str(e)}


def sanitize_filename(filename):
    """Sanitize filename for use in OpenSearch index name"""
    # Remove extension
    name = os.path.splitext(filename)[0]
    # Replace invalid characters
    name = name.replace('%', '_').replace(' ', '_').replace('-', '_')
    # Convert to lowercase
    name = name.lower()
    # Limit length
    return name[:100]


def flatten_event(event_data, parent_key='', sep='.'):
    """
    Flatten nested event structure for easier searching
    Converts nested dicts to dot-notation keys
    """
    items = []
    
    if isinstance(event_data, dict):
        for k, v in event_data.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            
            if isinstance(v, dict):
                items.extend(flatten_event(v, new_key, sep=sep).items())
            elif isinstance(v, list):
                # Handle lists by indexing or concatenating
                if v and isinstance(v[0], dict):
                    for i, item in enumerate(v):
                        items.extend(flatten_event(item, f"{new_key}_{i}", sep=sep).items())
                else:
                    items.append((new_key, v))
            else:
                items.append((new_key, v))
    else:
        items.append((parent_key, event_data))
    
    return dict(items)


def create_index_mapping(index_name):
    """
    Create index with proper field mappings for sorting and searching
    
    PHILOSOPHY:
    - ALL fields indexed as TEXT for plain-text searching (normalize to text)
    - CRITICAL fields get subfields for structured operations:
      * .keyword - exact match, sorting, aggregations
      * .date - timestamps (range queries, date math, sorting)
      * .long - numeric fields (range queries, sorting)
    
    NOTE: evtx_dump uses #attributes for XML attributes (not @ prefix)
    """
    mapping = {
        "mappings": {
            # Dynamic templates apply to all fields not explicitly defined
            "dynamic_templates": [
                {
                    # All string fields → text with keyword subfield
                    "strings_as_text_and_keyword": {
                        "match_mapping_type": "string",
                        "mapping": {
                            "type": "text",
                            "fields": {
                                "keyword": {
                                    "type": "keyword",
                                    "ignore_above": 8192  # Increased from 256 for long command lines
                                }
                            }
                        }
                    }
                },
                {
                    # All numeric fields → long with keyword subfield for exact match
                    "numbers_as_long_and_keyword": {
                        "match_mapping_type": "long",
                        "mapping": {
                            "type": "long",
                            "fields": {
                                "keyword": {"type": "keyword"}
                            }
                        }
                    }
                }
            ],
            "properties": {
                # ===== CRITICAL SYSTEM FIELDS (explicitly mapped) =====
                
                # Timestamp - TEXT (searchable) + KEYWORD (exact) + DATE (sortable, filterable)
                "System.TimeCreated.#attributes.SystemTime": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"},
                        "date": {"type": "date", "ignore_malformed": True}
                    }
                },
                
                # Event ID - TEXT (searchable "4624") + KEYWORD (exact match, sorting)
                "System.EventID.#text": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                
                # Computer - TEXT (searchable "WORKSTATION") + KEYWORD (exact, sorting)
                "System.Computer": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                
                # Channel - TEXT (searchable "Security") + KEYWORD (exact, sorting)
                "System.Channel": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                
                # Provider Name - TEXT (searchable) + KEYWORD (exact, sorting)
                "System.Provider.#attributes.Name": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                
                # Level - TEXT (searchable) + KEYWORD (exact) + LONG (numeric filtering)
                "System.Level": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"},
                        "long": {"type": "long", "ignore_malformed": True}
                    }
                },
                
                # Event Type (our added description field) - TEXT + KEYWORD
                "event_type": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                
                # ===== NDJSON/EDR FIELDS =====
                
                # Process command line - TEXT (searchable) + KEYWORD (exact)
                "process.command_line": {
                    "type": "text",
                    "fields": {
                        "keyword": {
                            "type": "keyword",
                            "ignore_above": 32766  # Very long command lines
                        }
                    }
                },
                
                # Timestamp for NDJSON - TEXT + KEYWORD + DATE
                "@timestamp": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"},
                        "date": {"type": "date", "ignore_malformed": True}
                    }
                },
                
                # ===== CASESCOPE METADATA =====
                
                # Source filename - TEXT + KEYWORD
                "_casescope_metadata.filename": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                
                # SIGMA enrichment flags (booleans)
                "has_violations": {"type": "boolean"},
                "has_ioc_matches": {"type": "boolean"},
                "violation_count": {"type": "long"}
            }
        },
        "settings": {
            "index": {
                "number_of_shards": 1,
                "number_of_replicas": 0,
                # Increase max fields to handle complex EVTX events
                "mapping.total_fields.limit": 5000,
                # Better for forensic timeline analysis
                "refresh_interval": "5s"
            }
        }
    }
    
    try:
        # Check if index exists
        if not opensearch_client.indices.exists(index=index_name):
            opensearch_client.indices.create(index=index_name, body=mapping)
            logger.info(f"Created index with mapping: {index_name}")
        else:
            logger.info(f"Index already exists: {index_name}")
    except Exception as e:
        logger.warning(f"Could not create index mapping: {e}")
        # Continue anyway - OpenSearch will use dynamic mapping


@celery_app.task(bind=True, name='tasks.count_evtx_events')
def count_evtx_events(self, file_id):
    """
    Count total events in EVTX file before indexing using evtx_dump
    This provides accurate progress tracking
    
    NEW IN v7.19.0: Uses evtx_dump (Rust) for 50x faster counting
    """
    import subprocess
    import tempfile
    
    logger.info("="*80)
    logger.info(f"COUNTING EVENTS - File ID: {file_id}")
    logger.info("="*80)
    
    with app.app_context():
        try:
            case_file = db.session.get(CaseFile, file_id)
            if not case_file:
                logger.error(f"File ID {file_id} not found in database")
                return {'status': 'error', 'message': f'File ID {file_id} not found'}
            
            if not os.path.exists(case_file.file_path):
                logger.error(f"File not found: {case_file.file_path}")
                return {'status': 'error', 'message': f'File not found: {case_file.file_path}'}
            
            logger.info(f"Counting events in: {case_file.original_filename}")
            logger.info(f"File path: {case_file.file_path}")
            
            # Convert EVTX to JSONL using evtx_dump (fast!)
            jsonl_file = tempfile.mktemp(suffix='.jsonl')
            
            try:
                logger.info("Running evtx_dump to count events...")
                subprocess.run([
                    '/opt/casescope/bin/evtx_dump',
                    '-t', '1',           # Single thread
                    '-o', 'jsonl',       # JSONL output
                    '-f', jsonl_file,    # Output file
                    case_file.file_path  # Input EVTX
                ], check=True, capture_output=True, text=True)
                
                # Count lines in JSONL file (each line = 1 event)
                total_events = 0
                with open(jsonl_file, 'r') as f:
                    for _ in f:
                        total_events += 1
                        if total_events % 10000 == 0:
                            logger.info(f"Counted {total_events:,} events so far...")
                
                logger.info(f"Total events counted: {total_events:,}")
                
                # Update database with actual count
                case_file.estimated_event_count = total_events
                db.session.commit()
                
                logger.info("="*80)
                logger.info(f"EVENT COUNT COMPLETE: {total_events:,} events")
                logger.info("="*80)
                
                # Now start the actual indexing
                index_evtx_file.delay(file_id)
                
                return {
                    'status': 'success',
                    'total_events': total_events
                }
            
            finally:
                # Clean up temporary file
                if os.path.exists(jsonl_file):
                    os.remove(jsonl_file)
        
        except subprocess.CalledProcessError as e:
            logger.error("="*80)
            logger.error(f"evtx_dump FAILED: {e}")
            logger.error(f"stdout: {e.stdout}")
            logger.error(f"stderr: {e.stderr}")
            logger.error("="*80)
            
            # Fall back to estimation and start indexing anyway
            case_file = db.session.get(CaseFile, file_id)
            if case_file:
                case_file.estimated_event_count = int((case_file.file_size / 1048576) * 1000)
                db.session.commit()
                logger.warning(f"Falling back to estimated count: {case_file.estimated_event_count:,}")
                index_evtx_file.delay(file_id)
            
            return {'status': 'error', 'message': str(e)}
        
        except Exception as e:
            logger.error("="*80)
            logger.error(f"EVENT COUNTING FAILED: {e}")
            logger.error("="*80)
            import traceback
            logger.error(traceback.format_exc())
            
            # Fall back to estimation and start indexing anyway
            case_file = db.session.get(CaseFile, file_id)
            if case_file:
                case_file.estimated_event_count = int((case_file.file_size / 1048576) * 1000)
                db.session.commit()
                logger.warning(f"Falling back to estimated count: {case_file.estimated_event_count:,}")
                index_evtx_file.delay(file_id)
            
            return {'status': 'error', 'message': str(e)}


@celery_app.task(name='tasks.start_file_indexing')
def start_file_indexing(file_id):
    """
    Trigger to start indexing a file
    This is called immediately after file upload
    Routes to appropriate handler based on file type
    """
    with app.app_context():
        case_file = db.session.get(CaseFile, file_id)
        if not case_file:
            logger.error(f"File ID {file_id} not found")
            return {'status': 'error', 'message': 'File not found'}
        
        # Detect file type from extension
        filename_lower = case_file.original_filename.lower()
        
        if filename_lower.endswith('.ndjson'):
            logger.info(f"Detected NDJSON file: {case_file.original_filename}")
            return index_ndjson_file.delay(file_id)
        elif filename_lower.endswith('.evtx'):
            logger.info(f"Detected EVTX file: {case_file.original_filename}")
            return count_evtx_events.delay(file_id)
        else:
            # Default to EVTX for backwards compatibility
            logger.info(f"Unknown file type, attempting EVTX parsing: {case_file.original_filename}")
            return count_evtx_events.delay(file_id)


@celery_app.task(name='tasks.index_ndjson_file', bind=True)
def index_ndjson_file(self, file_id):
    """
    Parse and index an NDJSON file to OpenSearch
    NDJSON = Newline Delimited JSON (EDR telemetry, process events, etc.)
    
    Args:
        file_id: Database ID of the CaseFile to process
    """
    import time
    task_start_time = time.time()
    
    logger.info("="*80)
    logger.info(f"NDJSON INDEXING TASK RECEIVED")
    logger.info(f"Task ID: {self.request.id}")
    logger.info(f"File ID: {file_id}")
    logger.info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*80)
    
    with app.app_context():
        try:
            # Get file record
            logger.info(f"Querying database for file ID {file_id}...")
            case_file = db.session.get(CaseFile, file_id)
            if not case_file:
                logger.error(f"File ID {file_id} not found in database")
                return {'status': 'error', 'message': f'File ID {file_id} not found'}
            
            case = db.session.get(Case, case_file.case_id)
            if not case:
                return {'status': 'error', 'message': f'Case ID {case_file.case_id} not found'}
            
            # Check if file exists
            if not os.path.exists(case_file.file_path):
                error_msg = f"File not found: {case_file.file_path}"
                logger.error(error_msg)
                case_file.indexing_status = 'Failed'
                db.session.commit()
                return {'status': 'error', 'message': error_msg}
            
            logger.info(f"File path: {case_file.file_path}")
            logger.info(f"File size: {case_file.file_size:,} bytes")
            
            # Fast line count for accurate progress estimation
            logger.info("Counting lines for progress estimation...")
            line_count = 0
            with open(case_file.file_path, 'rb') as f:
                for _ in f:
                    line_count += 1
            
            logger.info(f"Estimated {line_count:,} events (based on line count)")
            
            # Update status to Indexing with estimated count
            logger.info(f"Updating status to 'Indexing' for file: {case_file.original_filename}")
            case_file.indexing_status = 'Indexing'
            case_file.event_count = 0
            case_file.estimated_event_count = line_count  # Set accurate estimate
            db.session.commit()
            
            # Create OpenSearch index name
            index_name = make_index_name(case.id, case_file.original_filename)
            logger.info(f"OpenSearch index: {index_name}")
            
            # Parse and index NDJSON
            total_events = 0
            indexed_events = 0
            batch_size = 500
            events_batch = []
            last_progress_update = time.time()  # Track last progress update time for 5s intervals
            
            logger.info("Starting NDJSON parsing and indexing...")
            
            with open(case_file.file_path, 'r', encoding='utf-8') as ndjson_file:
                for line_num, line in enumerate(ndjson_file, 1):
                    # Skip empty lines
                    line = line.strip()
                    if not line:
                        continue
                    
                    try:
                        # Parse JSON line
                        event = json.loads(line)
                        total_events += 1
                        
                        # Add caseScope metadata
                        event['_casescope_metadata'] = {
                            'case_id': case.id,
                            'case_name': case.name,
                            'file_id': case_file.id,
                            'filename': case_file.original_filename,
                            'line_number': line_num,
                            'indexed_at': datetime.utcnow().isoformat(),
                            'source_type': 'ndjson'  # Tag as NDJSON/EDR data
                        }
                        
                        # Generate document ID (use line number + file hash for uniqueness)
                        doc_id = f"{case_file.file_hash}_{line_num}"
                        
                        # Add to batch
                        events_batch.append({
                            '_index': index_name,
                            '_id': doc_id,
                            '_source': event
                        })
                        
                        # Bulk index when batch is full
                        if len(events_batch) >= batch_size:
                            success, failed = helpers.bulk(
                                opensearch_client,
                                events_batch,
                                raise_on_error=False,
                                raise_on_exception=False
                            )
                            indexed_events += success
                            
                            if failed:
                                logger.warning(f"Failed to index {len(failed)} events from batch")
                            
                            # Update progress every 5 seconds (time-based)
                            current_time = time.time()
                            if current_time - last_progress_update >= 5.0:
                                case_file.event_count = indexed_events
                                db.session.commit()
                                
                                # Update task progress with current/total
                                self.update_state(
                                    state='PROGRESS',
                                    meta={
                                        'current': indexed_events,
                                        'total': case_file.estimated_event_count or indexed_events,
                                        'status': f'{indexed_events:,} / {case_file.estimated_event_count:,} events' if case_file.estimated_event_count else f'{indexed_events:,} events'
                                    }
                                )
                                
                                logger.info(f"Indexed {indexed_events:,} / {case_file.estimated_event_count:,} events...")
                                last_progress_update = current_time
                            
                            # Clear batch
                            events_batch = []
                        
                    except json.JSONDecodeError as e:
                        logger.warning(f"Skipping invalid JSON at line {line_num}: {e}")
                        continue
                    except Exception as e:
                        logger.error(f"Error processing line {line_num}: {e}")
                        continue
            
            # Index remaining events in batch
            if events_batch:
                success, failed = helpers.bulk(
                    opensearch_client,
                    events_batch,
                    raise_on_error=False,
                    raise_on_exception=False
                )
                indexed_events += success
                
                if failed:
                    logger.warning(f"Failed to index {len(failed)} events from final batch")
            
            # Update final counts
            case_file.event_count = indexed_events
            case_file.estimated_event_count = total_events
            case_file.indexing_status = 'Completed'
            case_file.is_indexed = True
            case_file.indexed_at = datetime.utcnow()
            db.session.commit()
            
            elapsed_time = time.time() - task_start_time
            logger.info("="*80)
            logger.info(f"NDJSON INDEXING COMPLETE")
            logger.info(f"Total events parsed: {total_events:,}")
            logger.info(f"Successfully indexed: {indexed_events:,}")
            logger.info(f"Elapsed time: {elapsed_time:.2f} seconds")
            logger.info(f"NOTE: SIGMA rules NOT run (NDJSON files are EDR data, not Windows Event Logs)")
            logger.info("="*80)
            
            return {
                'status': 'success',
                'total_events': total_events,
                'indexed_events': indexed_events,
                'elapsed_time': elapsed_time
            }
        
        except Exception as e:
            logger.error("="*80)
            logger.error(f"NDJSON INDEXING FAILED: {e}")
            logger.error("="*80)
            import traceback
            logger.error(traceback.format_exc())
            
            # Update file status to failed
            case_file = db.session.get(CaseFile, file_id)
            if case_file:
                case_file.indexing_status = 'Failed'
                db.session.commit()
            
            return {'status': 'error', 'message': str(e)}

# ============================================================================
# IOC HUNTING TASK
# ============================================================================

@celery_app.task(bind=True, name='tasks.hunt_iocs_for_file')
def hunt_iocs_for_file(self, file_id, index_name):
    """
    Hunt for IOCs in a specific file's indexed events
    Creates IOCMatch records for all matching events
    Used for re-hunting IOCs on a single file
    """
    from datetime import datetime
    import time
    
    logger.info("="*80)
    logger.info(f"IOC HUNT STARTED - File ID: {file_id}, Index: {index_name}")
    logger.info("="*80)
    
    task_start_time = time.time()
    
    try:
        with app.app_context():
            # Import models
            from main import Case, IOC, IOCMatch, CaseFile
            
            # Get file
            case_file = db.session.get(CaseFile, file_id)
            if not case_file:
                logger.error(f"File ID {file_id} not found")
                return {'status': 'error', 'message': 'File not found'}
            
            # Update status
            case_file.indexing_status = 'IOC Hunting'
            commit_with_retry(db.session, logger_instance=logger)
            logger.info(f"Status updated to 'IOC Hunting' for file: {case_file.original_filename}")
            
            # AUDIT LOG: Started IOC hunting
            case = db.session.get(Case, case_file.case_id)
            if case:
                estimated_events = case_file.event_count or case_file.estimated_event_count or 'unknown'
                write_audit_log('IOC', case.name, case_file.original_filename, 
                              f"Started IOC hunting est. {estimated_events} events")
            
            # Get all active IOCs for this case
            iocs = db.session.query(IOC).filter_by(case_id=case_file.case_id, is_active=True).all()
            
            if not iocs:
                logger.warning(f"No active IOCs found for case {case_file.case_id}")
                case_file.indexing_status = 'Completed'
                commit_with_retry(db.session, logger_instance=logger)
                return {'status': 'success', 'message': 'No active IOCs to hunt', 'total_iocs': 0, 'matches': 0}
            
            logger.info(f"Found {len(iocs)} active IOCs to hunt")
            
            # IOC field mappings
            ioc_field_mapping = {
                'ip': ['Computer', 'SourceAddress', 'DestinationAddress', 'IpAddress', 'ClientIP', 'ServerIP', 'host.ip'],
                'domain': ['DestinationHostname', 'QueryName', 'domain', 'dns.question.name'],
                'fqdn': ['DestinationHostname', 'QueryName', 'domain', 'dns.question.name'],
                'hostname': ['Computer', 'Hostname', 'host.name', 'host.hostname'],
                'username': ['User', 'TargetUserName', 'SubjectUserName', 'user.name', 'user.id'],
                'hash_md5': ['Hashes.MD5', 'MD5', 'hash.md5', 'file.hash.md5'],
                'hash_sha1': ['Hashes.SHA1', 'SHA1', 'hash.sha1', 'file.hash.sha1'],
                'hash_sha256': ['Hashes.SHA256', 'SHA256', 'hash.sha256', 'file.hash.sha256'],
                'command': ['CommandLine', 'command_line', 'process.command_line'],
                'filename': ['Image', 'ParentImage', 'TargetFilename', 'FileName', 'file.name', 'file.path'],
                'process_name': ['Image', 'ParentImage', 'ProcessName', 'process.name', 'process.executable'],
                'registry_key': ['TargetObject', 'registry.path', 'registry.key'],
                'email': ['TargetUserName', 'email', 'user.email'],
                'url': ['url', 'url.full', 'url.original'],
                'malware_name': ['*']  # Search all fields for malware names
            }
            
            total_matches = 0
            last_progress_update = time.time()
            
            # Process each IOC
            for idx, ioc in enumerate(iocs, 1):
                logger.info(f"Processing IOC {idx}/{len(iocs)}: {ioc.ioc_type}={ioc.ioc_value}")
                
                # Update progress every 5 seconds
                current_time = time.time()
                if current_time - last_progress_update >= 5.0:
                    self.update_state(
                        state='PROGRESS',
                        meta={
                            'current': idx,
                            'total': len(iocs),
                            'ioc_type': ioc.ioc_type,
                            'ioc_value': ioc.ioc_value[:50],
                            'matches': total_matches
                        }
                    )
                    logger.info(f"IOC Hunting Progress: {idx} / {len(iocs)} IOCs processed, {total_matches} matches found")
                    last_progress_update = current_time
                
                # Get fields to search based on IOC type
                search_fields = ioc_field_mapping.get(ioc.ioc_type, ['*'])
                
                # Build OpenSearch query
                search_value = ioc.ioc_value_normalized or ioc.ioc_value.lower()
                
                # Escape special characters for OpenSearch query_string syntax
                # These characters have special meaning in Lucene/OpenSearch query syntax
                special_chars = ['\\', '"', '+', '-', '=', '&&', '||', '>', '<', '!', '(', ')', '{', '}', '[', ']', '^', '~', '*', '?', ':', '/']
                escaped_value = search_value
                for char in special_chars:
                    escaped_value = escaped_value.replace(char, '\\\\' + char)
                
                # Build multi-field query with nested field support
                should_clauses = []
                for field in search_fields:
                    # Use query_string with lenient flag to ignore incompatible field types
                    # Note: search_value already lowercased at line 1927, provides case-insensitive matching
                    should_clauses.append({
                        "query_string": {
                            "query": f"*{escaped_value}*",
                            "fields": [f"{field}*"],  # Wildcard to match nested paths
                            "default_operator": "AND",
                            "lenient": True  # Ignore field type errors
                        }
                    })
                
                query = {
                    "query": {
                        "bool": {
                            "should": should_clauses,
                            "minimum_should_match": 1
                        }
                    },
                    "size": 1000  # Process in batches
                }
                
                # Search OpenSearch
                try:
                    response = opensearch_client.search(index=index_name, body=query)
                    hits = response['hits']['hits']
                    
                    if hits:
                        logger.info(f"Found {len(hits)} matches for IOC: {ioc.ioc_value}")
                        
                        # Create IOCMatch records
                        for hit in hits:
                            event_source = hit['_source']
                            event_id = hit['_id']
                            
                            # Extract timestamp
                            timestamp = (event_source.get('System', {}).get('TimeCreated', {}).get('#attributes', {}).get('SystemTime') or 
                                       event_source.get('@timestamp') or 
                                       datetime.utcnow().isoformat())
                            
                            # Check if match already exists (prevent duplicates)
                            existing = db.session.query(IOCMatch).filter_by(
                                ioc_id=ioc.id,
                                event_id=event_id,
                                case_id=case_file.case_id
                            ).first()
                            
                            if not existing:
                                ioc_match = IOCMatch(
                                    ioc_id=ioc.id,
                                    case_id=case_file.case_id,
                                    event_id=event_id,
                                    source_filename=case_file.original_filename,
                                    matched_field='auto_detected',  # Could be enhanced to show exact field
                                    event_timestamp=timestamp,
                                    detected_at=datetime.utcnow()
                                )
                                db.session.add(ioc_match)
                                total_matches += 1
                        
                        # Commit matches in batches
                        commit_with_retry(db.session, logger_instance=logger)
                        
                        # Enrich OpenSearch events with IOC match flags
                        bulk_updates = []
                        for hit in hits:
                            bulk_updates.append({
                                '_op_type': 'update',
                                '_index': index_name,
                                '_id': hit['_id'],
                                'doc': {
                                    'has_ioc_matches': True,
                                    'ioc_matches': [{'ioc_id': ioc.id, 'ioc_value': ioc.ioc_value, 'ioc_type': ioc.ioc_type}]
                                },
                                'doc_as_upsert': True
                            })
                        
                        if bulk_updates:
                            from opensearchpy.helpers import bulk as opensearch_bulk
                            opensearch_bulk(opensearch_client, bulk_updates, raise_on_error=False)
                            logger.info(f"Enriched {len(bulk_updates)} events with IOC match flags")
                
                except Exception as e:
                    logger.error(f"Error searching for IOC {ioc.ioc_value}: {e}")
                    continue
            
            # Mark file as completed
            case_file.indexing_status = 'Completed'
            case_file.celery_task_id = None
            commit_with_retry(db.session, logger_instance=logger)
            
            task_duration = time.time() - task_start_time
            logger.info("="*80)
            logger.info(f"IOC HUNT COMPLETED - File: {case_file.original_filename}")
            logger.info(f"Total IOCs processed: {len(iocs)}")
            logger.info(f"Total matches found: {total_matches}")
            logger.info(f"Duration: {task_duration:.2f} seconds")
            logger.info("="*80)
            
            # AUDIT LOG: Finished IOC hunting
            if case:
                events_processed = case_file.event_count or 0
                write_audit_log('IOC', case.name, case_file.original_filename, 
                              f"Finished IOC hunting, {events_processed} events with {total_matches} IOC matches")
            
            return {
                'status': 'success',
                'file_id': file_id,
                'total_iocs': len(iocs),
                'matches': total_matches,
                'duration': task_duration
            }
            
    except Exception as e:
        logger.error(f"IOC hunt failed: {e}")
        import traceback
        logger.error(traceback.format_exc())
        
        # Mark file as failed
        try:
            with app.app_context():
                from main import CaseFile, Case
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    case_file.indexing_status = 'Failed'
                    case_file.celery_task_id = None
                    case = db.session.get(Case, case_file.case_id)
                    if case:
                        # AUDIT LOG: Error during IOC hunting
                        write_audit_log('IOC', case.name, case_file.original_filename, 
                                      f"ERROR: {str(e)[:100]}")
                    commit_with_retry(db.session, logger_instance=logger)
        except:
            pass
        
        return {'status': 'error', 'message': str(e)}


# ============================================================================
# IOC Hunting Helper Functions (Refactored from 329-line hunt_iocs function)
# ============================================================================

def get_ioc_field_mapping():
    """
    Get mapping of IOC types to OpenSearch field names to search.
    
    Returns:
        dict: Mapping of IOC type to list of field names
    """
    return {
        'ip': ['Computer', 'SourceAddress', 'DestinationAddress', 'IpAddress', 'ClientIP', 'ServerIP', 'host.ip'],
        'domain': ['DestinationHostname', 'QueryName', 'domain', 'dns.question.name'],
        'fqdn': ['DestinationHostname', 'QueryName', 'domain', 'dns.question.name'],
        'hostname': ['Computer', 'Hostname', 'host.name', 'host.hostname'],
        'username': ['User', 'TargetUserName', 'SubjectUserName', 'user.name', 'user.id'],
        'hash_md5': ['Hashes.MD5', 'MD5', 'hash.md5', 'file.hash.md5'],
        'hash_sha1': ['Hashes.SHA1', 'SHA1', 'hash.sha1', 'file.hash.sha1'],
        'hash_sha256': ['Hashes.SHA256', 'SHA256', 'hash.sha256', 'file.hash.sha256'],
        'command': ['CommandLine', 'command_line', 'process.command_line'],
        'filename': ['Image', 'ParentImage', 'TargetFilename', 'FileName', 'file.name', 'file.path'],
        'process_name': ['Image', 'ParentImage', 'ProcessName', 'process.name', 'process.executable'],
        'registry_key': ['TargetObject', 'registry.path', 'registry.key'],
        'email': ['TargetUserName', 'email', 'user.email'],
        'url': ['url', 'url.full', 'url.original'],
        'malware_name': ['malware.name', 'threat.name', 'ThreatName']
    }

def build_ioc_search_query(ioc, field_mapping):
    """
    Build OpenSearch query for IOC hunting.
    
    Args:
        ioc: IOC object with ioc_type, ioc_value, ioc_value_normalized
        field_mapping: Dict mapping IOC types to field names
        
    Returns:
        dict: OpenSearch query body
    """
    search_fields = field_mapping.get(ioc.ioc_type, ['*'])
    search_value = ioc.ioc_value_normalized or ioc.ioc_value.lower()
    
    # Build multi-field query
    should_clauses = []
    for field in search_fields:
        # Use match query for exact matching
        should_clauses.append({
            "match": {
                field: {
                    "query": search_value,
                    "operator": "and"
                }
            }
        })
        # Also try wildcard for partial matches (e.g., filenames)
        if ioc.ioc_type in ['filename', 'command', 'registry_key', 'url']:
            should_clauses.append({
                "wildcard": {
                    f"{field}.keyword": f"*{search_value}*"
                }
            })
    
    # CRITICAL: Add wildcard search across ALL fields to catch flattened field paths
    # e.g., EventData.Data_12.#text where Data_12.@Name might be "IpAddress"
    # Note: search_value already lowercased, provides case-insensitive matching
    should_clauses.append({
        "query_string": {
            "query": f"*{search_value}*",
            "fields": ["*"],
            "analyze_wildcard": True
        }
    })
    
    return {
        "query": {
            "bool": {
                "should": should_clauses,
                "minimum_should_match": 1
            }
        },
        "size": 1000,  # Max results per IOC
        "_source": True
    }

def find_matched_field_in_event(source, search_value, search_fields):
    """
    Find which field in the event matched the IOC value.
    
    Args:
        source: OpenSearch document _source
        search_value: IOC value to search for
        search_fields: List of field names to check
        
    Returns:
        tuple: (matched_field_name, matched_value) or ('unknown', search_value)
    """
    def search_nested_dict(d, search_val, path=''):
        """Recursively search nested dict for matching value"""
        if isinstance(d, dict):
            for key, val in d.items():
                current_path = f"{path}.{key}" if path else key
                if isinstance(val, (dict, list)):
                    result = search_nested_dict(val, search_val, current_path)
                    if result:
                        return result
                elif val and search_val.lower() in str(val).lower():
                    return (current_path, str(val))
        elif isinstance(d, list):
            for idx, item in enumerate(d):
                result = search_nested_dict(item, search_val, f"{path}[{idx}]")
                if result:
                    return result
        return None
    
    # Try specific fields first
    for field in search_fields:
        if field == '*':
            continue
        # Check nested fields
        if '.' in field:
            parts = field.split('.')
            val = source
            for part in parts:
                if isinstance(val, dict):
                    val = val.get(part)
                else:
                    val = None
                    break
            if val and search_value.lower() in str(val).lower():
                return (field, str(val)[:500])
        else:
            # Direct field
            val = source.get(field)
            if val and search_value.lower() in str(val).lower():
                return (field, str(val)[:500])
    
    # If not found in specific fields, do deep search
    result = search_nested_dict(source, search_value)
    if result:
        field_name, field_value = result
        return (field_name, field_value[:500])
    
    return ('unknown', search_value)

def extract_ioc_match_metadata(source):
    """
    Extract metadata fields from event for IOC match record.
    
    Args:
        source: OpenSearch document _source
        
    Returns:
        dict with timestamp and source_filename
    """
    # Extract timestamp - try all possible field notations
    event_timestamp = (
        source.get('System.TimeCreated.#attributes.SystemTime') or  # evtx_dump format (current)
        source.get('System.TimeCreated.@SystemTime') or  # Legacy format
        source.get('System', {}).get('TimeCreated', {}).get('@SystemTime') or  # Nested dict
        source.get('System_TimeCreated_@SystemTime') or  # Old underscore notation
        source.get('@timestamp') or  # Generic timestamp
        None
    )
    # Clean up timestamp - remove microseconds and timezone for display
    if event_timestamp and event_timestamp != 'N/A':
        # Format: "2025-09-25 05:07:08.123456+00:00" -> "2025-09-25 05:07:08"
        event_timestamp = event_timestamp.split('.')[0] if '.' in event_timestamp else event_timestamp
    
    # Extract source filename - try all possible field notations
    source_filename = (
        source.get('_casescope_metadata.filename') or  # Flattened dot notation
        source.get('_casescope_metadata', {}).get('filename') or  # Nested dict
        source.get('_casescope_metadata_filename') or  # Old underscore notation
        'Unknown'
    )
    
    return {
        'timestamp': event_timestamp,
        'filename': source_filename
    }

def enrich_events_with_ioc_flags(hits, case_id, opensearch_client, db_session, logger):
    """
    Enrich OpenSearch events with IOC match flags via bulk update.
    
    Args:
        hits: List of OpenSearch hits to enrich
        case_id: Case ID
        opensearch_client: OpenSearch client
        db_session: SQLAlchemy session
        logger: Logger instance
    """
    try:
        from main import IOCMatch
        
        logger.info(f"Enriching {len(hits)} events with IOC match flags")
        
        # Build bulk update for all matching events
        bulk_actions = []
        for hit in hits:
            event_id = hit['_id']
            event_index = hit['_index']
            
            # Get current IOC matches for this event (could be multiple IOCs)
            event_ioc_matches = db_session.query(IOCMatch).filter_by(
                case_id=case_id,
                event_id=event_id
            ).all()
            
            # Build list of matched IOC values
            ioc_values = [match.ioc.ioc_value for match in event_ioc_matches if match.ioc]
            
            # Update document with IOC match information
            bulk_actions.append({
                'update': {
                    '_index': event_index,
                    '_id': event_id
                }
            })
            bulk_actions.append({
                'doc': {
                    'has_ioc_matches': True,
                    'ioc_match_count': len(event_ioc_matches),
                    'matched_iocs': ioc_values
                },
                'doc_as_upsert': True,
                'detect_noop': False
            })
        
        if bulk_actions:
            opensearch_client.bulk(body=bulk_actions, timeout=60)
            logger.info(f"✓ Enriched {len(bulk_actions)//2} events with IOC match flags")
    except Exception as enrich_err:
        logger.warning(f"Failed to enrich events with IOC flags: {enrich_err}")


def bulk_clear_ioc_data(case_id, logger):
    """
    Bulk clear ALL IOC data for a case in one operation.
    This is used by both 'Hunt Now' and 'Re-hunt All IOCs' to ensure clean slate.
    
    Steps:
    1. Delete all IOCMatch records for case (one database query)
    2. Clear has_ioc_matches flags from all OpenSearch indices (bulk operation)
    3. Reset IOC statistics
    
    Args:
        case_id: Case ID to clear IOC data for
        logger: Logger instance for output
    
    Returns:
        dict with cleared_matches and cleared_events counts
    """
    from main import IOCMatch, IOC, CaseFile
    
    logger.info("="*80)
    logger.info(f"BULK CLEAR IOC DATA - Case ID: {case_id}")
    logger.info("="*80)
    
    try:
        # Step 1: Get all IOC matches for this case before deleting (for OpenSearch clearing)
        ioc_matches = db.session.query(IOCMatch).filter_by(case_id=case_id).all()
        match_count = len(ioc_matches)
        
        # Collect unique (index_name, event_id) tuples for OpenSearch clearing
        events_to_clear = set()
        for match in ioc_matches:
            if match.index_name and match.event_id:
                events_to_clear.add((match.index_name, match.event_id))
        
        logger.info(f"Found {match_count} IOC matches to clear across {len(events_to_clear)} unique events")
        
        # Step 2: Bulk delete ALL IOCMatch records for this case
        deleted = db.session.query(IOCMatch).filter_by(case_id=case_id).delete(synchronize_session=False)
        commit_with_retry(db.session, logger_instance=logger)
        logger.info(f"✓ Deleted {deleted} IOCMatch records from database")
        
        # Step 3: Bulk clear has_ioc_matches flags in OpenSearch
        if events_to_clear:
            from opensearchpy.helpers import bulk
            actions = []
            for index_name, event_id in events_to_clear:
                actions.append({
                    '_op_type': 'update',
                    '_index': index_name,
                    '_id': event_id,
                    'doc': {
                        'has_ioc_matches': False,
                        'ioc_match_count': 0,
                        'matched_iocs': []
                    },
                    'doc_as_upsert': False
                })
            
            if actions:
                try:
                    success, failed = bulk(opensearch_client, actions, raise_on_error=False, ignore_status=404)
                    logger.info(f"✓ Cleared IOC flags for {success} events in OpenSearch")
                    if failed:
                        logger.warning(f"Failed to clear flags for {len(failed)} events (may be deleted)")
                except Exception as e:
                    logger.warning(f"Error clearing IOC flags in OpenSearch: {e}")
        
        # Step 4: Reset IOC statistics
        iocs = db.session.query(IOC).filter_by(case_id=case_id).all()
        for ioc in iocs:
            ioc.match_count = 0
        commit_with_retry(db.session, logger_instance=logger)
        logger.info(f"✓ Reset statistics for {len(iocs)} IOCs")
        
        logger.info("="*80)
        logger.info(f"BULK CLEAR COMPLETE - Cleared {deleted} matches, {len(events_to_clear)} events")
        logger.info("="*80)
        
        return {
            'cleared_matches': deleted,
            'cleared_events': len(events_to_clear)
        }
        
    except Exception as e:
        logger.error(f"Error during bulk IOC clear: {e}")
        import traceback
        logger.error(traceback.format_exc())
        return {
            'cleared_matches': 0,
            'cleared_events': 0,
            'error': str(e)
        }


@celery_app.task(bind=True, name='tasks.hunt_iocs_for_case')
def hunt_iocs_for_case(self, case_id):
    """
    V8.1 UNIFIED IOC HUNTING
    
    This is the NEW unified IOC hunting task that replaces both:
    - Old hunt_iocs (Hunt Now button)
    - Old per-file IOC hunting (Re-hunt All IOCs button)
    
    Process:
    1. Bulk clear ALL IOC data for case (one operation)
    2. Hunt ALL IOCs across ALL files (all-fields search, v8.0.3 approach)
    3. Bulk insert matches and update OpenSearch flags
    
    This ensures:
    - Both operations use same code path
    - No duplicate matches (always clear first)
    - Consistent results (same search logic)
    - Fast performance (bulk operations)
    
    Args:
        case_id: Case ID to hunt IOCs for
        
    Returns:
        dict with status, total_iocs, matches, cleared_matches
    """
    from datetime import datetime
    import time
    
    logger.info("="*80)
    logger.info(f"V8.1 UNIFIED IOC HUNT STARTED - Case ID: {case_id}")
    logger.info("="*80)
    
    task_start_time = time.time()
    
    try:
        with app.app_context():
            # Import models
            from main import Case, IOC, IOCMatch, CaseFile
            
            # Get case
            case = db.session.get(Case, case_id)
            if not case:
                logger.error(f"Case {case_id} not found")
                return {'status': 'error', 'message': 'Case not found'}
            
            # STEP 1: BULK CLEAR ALL IOC DATA
            logger.info("STEP 1: Bulk clearing all IOC data for case")
            clear_result = bulk_clear_ioc_data(case_id, logger)
            cleared_matches = clear_result.get('cleared_matches', 0)
            logger.info(f"✓ Cleared {cleared_matches} existing IOC matches")
            
            # Get all active IOCs for this case
            iocs = db.session.query(IOC).filter_by(case_id=case_id, is_active=True).all()
            
            if not iocs:
                logger.warning(f"No active IOCs found for case {case_id}")
                return {
                    'status': 'success',
                    'message': 'No active IOCs to hunt',
                    'total_iocs': 0,
                    'matches': 0,
                    'cleared_matches': cleared_matches
                }
            
            logger.info(f"Found {len(iocs)} active IOCs to hunt")
            
            # Get all indexed files for this case
            indexed_files = db.session.query(CaseFile).filter_by(
                case_id=case_id,
                is_indexed=True,
                is_deleted=False
            ).all()
            
            if not indexed_files:
                logger.warning(f"No indexed files found for case {case_id}")
                return {
                    'status': 'success',
                    'message': 'No indexed files',
                    'total_iocs': len(iocs),
                    'matches': 0,
                    'cleared_matches': cleared_matches
                }
            
            # Use wildcard index pattern instead of listing all indices
            # Prevents HTTP line too long error with many files
            index_pattern = f"case{case_id}_*"
            logger.info(f"Searching across case indices using pattern: {index_pattern}")
            
            # STEP 2: HUNT ALL IOCs (using v8.0.3 all-fields approach)
            logger.info("="*80)
            logger.info("STEP 2: Hunting all IOCs with all-fields search")
            logger.info("="*80)
            
            total_matches = 0
            
            # Process each IOC
            for idx, ioc in enumerate(iocs, 1):
                logger.info(f"Processing IOC {idx}/{len(iocs)}: {ioc.ioc_type}={ioc.ioc_value}")
                
                # Update progress
                try:
                    if self.request.id:
                        self.update_state(
                            state='PROGRESS',
                            meta={
                                'current': idx,
                                'total': len(iocs),
                                'ioc_type': ioc.ioc_type,
                                'ioc_value': ioc.ioc_value[:50],
                                'matches': total_matches
                            }
                        )
                except (AttributeError, ValueError):
                    pass
                
                # V8.0.3 ALL-FIELDS SEARCH (not field-specific)
                search_value = ioc.ioc_value_normalized or ioc.ioc_value.lower()
                query = {
                    "query": {
                        "query_string": {
                            "query": f"*{search_value}*",
                            "default_operator": "AND",
                            "lenient": True
                        }
                    },
                    "size": 10000
                }
                
                try:
                    # Search across ALL indices using wildcard pattern
                    response = opensearch_client.search(
                        index=index_pattern,
                        body=query,
                        ignore_unavailable=True
                    )
                    
                    hits = response['hits']['hits']
                    logger.info(f"Found {len(hits)} matches for IOC {ioc.ioc_value}")
                    
                    ioc_match_count = 0
                    
                    # STEP 3: BULK INSERT MATCHES (no duplicate checks - we cleared first!)
                    for hit in hits:
                        event_id = hit['_id']
                        index_name = hit['_index']
                        source = hit['_source']
                        
                        # Extract metadata
                        metadata = extract_ioc_match_metadata(source)
                        event_timestamp = metadata['timestamp']
                        source_filename = metadata['filename']
                        
                        # Create match (no duplicate check - we cleared first!)
                        match = IOCMatch(
                            case_id=case_id,
                            ioc_id=ioc.id,
                            event_id=event_id,
                            index_name=index_name,
                            event_timestamp=event_timestamp,
                            source_filename=source_filename,
                            matched_field='all_fields',  # All-fields search
                            matched_value=ioc.ioc_value,
                            hunt_type='auto'
                        )
                        db.session.add(match)
                        ioc_match_count += 1
                    
                    # Update IOC statistics
                    ioc.match_count = ioc_match_count
                    if ioc_match_count > 0:
                        ioc.last_seen = datetime.utcnow()
                    ioc.last_hunted = datetime.utcnow()
                    
                    commit_with_retry(db.session, logger_instance=logger)
                    total_matches += ioc_match_count
                    
                    logger.info(f"✓ Created {ioc_match_count} matches for IOC {ioc.ioc_value}")
                    
                    # Enrich OpenSearch events with IOC match flags
                    if ioc_match_count > 0:
                        enrich_events_with_ioc_flags(
                            hits, case_id, opensearch_client, db.session, logger
                        )
                    
                except Exception as ioc_err:
                    logger.error(f"Error processing IOC {ioc.ioc_value}: {ioc_err}")
                    import traceback
                    logger.error(traceback.format_exc())
                    continue
            
            elapsed_time = time.time() - task_start_time
            
            logger.info("="*80)
            logger.info("V8.1 UNIFIED IOC HUNT COMPLETED")
            logger.info(f"IOCs Processed: {len(iocs)}")
            logger.info(f"Total Matches: {total_matches}")
            logger.info(f"Cleared Old Matches: {cleared_matches}")
            logger.info(f"Duration: {elapsed_time:.2f}s")
            logger.info("="*80)
            
            return {
                'status': 'success',
                'message': f'Found {total_matches} IOC matches',
                'total_iocs': len(iocs),
                'matches': total_matches,
                'cleared_matches': cleared_matches,
                'elapsed_time': elapsed_time
            }
            
    except Exception as e:
        logger.error("="*80)
        logger.error(f"IOC HUNT FAILED: {e}")
        logger.error("="*80)
        import traceback
        logger.error(traceback.format_exc())
        
        return {
            'status': 'error',
            'message': str(e),
            'total_iocs': 0,
            'matches': 0
        }


@celery_app.task(bind=True, name='tasks.hunt_iocs')
def hunt_iocs(self, case_id):
    """
    Hunt for IOCs across all indexed events in a case.
    Creates IOCMatch records for all matching events.
    
    REFACTORED: Extracted helper functions to reduce complexity:
    - get_ioc_field_mapping(): Get IOC field mappings
    - build_ioc_search_query(): Build OpenSearch query
    - find_matched_field_in_event(): Find which field matched
    - extract_ioc_match_metadata(): Extract timestamp/filename
    - enrich_events_with_ioc_flags(): Bulk update OpenSearch
    """
    from datetime import datetime
    
    logger.info("="*80)
    logger.info(f"IOC HUNT STARTED - Case ID: {case_id}")
    logger.info("="*80)
    
    try:
        with app.app_context():
            # Import models
            from main import Case, IOC, IOCMatch, CaseFile
            
            # Get case
            case = db.session.get(Case, case_id)
            if not case:
                logger.error(f"Case {case_id} not found")
                return {'status': 'error', 'message': 'Case not found'}
            
            # Get all active IOCs for this case
            iocs = db.session.query(IOC).filter_by(case_id=case_id, is_active=True).all()
            
            if not iocs:
                logger.warning(f"No active IOCs found for case {case_id}")
                return {'status': 'success', 'message': 'No active IOCs to hunt', 'total_iocs': 0, 'matches': 0}
            
            logger.info(f"Found {len(iocs)} active IOCs to hunt")
            
            # Get all indexed files for this case
            indexed_files = db.session.query(CaseFile).filter_by(case_id=case_id, is_indexed=True, is_deleted=False).all()
            
            if not indexed_files:
                logger.warning(f"No indexed files found for case {case_id}")
                return {'status': 'success', 'message': 'No indexed files', 'total_iocs': len(iocs), 'matches': 0}
            
            # Use wildcard index pattern instead of listing all indices
            # Prevents HTTP line too long error with many files
            index_pattern = f"case{case_id}_*"
            logger.info(f"Searching across case indices using pattern: {index_pattern}")
            
            # Get IOC field mappings using helper
            ioc_field_mapping = get_ioc_field_mapping()
            
            total_matches = 0
            
            # Process each IOC
            for idx, ioc in enumerate(iocs, 1):
                logger.info(f"Processing IOC {idx}/{len(iocs)}: {ioc.ioc_type}={ioc.ioc_value}")
                
                # Update progress (only if running as a Celery task with task ID)
                try:
                    if self.request.id:
                        self.update_state(
                            state='PROGRESS',
                            meta={
                                'current': idx,
                                'total': len(iocs),
                                'ioc_type': ioc.ioc_type,
                                'ioc_value': ioc.ioc_value[:50],
                                'matches': total_matches
                            }
                        )
                except (AttributeError, ValueError):
                    # Called directly (not as Celery task), skip progress updates
                    pass
                
                # Build OpenSearch query using helper
                search_value = ioc.ioc_value_normalized or ioc.ioc_value.lower()
                search_fields = ioc_field_mapping.get(ioc.ioc_type, ['*'])
                query = build_ioc_search_query(ioc, ioc_field_mapping)
                
                try:
                    # Search OpenSearch using wildcard pattern (ignore_unavailable allows searching even if some indices don't exist)
                    response = opensearch_client.search(
                        index=index_pattern,
                        body=query,
                        ignore_unavailable=True
                    )
                    
                    hits = response['hits']['hits']
                    logger.info(f"Found {len(hits)} matches for IOC {ioc.ioc_value}")
                    
                    ioc_match_count = 0
                    
                    # Create IOCMatch records for each hit using helpers
                    for hit in hits:
                        event_id = hit['_id']
                        index_name = hit['_index']
                        source = hit['_source']
                        
                        # Extract metadata using helper
                        metadata = extract_ioc_match_metadata(source)
                        event_timestamp = metadata['timestamp']
                        source_filename = metadata['filename']
                        
                        # Find matched field using helper
                        matched_field, matched_value = find_matched_field_in_event(
                            source, search_value, search_fields
                        )
                        
                        # Check if match already exists
                        existing_match = db.session.query(IOCMatch).filter_by(
                            case_id=case_id,
                            ioc_id=ioc.id,
                            event_id=event_id
                        ).first()
                        
                        if not existing_match:
                            # Create new match
                            match = IOCMatch(
                                case_id=case_id,
                                ioc_id=ioc.id,
                                event_id=event_id,
                                index_name=index_name,
                                event_timestamp=event_timestamp,
                                source_filename=source_filename,
                                matched_field=matched_field,
                                matched_value=matched_value[:500],  # Truncate long values
                                hunt_type='automatic'
                            )
                            db.session.add(match)
                            ioc_match_count += 1
                    
                    # Update IOC statistics
                    ioc.match_count = db.session.query(IOCMatch).filter_by(ioc_id=ioc.id).count()
                    if ioc_match_count > 0:
                        ioc.last_seen = datetime.utcnow()
                    ioc.last_hunted = datetime.utcnow()
                    
                    db.session.commit()
                    total_matches += ioc_match_count
                    
                    logger.info(f"Created {ioc_match_count} new matches for IOC {ioc.ioc_value}")
                    
                    # Enrich OpenSearch events with IOC match flags using helper
                    if ioc_match_count > 0:
                        enrich_events_with_ioc_flags(
                            hits, case_id, opensearch_client, db.session, logger
                        )
                    
                except Exception as e:
                    logger.error(f"Error searching for IOC {ioc.ioc_value}: {e}")
                    db.session.rollback()
                    continue
            
            logger.info("="*80)
            logger.info(f"IOC HUNT COMPLETED - Total: {total_matches} new matches")
            logger.info("="*80)
            
            return {
                'status': 'success',
                'total_iocs': len(iocs),
                'total_matches': total_matches,
                'case_id': case_id
            }
            
    except Exception as e:
        logger.error("="*80)
        logger.error(f"IOC HUNT FAILED: {e}")
        logger.error("="*80)
        import traceback
        logger.error(traceback.format_exc())
        return {'status': 'error', 'message': str(e)}


# ════════════════════════════════════════════════════════════════════════════════
# V8.0 SEQUENTIAL FILE PROCESSING - HELPER FUNCTIONS
# ════════════════════════════════════════════════════════════════════════════════
#
# These are INTERNAL helper functions (not Celery tasks)
# Called by process_file_complete master task
# Do NOT call these directly - use the master task
#
# ════════════════════════════════════════════════════════════════════════════════

# ──────────────────────────────────────────────────────────────────────────────
# INDEXING HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _index_evtx_helper(celery_task, file_id, case_file, file_path, index_name):
    """
    Index EVTX file to OpenSearch
    
    Returns:
        dict: {'status': 'success'|'error', 'event_count': int, 'message': str}
    """
    import subprocess
    import tempfile
    
    logger.info(f"[Index EVTX] Converting to JSONL: {file_path}")
    
    # Get case name once
    case = db.session.get(Case, case_file.case_id)
    case_name = case.name if case else ''
    
    jsonl_file = tempfile.mktemp(suffix='.jsonl')
    
    try:
        # Convert EVTX to JSONL
        subprocess.run([
            '/opt/casescope/bin/evtx_dump',
            '-t', '1',
            '-o', 'jsonl',
            '-f', jsonl_file,
            file_path
        ], check=True, capture_output=True, text=True, timeout=600)
        
        # Parse and index
        events = []
        event_count = 0
        record_number = 0
        last_progress = time.time()
        
        with open(jsonl_file, 'r', encoding='utf-8') as f:
            for line in f:
                record_number += 1
                try:
                    event_dict = json.loads(line)
                    if 'Event' in event_dict:
                        event_data = event_dict['Event']
                        flat_event = flatten_event(event_data)
                        flat_event = normalize_event_fields(flat_event)
                        
                        # Add event type description
                        from main import get_event_description
                        event_id = (flat_event.get('System.EventID.#text') or 
                                   flat_event.get('System.EventID') or 'N/A')
                        channel = flat_event.get('System.Channel') or ''
                        provider = (flat_event.get('System.Provider.#attributes.Name') or 
                                   flat_event.get('System.Provider') or '')
                        flat_event['event_type'] = get_event_description(event_id, channel, provider, flat_event)
                        
                        # Add metadata
                        event_record_id = (flat_event.get('System.EventRecordID') or 
                                         flat_event.get('System_EventRecordID') or record_number)
                        
                        flat_event['_casescope_metadata'] = {
                            'case_id': case_file.case_id,
                            'case_name': case_name,
                            'file_id': file_id,
                            'filename': case_file.original_filename,
                            'indexed_at': datetime.utcnow().isoformat(),
                            'record_number': str(event_record_id),
                            'source_type': 'evtx'
                        }
                        
                        events.append(flat_event)
                        event_count += 1
                        
                        # Bulk index every 100 events
                        if len(events) >= 100:
                            bulk_index_events(index_name, events)
                            events = []
                            
                            # Update progress every 5 seconds
                            if time.time() - last_progress >= 5.0:
                                case_file.event_count = event_count
                                commit_with_retry(db.session, logger_instance=logger)
                                celery_task.update_state(
                                    state='PROGRESS',
                                    meta={'current': event_count, 'total': case_file.estimated_event_count or event_count}
                                )
                                last_progress = time.time()
                
                except (json.JSONDecodeError, Exception) as e:
                    logger.warning(f"Error processing record {record_number}: {e}")
                    continue
        
        # Index remaining events
        if events:
            bulk_index_events(index_name, events)
        
        return {'status': 'success', 'event_count': event_count, 'message': f'Indexed {event_count:,} events'}
    
    finally:
        if jsonl_file and os.path.exists(jsonl_file):
            try:
                os.remove(jsonl_file)
            except:
                pass


def _index_ndjson_helper(celery_task, file_id, case_file, file_path, index_name):
    """
    Index NDJSON file to OpenSearch
    
    Returns:
        dict: {'status': 'success'|'error', 'event_count': int, 'message': str}
    """
    logger.info(f"[Index NDJSON] Processing: {file_path}")
    
    # Get case name once
    case = db.session.get(Case, case_file.case_id)
    case_name = case.name if case else ''
    
    events = []
    event_count = 0
    last_progress = time.time()
    
    with open(file_path, 'r', encoding='utf-8') as f:
        for line_num, line in enumerate(f, 1):
            if not line.strip():
                continue
            
            try:
                event_data = json.loads(line)
                flat_event = flatten_event(event_data)
                flat_event = normalize_event_fields(flat_event)
                
                # Add metadata
                flat_event['_casescope_metadata'] = {
                    'case_id': case_file.case_id,
                    'case_name': case_name,
                    'file_id': file_id,
                    'filename': case_file.original_filename,
                    'indexed_at': datetime.utcnow().isoformat(),
                    'record_number': str(line_num),
                    'source_type': 'ndjson'
                }
                
                events.append(flat_event)
                event_count += 1
                
                # Bulk index every 100 events
                if len(events) >= 100:
                    bulk_index_events(index_name, events)
                    events = []
                    
                    # Update progress every 5 seconds
                    if time.time() - last_progress >= 5.0:
                        case_file.event_count = event_count
                        commit_with_retry(db.session, logger_instance=logger)
                        celery_task.update_state(
                            state='PROGRESS',
                            meta={'current': event_count, 'total': case_file.estimated_event_count or event_count}
                        )
                        last_progress = time.time()
            
            except (json.JSONDecodeError, Exception) as e:
                logger.warning(f"Error processing line {line_num}: {e}")
                continue
    
    # Index remaining events
    if events:
        bulk_index_events(index_name, events)
    
    return {'status': 'success', 'event_count': event_count, 'message': f'Indexed {event_count:,} events'}


def _process_sigma_helper(celery_task, file_id, case_file, file_path, index_name):
    """
    Process SIGMA rules using Chainsaw
    
    Returns:
        dict: {'status': 'success'|'error', 'violations': int, 'message': str}
    """
    import subprocess
    import tempfile
    import shutil
    
    logger.info(f"[SIGMA] Processing rules for: {file_path}")
    
    # Get enabled rules
    enabled_rules = db.session.query(SigmaRule).filter_by(is_enabled=True).all()
    if not enabled_rules:
        logger.warning("[SIGMA] No enabled rules found")
        return {'status': 'success', 'violations': 0, 'message': 'No enabled rules'}
    
    logger.info(f"[SIGMA] Found {len(enabled_rules)} enabled rules")
    
    temp_dir = tempfile.mkdtemp(prefix='casescope_chainsaw_')
    
    try:
        # Export rules
        rules_dir = os.path.join(temp_dir, 'sigma_rules')
        os.makedirs(rules_dir, exist_ok=True)
        
        for rule in enabled_rules:
            rule_file = os.path.join(rules_dir, f"{rule.id}_{sanitize_filename(rule.title)}.yml")
            with open(rule_file, 'w') as f:
                f.write(rule.rule_yaml)
        
        # Run Chainsaw
        chainsaw_output = os.path.join(temp_dir, 'detections.json')
        subprocess.run([
            '/opt/casescope/bin/chainsaw',
            'hunt',
            file_path,
            '--sigma', rules_dir,
            '--mapping', '/opt/casescope/chainsaw/mappings/sigma-event-logs-all.yml',
            '--json',
            '--output', chainsaw_output
        ], check=True, capture_output=True, text=True, timeout=600)
        
        # Parse detections and create violations
        total_violations = 0
        detections_by_record = {}
        
        if os.path.exists(chainsaw_output) and os.path.getsize(chainsaw_output) > 0:
            with open(chainsaw_output, 'r') as f:
                chainsaw_results = json.load(f)
            
            for detection in chainsaw_results:
                rule_name = detection.get('name', 'Unknown')
                doc = detection.get('document', {})
                
                if not doc:
                    continue
                
                # Extract EventRecordID
                event = doc.get('data', {}).get('Event', {})
                system = event.get('System', {})
                event_record_id = str(system.get('EventRecordID', ''))
                
                if not event_record_id:
                    continue
                
                # Create violation
                import hashlib
                event_id = hashlib.sha256(f"{file_id}_{event_record_id}".encode()).hexdigest()[:16]
                
                # Find matching rule
                matching_rule = _find_matching_rule(enabled_rules, rule_name, detection.get('id', ''))
                if not matching_rule:
                    logger.warning(f"[SIGMA] Could not find rule for {rule_name}")
                    continue
                
                violation = SigmaViolation(
                    case_id=case_file.case_id,
                    file_id=file_id,
                    rule_id=matching_rule.id,
                    event_id=event_id,
                    event_data=json.dumps(doc.get('data', {})),
                    matched_fields=json.dumps({'rule_name': rule_name}),
                    severity=detection.get('level', 'medium')
                )
                db.session.add(violation)
                total_violations += 1
                
                # Track for enrichment
                if event_record_id not in detections_by_record:
                    detections_by_record[event_record_id] = []
                detections_by_record[event_record_id].append(detection)
            
            commit_with_retry(db.session, logger_instance=logger)
            
            # Enrich events
            if detections_by_record:
                enrich_events_with_detections(index_name, detections_by_record, file_id)
        
        return {'status': 'success', 'violations': total_violations, 'message': f'Found {total_violations} violations'}
    
    finally:
        if temp_dir and os.path.exists(temp_dir):
            shutil.rmtree(temp_dir)


def _find_matching_rule(enabled_rules, rule_name, rule_id_yaml):
    """Find matching rule in database"""
    for rule in enabled_rules:
        if rule.title == rule_name or rule_id_yaml in rule.rule_yaml:
            return rule
    return None


def _hunt_iocs_helper(celery_task, file_id, case_file, index_name):
    """
    Hunt for IOCs in indexed events
    
    Returns:
        dict: {'status': 'success'|'error', 'matches': int, 'message': str}
    """
    from main import IOC, IOCMatch
    
    logger.info(f"[IOC Hunt] Searching for IOCs in: {index_name}")
    
    # Get case IOCs
    iocs = db.session.query(IOC).filter_by(case_id=case_file.case_id, is_active=True).all()
    
    if not iocs:
        logger.warning("[IOC Hunt] No active IOCs found")
        return {'status': 'success', 'matches': 0, 'message': 'No active IOCs'}
    
    logger.info(f"[IOC Hunt] Found {len(iocs)} active IOCs to hunt")
    
    total_matches = 0
    
    for ioc in iocs:
        search_value = ioc.ioc_value_normalized or ioc.ioc_value.lower()
        
        # Search ALL fields - IOC can appear anywhere in event
        # Same approach as regular search (finds ALL occurrences)
        # search_value lowercased for case-insensitive matching
        query = {
            "query": {
                "query_string": {
                    "query": f"*{search_value}*",
                    "default_operator": "AND",
                    "lenient": True
                }
            },
            "size": 10000  # Increased from 1000 to handle more matches
        }
        
        try:
            response = opensearch_client.search(index=index_name, body=query)
            hits = response['hits']['hits']
            
            if hits:
                # Create IOCMatch records
                # NOTE: We don't check for duplicates because:
                # 1. ioc_only operation clears all IOC data first (no duplicates possible)
                # 2. Checking every match = hundreds/thousands of DB queries (CPU killer!)
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
                
                # Enrich events with IOC flags
                from opensearchpy.helpers import bulk as opensearch_bulk
                bulk_updates = []
                for hit in hits:
                    bulk_updates.append({
                        '_op_type': 'update',
                        '_index': index_name,
                        '_id': hit['_id'],
                        'doc': {
                            'has_ioc_matches': True,
                            'ioc_matches': [{'ioc_id': ioc.id, 'ioc_value': ioc.ioc_value, 'ioc_type': ioc.ioc_type}]
                        },
                        'doc_as_upsert': True
                    })
                
                if bulk_updates:
                    opensearch_bulk(opensearch_client, bulk_updates, raise_on_error=False)
        
        except Exception as e:
            logger.error(f"[IOC Hunt] Error searching for IOC {ioc.ioc_value}: {e}")
            continue
    
    return {'status': 'success', 'matches': total_matches, 'message': f'Found {total_matches} IOC matches'}


# ──────────────────────────────────────────────────────────────────────────────
# DATA CLEARING HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def _clear_all_file_data(file_id, case_file, index_name):
    """Clear ALL data for file (reindex operation)"""
    logger.info("[Clear Data] Removing all existing data for reindex...")
    
    # Delete OpenSearch index
    if opensearch_client.indices.exists(index=index_name):
        opensearch_client.indices.delete(index=index_name)
        logger.info(f"[Clear Data] Deleted OpenSearch index: {index_name}")
    
    # Delete SIGMA violations
    violations_deleted = db.session.query(SigmaViolation).filter_by(file_id=file_id).delete()
    if violations_deleted > 0:
        logger.info(f"[Clear Data] Deleted {violations_deleted} SIGMA violations")
    
    # Delete IOC matches
    from main import IOCMatch
    ioc_matches_deleted = db.session.query(IOCMatch).filter_by(
        source_filename=case_file.original_filename,
        case_id=case_file.case_id
    ).delete()
    if ioc_matches_deleted > 0:
        logger.info(f"[Clear Data] Deleted {ioc_matches_deleted} IOC matches")
    
    # Reset file record
    case_file.is_indexed = False
    case_file.indexed_at = None
    case_file.event_count = 0
    case_file.violation_count = 0
    case_file.estimated_event_count = None
    
    commit_with_retry(db.session, logger_instance=logger)
    logger.info("[Clear Data] ✓ All data cleared - clean slate")


def _clear_sigma_data(file_id, case_file):
    """Clear only SIGMA data (re-run rules operation)"""
    logger.info("[Clear SIGMA] Removing existing SIGMA detections...")
    
    violations_deleted = db.session.query(SigmaViolation).filter_by(file_id=file_id).delete()
    if violations_deleted > 0:
        logger.info(f"[Clear SIGMA] Deleted {violations_deleted} violations")
    
    case_file.violation_count = 0
    commit_with_retry(db.session, logger_instance=logger)
    logger.info("[Clear SIGMA] ✓ SIGMA data cleared")


def _clear_ioc_data(file_id, case_file, index_name):
    """Clear only IOC data (re-hunt operation)"""
    logger.info("[Clear IOC] Removing existing IOC matches...")
    
    from main import IOCMatch
    ioc_matches_deleted = db.session.query(IOCMatch).filter_by(
        source_filename=case_file.original_filename,
        case_id=case_file.case_id
    ).delete()
    if ioc_matches_deleted > 0:
        logger.info(f"[Clear IOC] Deleted {ioc_matches_deleted} IOC matches")
    
    commit_with_retry(db.session, logger_instance=logger)
    logger.info("[Clear IOC] ✓ IOC data cleared")


def _count_evtx_events_helper(file_path):
    """Count events in EVTX file using evtx_dump"""
    import subprocess
    
    logger.info(f"[Count] Counting EVTX events: {file_path}")
    
    result = subprocess.run(
        ['/opt/casescope/bin/evtx_dump', '-t', '1', '--no-confirm-overwrite', file_path],
        capture_output=True,
        text=True,
        timeout=300
    )
    
    if result.returncode != 0:
        raise Exception(f"evtx_dump failed: {result.stderr}")
    
    # Parse output for event count
    for line in result.stdout.split('\n'):
        if 'Parsed' in line and 'records' in line:
            parts = line.split()
            for i, part in enumerate(parts):
                if part == 'Parsed' and i+1 < len(parts):
                    count = int(parts[i+1])
                    logger.info(f"[Count] ✓ Found {count:,} events")
                    return count
    
    # Fallback: estimate from file size
    file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
    estimated = int(file_size_mb * 1000)
    logger.warning(f"[Count] Could not parse count, estimating {estimated:,} events")
    return estimated


def _count_ndjson_events_helper(file_path):
    """Count events in NDJSON file"""
    logger.info(f"[Count] Counting NDJSON events: {file_path}")
    
    count = 0
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                count += 1
    
    logger.info(f"[Count] ✓ Found {count:,} events")
    return count


# ════════════════════════════════════════════════════════════════════════════════
# V8.0 SEQUENTIAL FILE PROCESSING - MASTER TASK
# ════════════════════════════════════════════════════════════════════════════════
#
# PURPOSE: Process files sequentially (Index → SIGMA → IOC) without releasing worker
# BENEFIT: Eliminates database lock issues from parallel processing
# ARCHITECTURE: One worker owns one file completely from start to finish
#
# ════════════════════════════════════════════════════════════════════════════════

@celery_app.task(bind=True, name='tasks.process_file_complete')
def process_file_complete(self, file_id, operation='full'):
    """
    V8.0 Master Task - Sequential file processing without worker release
    
    Processes a file completely (Index → SIGMA → IOC) in ONE worker session.
    Worker is not released until file reaches 'Completed' or 'Failed' status.
    
    Args:
        file_id: CaseFile database ID
        operation: Processing type
            - 'full': Full processing (count → index → SIGMA → IOC)
            - 'reindex': Clear all data, then full processing
            - 'sigma_only': Clear SIGMA, run SIGMA → IOC
            - 'ioc_only': Clear IOC, run IOC only
    
    Status Progression:
        Queued → Estimating → Indexing → SIGMA Hunting → IOC Hunting → Completed
    
    Benefits:
        - No database locks (one worker = one file)
        - No transaction rollbacks
        - Predictable sequential processing
        - Worker failures isolated to single file
    
    Returns:
        dict: {'status': 'success'|'error', 'message': str, 'stats': dict}
    """
    import time
    import subprocess
    import tempfile
    import shutil
    
    task_start_time = time.time()
    
    logger.info("="*80)
    logger.info(f"V8.0 SEQUENTIAL FILE PROCESSING STARTED")
    logger.info(f"Task ID: {self.request.id}")
    logger.info(f"File ID: {file_id}")
    logger.info(f"Operation: {operation}")
    logger.info(f"Started at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    logger.info("="*80)
    
    with app.app_context():
        try:
            # Get file record
            case_file = db.session.get(CaseFile, file_id)
            if not case_file:
                logger.error(f"File ID {file_id} not found in database")
                return {'status': 'error', 'message': f'File ID {file_id} not found'}
            
            case = db.session.get(Case, case_file.case_id)
            if not case:
                logger.error(f"Case ID {case_file.case_id} not found")
                return {'status': 'error', 'message': f'Case not found'}
            
            filename = case_file.original_filename
            file_path = case_file.file_path
            
            logger.info(f"Processing: {filename}")
            logger.info(f"Case: {case.name}")
            logger.info(f"File path: {file_path}")
            
            # Verify file exists
            if not os.path.exists(file_path):
                case_file.indexing_status = 'Failed'
                commit_with_retry(db.session, logger_instance=logger)
                return {'status': 'error', 'message': f'File not found: {file_path}'}
            
            # Determine file type
            is_evtx = filename.lower().endswith('.evtx')
            is_ndjson = filename.lower().endswith('.ndjson')
            
            if not (is_evtx or is_ndjson):
                logger.warning(f"Unknown file type: {filename}, attempting EVTX processing")
                is_evtx = True
            
            # Generate index name
            index_name = make_index_name(case.id, filename)
            logger.info(f"Target index: {index_name}")
            
            # ═══════════════════════════════════════════════════════════════════
            # STEP 1: HANDLE OPERATION TYPE (Clear data if needed)
            # ═══════════════════════════════════════════════════════════════════
            
            if operation == 'reindex':
                logger.info("Operation: REINDEX - Clearing all existing data...")
                _clear_all_file_data(file_id, case_file, index_name)
            elif operation == 'sigma_only':
                logger.info("Operation: SIGMA ONLY - Clearing SIGMA data...")
                _clear_sigma_data(file_id, case_file)
            elif operation == 'ioc_only':
                logger.info("Operation: IOC ONLY - Clearing IOC data...")
                _clear_ioc_data(file_id, case_file, index_name)
            
            # ═══════════════════════════════════════════════════════════════════
            # STEP 2: COUNT EVENTS (if full/reindex operation)
            # ═══════════════════════════════════════════════════════════════════
            
            if operation in ['full', 'reindex']:
                logger.info("STEP: Event Counting")
                case_file.indexing_status = 'Estimating'
                commit_with_retry(db.session, logger_instance=logger)
                
                if is_evtx:
                    event_count = _count_evtx_events_helper(file_path)
                else:
                    event_count = _count_ndjson_events_helper(file_path)
                
                case_file.estimated_event_count = event_count
                commit_with_retry(db.session, logger_instance=logger)
                logger.info(f"✓ Counted {event_count:,} events")
            
            # ═══════════════════════════════════════════════════════════════════
            # STEP 3: INDEX EVENTS (if full/reindex operation)
            # ═══════════════════════════════════════════════════════════════════
            
            if operation in ['full', 'reindex']:
                logger.info("STEP: Indexing Events")
                case_file.indexing_status = 'Indexing'
                commit_with_retry(db.session, logger_instance=logger)
                
                write_audit_log('INDEX', case.name, filename, 
                              f"Started indexing est. {case_file.estimated_event_count or 'unknown'} events")
                
                if is_evtx:
                    result = _index_evtx_helper(self, file_id, case_file, file_path, index_name)
                else:
                    result = _index_ndjson_helper(self, file_id, case_file, file_path, index_name)
                
                if result['status'] == 'error':
                    case_file.indexing_status = 'Failed'
                    commit_with_retry(db.session, logger_instance=logger)
                    write_audit_log('INDEX', case.name, filename, f"ERROR: {result['message'][:100]}")
                    return result
                
                case_file.event_count = result['event_count']
                case_file.indexed_at = datetime.utcnow()
                case_file.is_indexed = True
                commit_with_retry(db.session, logger_instance=logger)
                
                write_audit_log('INDEX', case.name, filename, 
                              f"Finished indexing, {result['event_count']} events indexed")
                logger.info(f"✓ Indexed {result['event_count']:,} events")
            
            # ═══════════════════════════════════════════════════════════════════
            # STEP 4: SIGMA PROCESSING (if EVTX and not ioc_only)
            # ═══════════════════════════════════════════════════════════════════
            
            if is_evtx and operation != 'ioc_only':
                logger.info("STEP: SIGMA Rule Processing")
                case_file.indexing_status = 'SIGMA Hunting'
                commit_with_retry(db.session, logger_instance=logger)
                
                write_audit_log('SIGMA', case.name, filename, 
                              f"Started SIGMA processing est. {case_file.event_count or 'unknown'} events")
                
                result = _process_sigma_helper(self, file_id, case_file, file_path, index_name)
                
                if result['status'] == 'error':
                    case_file.indexing_status = 'Failed'
                    commit_with_retry(db.session, logger_instance=logger)
                    write_audit_log('SIGMA', case.name, filename, f"ERROR: {result['message'][:100]}")
                    return result
                
                case_file.violation_count = result['violations']
                commit_with_retry(db.session, logger_instance=logger)
                
                write_audit_log('SIGMA', case.name, filename, 
                              f"Finished SIGMA processing, {case_file.event_count} events with {result['violations']} violations")
                logger.info(f"✓ Found {result['violations']} SIGMA violations")
            else:
                if not is_evtx:
                    logger.info("STEP: SIGMA Processing - SKIPPED (NDJSON file)")
                elif operation == 'ioc_only':
                    logger.info("STEP: SIGMA Processing - SKIPPED (ioc_only operation)")
            
            # ═══════════════════════════════════════════════════════════════════
            # STEP 5: IOC HUNTING (always run unless reindex-only)
            # ═══════════════════════════════════════════════════════════════════
            
            logger.info("STEP: IOC Hunting")
            case_file.indexing_status = 'IOC Hunting'
            commit_with_retry(db.session, logger_instance=logger)
            
            write_audit_log('IOC', case.name, filename, 
                          f"Started IOC hunting est. {case_file.event_count or 'unknown'} events")
            
            result = _hunt_iocs_helper(self, file_id, case_file, index_name)
            
            if result['status'] == 'error':
                case_file.indexing_status = 'Failed'
                commit_with_retry(db.session, logger_instance=logger)
                write_audit_log('IOC', case.name, filename, f"ERROR: {result['message'][:100]}")
                return result
            
            write_audit_log('IOC', case.name, filename, 
                          f"Finished IOC hunting, {case_file.event_count} events with {result['matches']} IOC matches")
            logger.info(f"✓ Found {result['matches']} IOC matches")
            
            # ═══════════════════════════════════════════════════════════════════
            # STEP 6: MARK COMPLETED
            # ═══════════════════════════════════════════════════════════════════
            
            case_file.indexing_status = 'Completed'
            case_file.celery_task_id = None
            commit_with_retry(db.session, logger_instance=logger)
            
            task_duration = time.time() - task_start_time
            
            logger.info("="*80)
            logger.info(f"V8.0 SEQUENTIAL PROCESSING COMPLETED")
            logger.info(f"File: {filename}")
            logger.info(f"Events: {case_file.event_count:,}")
            logger.info(f"SIGMA Violations: {case_file.violation_count}")
            logger.info(f"IOC Matches: {result.get('matches', 0)}")
            logger.info(f"Duration: {task_duration:.2f} seconds ({task_duration/60:.2f} minutes)")
            logger.info("="*80)
            
            return {
                'status': 'success',
                'message': 'File processing completed',
                'stats': {
                    'event_count': case_file.event_count,
                    'violations': case_file.violation_count,
                    'ioc_matches': result.get('matches', 0),
                    'duration': task_duration
                }
            }
        
        except Exception as e:
            logger.error("="*80)
            logger.error(f"V8.0 SEQUENTIAL PROCESSING FAILED: {e}")
            logger.error("="*80)
            import traceback
            logger.error(traceback.format_exc())
            
            try:
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    case_file.indexing_status = 'Failed'
                    case_file.celery_task_id = None
                    commit_with_retry(db.session, logger_instance=logger)
            except Exception as db_err:
                logger.error(f"Failed to update file status: {db_err}")
            
            return {'status': 'error', 'message': str(e)}
