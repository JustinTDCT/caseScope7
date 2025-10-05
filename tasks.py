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
CASESCOPE_FIELD_MAPPING = {
    # System fields
    'EventID': 'System.EventID.#text',
    'Provider_Name': 'System.Provider.@Name',
    'Computer': 'System.Computer',
    'Channel': 'System.Channel',
    'Level': 'System.Level',
    'Task': 'System.Task',
    'Keywords': 'System.Keywords',
    'TimeCreated': 'System.TimeCreated.@SystemTime',
    
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
        doc_id = hashlib.sha256(f"{file_id}_{record_num}".encode()).hexdigest()[:16]
        
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
                logger.error(f"Bulk update had errors!")
                for item in response.get('items', []):
                    if 'update' in item and 'error' in item['update']:
                        logger.error(f"Update error: {item['update']['error']}")
                logger.warning(f"Full response: {response}")
            else:
                logger.info(f"✓ Successfully enriched {len(detections_by_record_number)} events")
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
        doc_id = hashlib.sha256(f"{file_id}_{record_num}".encode()).hexdigest()[:16]
        
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
                            
                            # Get Event ID for description (handle both dot and underscore notation)
                            event_id = (flat_event.get('System.EventID.#text') or 
                                       flat_event.get('System_EventID_#text') or 
                                       flat_event.get('System.EventID') or 'N/A')
                            channel = (flat_event.get('System.Channel') or 
                                      flat_event.get('System_Channel') or '')
                            provider = (flat_event.get('System.Provider.@Name') or 
                                       flat_event.get('System_Provider_@Name') or '')
                            
                            # Add Event Type description for searchability
                            from main import get_event_description
                            event_description = get_event_description(event_id, channel, provider, flat_event)
                            flat_event['event_type'] = event_description
                            
                            # Add metadata
                            flat_event['_casescope_metadata'] = {
                                'case_id': case.id,
                                'case_name': case.name,
                                'file_id': case_file.id,
                                'filename': case_file.original_filename,
                                'indexed_at': datetime.utcnow().isoformat(),
                                'record_number': record_number
                            }
                            
                            events.append(flat_event)
                            event_count += 1
                            
                            # Bulk index every 100 events for faster UI updates
                            if len(events) >= 100:
                                bulk_index_events(index_name, events)
                                events = []
                                
                                # Update progress - send current/total for UI display
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
                                
                                # Log progress less frequently to reduce log spam
                                if event_count % 1000 == 0:
                                    logger.info(f"Progress: {event_count:,} / {case_file.estimated_event_count:,} events indexed")
                    
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
            case_file.indexing_status = 'Running Rules'
            db.session.commit()
            
            logger.info("="*80)
            logger.info(f"INDEXING COMPLETED: {event_count:,} events indexed from {case_file.original_filename}")
            logger.info("="*80)
            
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
                with db.session.no_autoflush:
                    for detection in chainsaw_results:
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
                            
                            # Create a unique event ID (same format as indexing uses)
                            import hashlib
                            event_id = hashlib.sha256(f"{file_id}_{event_record_id}".encode()).hexdigest()[:16]
                            
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
                                
                                # Track detections for enrichment by EventRecordID
                                if event_record_id not in detections_by_record_number:
                                    detections_by_record_number[event_record_id] = []
                                detections_by_record_number[event_record_id].append({
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
    Uses multi-field mapping: text for searching, keyword/date for sorting
    """
    mapping = {
        "mappings": {
            "properties": {
                # Timestamp field - both as text (searchable) and date (sortable)
                "System.TimeCreated.@SystemTime": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"},
                        "date": {"type": "date", "ignore_malformed": True}
                    }
                },
                # Event ID - text (searchable) and keyword (sortable/filterable)
                "System.EventID.#text": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                # Computer - text (searchable) and keyword (sortable)
                "System.Computer": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                # Channel - text (searchable) and keyword (sortable)
                "System.Channel": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                # Provider - text (searchable) and keyword (sortable)
                "System.Provider.@Name": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"}
                    }
                },
                # Level - both text and long for filtering
                "System.Level": {
                    "type": "text",
                    "fields": {
                        "keyword": {"type": "keyword"},
                        "long": {"type": "long", "ignore_malformed": True}
                    }
                },
                # Default mapping for all other fields - text with keyword subfield
                "_default_": {
                    "dynamic_templates": [
                        {
                            "strings": {
                                "match_mapping_type": "string",
                                "mapping": {
                                    "type": "text",
                                    "fields": {
                                        "keyword": {"type": "keyword", "ignore_above": 256}
                                    }
                                }
                            }
                        }
                    ]
                }
            }
        },
        "settings": {
            "index": {
                "number_of_shards": 1,
                "number_of_replicas": 0
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
            
            # Update status to Indexing
            logger.info(f"Updating status to 'Indexing' for file: {case_file.original_filename}")
            case_file.indexing_status = 'Indexing'
            case_file.event_count = 0
            db.session.commit()
            
            # Check if file exists
            if not os.path.exists(case_file.file_path):
                error_msg = f"File not found: {case_file.file_path}"
                logger.error(error_msg)
                case_file.indexing_status = 'Failed'
                db.session.commit()
                return {'status': 'error', 'message': error_msg}
            
            logger.info(f"File path: {case_file.file_path}")
            logger.info(f"File size: {case_file.file_size:,} bytes")
            
            # Create OpenSearch index name
            index_name = make_index_name(case.id, case_file.original_filename)
            logger.info(f"OpenSearch index: {index_name}")
            
            # Parse and index NDJSON
            total_events = 0
            indexed_events = 0
            batch_size = 500
            events_batch = []
            
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
                            
                            # Update progress in database
                            case_file.event_count = indexed_events
                            db.session.commit()
                            
                            logger.info(f"Indexed {indexed_events:,} / {total_events:,} events...")
                            
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

@celery_app.task(bind=True, name='tasks.hunt_iocs')
def hunt_iocs(self, case_id):
    """
    Hunt for IOCs across all indexed events in a case
    Creates IOCMatch records for all matching events
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
            
            # Build list of indices
            indices = [make_index_name(case_id, f.original_filename) for f in indexed_files]
            logger.info(f"Searching across {len(indices)} indices")
            
            # IOC field mappings - which OpenSearch fields to search for each IOC type
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
                'url': ['url', 'url.full', 'url.original']
            }
            
            total_matches = 0
            
            # Process each IOC
            for idx, ioc in enumerate(iocs, 1):
                logger.info(f"Processing IOC {idx}/{len(iocs)}: {ioc.ioc_type}={ioc.ioc_value}")
                
                # Update progress
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
                
                # Get fields to search based on IOC type
                search_fields = ioc_field_mapping.get(ioc.ioc_type, ['*'])
                
                # Build OpenSearch query - use normalized (lowercase) value for matching
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
                # This ensures we find IOCs even when they're in nested/flattened structures
                should_clauses.append({
                    "query_string": {
                        "query": f"*{search_value}*",
                        "fields": ["*"],
                        "analyze_wildcard": True
                    }
                })
                
                query = {
                    "query": {
                        "bool": {
                            "should": should_clauses,
                            "minimum_should_match": 1
                        }
                    },
                    "size": 1000,  # Max results per IOC
                    "_source": True
                }
                
                try:
                    # Search OpenSearch (ignore_unavailable allows searching even if some indices don't exist)
                    response = opensearch_client.search(
                        index=','.join(indices),
                        body=query,
                        ignore_unavailable=True
                    )
                    
                    hits = response['hits']['hits']
                    logger.info(f"Found {len(hits)} matches for IOC {ioc.ioc_value}")
                    
                    ioc_match_count = 0
                    
                    # Create IOCMatch records for each hit
                    for hit in hits:
                        event_id = hit['_id']
                        index_name = hit['_index']
                        source = hit['_source']
                        
                        # Extract timestamp - try all possible field notations
                        event_timestamp = (
                            source.get('System.TimeCreated.@SystemTime') or  # Flattened dot notation (current)
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
                        
                        # Find which field matched - recursive search through all fields
                        matched_field = 'unknown'
                        matched_value = search_value
                        
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
                        found = False
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
                                    matched_field = field
                                    matched_value = str(val)[:500]
                                    found = True
                                    break
                            else:
                                # Direct field
                                val = source.get(field)
                                if val and search_value.lower() in str(val).lower():
                                    matched_field = field
                                    matched_value = str(val)[:500]
                                    found = True
                                    break
                        
                        # If not found in specific fields, do deep search
                        if not found:
                            result = search_nested_dict(source, search_value)
                            if result:
                                matched_field, matched_value = result
                                matched_value = matched_value[:500]
                        
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
                    
                    # Enrich OpenSearch events with IOC match flags
                    if ioc_match_count > 0:
                        try:
                            logger.info(f"Enriching {ioc_match_count} events with IOC match flags for {ioc.ioc_value}")
                            
                            # Build bulk update for all matching events
                            bulk_actions = []
                            for hit in hits:
                                event_id = hit['_id']
                                event_index = hit['_index']
                                
                                # Get current IOC matches for this event (could be multiple IOCs)
                                event_ioc_matches = db.session.query(IOCMatch).filter_by(
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
