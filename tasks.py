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
import Evtx.Evtx as evtx
import xmltodict

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

# Add app directory to path for imports
sys.path.insert(0, '/opt/casescope/app')
logger.info("Importing Flask app and database models...")
from main import app, db, CaseFile, Case, SigmaRule, SigmaViolation
logger.info("Flask app and models imported successfully")

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

def enrich_events_with_detections(index_name, detections_by_record_number):
    """
    Enrich indexed events with SIGMA detection metadata by EventRecordID
    Adds 'sigma_detections' and 'has_violations' fields to matching events
    
    Args:
        index_name: OpenSearch index name
        detections_by_record_number: Dict mapping EventRecordID -> list of detections
    """
    logger.info(f"Enriching {len(detections_by_record_number)} events with detection metadata...")
    
    # Search OpenSearch to find actual document IDs by EventRecordID
    # Then bulk update using those IDs
    bulk_actions = []
    for record_num, detections in detections_by_record_number.items():
        # Query OpenSearch to find the document with this EventRecordID
        try:
            search_result = opensearch_client.search(
                index=index_name,
                body={
                    "query": {
                        "bool": {
                            "should": [
                                {"term": {"System_EventRecordID": str(record_num)}},
                                {"term": {"_casescope_metadata_record_number": str(record_num)}}
                            ]
                        }
                    },
                    "size": 1,
                    "_source": False
                },
                timeout=10
            )
            
            if search_result['hits']['total']['value'] > 0:
                actual_doc_id = search_result['hits']['hits'][0]['_id']
                
                action = {
                    "update": {
                        "_index": index_name,
                        "_id": actual_doc_id
                    }
                }
                doc = {
                    "doc": {
                        "sigma_detections": detections,
                        "has_violations": True,
                        "violation_count": len(detections)
                    }
                }
                
                bulk_actions.append(json.dumps(action))
                bulk_actions.append(json.dumps(doc))
        except Exception as e:
            logger.warning(f"Could not find document for EventRecordID {record_num}: {e}")
            continue
    
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
                logger.info(f"✓ Successfully enriched {len(detections_by_event)} events")
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
    Parse and index an EVTX file to OpenSearch
    
    Args:
        file_id: Database ID of the CaseFile to process
    """
    import time
    task_start_time = time.time()
    
    logger.info("="*80)
    logger.info(f"EVTX INDEXING TASK RECEIVED")
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
            
            # Parse EVTX file
            logger.info(f"Starting EVTX parsing: {case_file.original_filename}")
            logger.info(f"File path: {case_file.file_path}")
            logger.info(f"Index name: {index_name}")
            events = []
            event_count = 0
            
            with evtx.Evtx(case_file.file_path) as log:
                for record in log.records():
                    try:
                        # Parse XML to dict with size safety check
                        xml_string = record.xml()
                        
                        # Safety guard: skip oversized XML records
                        if len(xml_string) > 1048576:  # 1MB limit
                            logger.warning(f"Skipping oversized XML record {record.record_num()}: {len(xml_string)} bytes")
                            continue
                        
                        event_dict = xmltodict.parse(xml_string)
                        
                        # Extract Event data
                        if 'Event' in event_dict:
                            event_data = event_dict['Event']
                            
                            # Flatten the structure for easier searching
                            flat_event = flatten_event(event_data)
                            
                            # Get Event ID for description
                            event_id = flat_event.get('System_EventID_#text', 'N/A')
                            channel = flat_event.get('System_Channel', '')
                            provider = flat_event.get('System_Provider_@Name', '')
                            
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
                                'record_number': record.record_num()
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
                    
                    except Exception as e:
                        logger.warning(f"Error parsing record {record.record_num()}: {e}")
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
            
            # Queue SIGMA rule processing
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
            
            # Get all enabled SIGMA rules
            logger.info("Querying for enabled SIGMA rules...")
            enabled_rules = SigmaRule.query.filter_by(is_enabled=True).all()
            total_rules = SigmaRule.query.count()
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
                        existing = SigmaViolation.query.filter_by(
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
                
                # Commit all violations
                db.session.commit()
                logger.info(f"✓ Created {total_violations} violation records")
            else:
                logger.info("No detections found by Chainsaw (empty output file)")
            
            # Step 5: Enrich indexed events with detection metadata
            if detections_by_record_number:
                logger.info(f"Enriching {len(detections_by_record_number)} events with detection metadata...")
                enrich_events_with_detections(index_name, detections_by_record_number)
                logger.info(f"✓ Events enriched with detection flags")
            
            # Update file record with violation count and mark as completed
            case_file.violation_count = total_violations
            case_file.indexing_status = 'Completed'
            case_file.celery_task_id = None  # Clear task ID on completion
            db.session.commit()
            
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
            
            case_file = db.session.get(CaseFile, file_id)
            if case_file:
                case_file.indexing_status = 'Failed'
                case_file.celery_task_id = None  # Clear task ID on failure
                db.session.commit()
            
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


def bulk_index_events(index_name, events):
    """
    Bulk index events to OpenSearch
    
    Args:
        index_name: Name of the index
        events: List of event dictionaries
    """
    if not events:
        return
    
    # Ensure index exists with proper mapping
    create_index_mapping(index_name)
    
    # Prepare bulk actions
    actions = [
        {
            '_index': index_name,
            '_source': event
        }
        for event in events
    ]
    
    try:
        # Bulk index
        success, failed = helpers.bulk(
            opensearch_client,
            actions,
            raise_on_error=False,
            raise_on_exception=False
        )
        
        if failed:
            print(f"[Indexing] Warning: {len(failed)} events failed to index")
        
        return success
    
    except Exception as e:
        print(f"[Indexing] Bulk indexing error: {e}")
        raise


@celery_app.task(bind=True, name='tasks.count_evtx_events')
def count_evtx_events(self, file_id):
    """
    Count total events in EVTX file before indexing
    This provides accurate progress tracking
    """
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
            
            # Count total events
            total_events = 0
            with evtx.Evtx(case_file.file_path) as log:
                for _ in log.records():
                    total_events += 1
                    
                    # Update count every 10000 events
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
    First counts events, then indexes
    """
    return count_evtx_events.delay(file_id)
