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

def create_casescope_pipeline():
    """
    Create pySigma processing pipeline for caseScope EVTX structure
    Maps Sigma standard fields to our flattened XML structure
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

@celery_app.task(bind=True, name='tasks.index_evtx_file')
def index_evtx_file(self, file_id):
    """
    Parse and index an EVTX file to OpenSearch
    
    Args:
        file_id: Database ID of the CaseFile to process
    """
    logger.info("="*80)
    logger.info(f"STARTING EVTX INDEXING - File ID: {file_id}")
    logger.info("="*80)
    
    with app.app_context():
        try:
            # Get file record
            logger.info(f"Querying database for file ID {file_id}...")
            case_file = CaseFile.query.get(file_id)
            if not case_file:
                logger.error(f"File ID {file_id} not found in database")
                return {'status': 'error', 'message': f'File ID {file_id} not found'}
            
            case = Case.query.get(case_file.case_id)
            if not case:
                return {'status': 'error', 'message': f'Case ID {case_file.case_id} not found'}
            
            # Update status to Indexing
            case_file.indexing_status = 'Indexing'
            db.session.commit()
            
            # Generate index name: case{ID}_{filename_sanitized}
            index_name = f"case{case.id}_{sanitize_filename(case_file.original_filename)}"
            
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
                        # Parse XML to dict
                        xml_string = record.xml()
                        event_dict = xmltodict.parse(xml_string)
                        
                        # Extract Event data
                        if 'Event' in event_dict:
                            event_data = event_dict['Event']
                            
                            # Flatten the structure for easier searching
                            flat_event = flatten_event(event_data)
                            
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
                            
                            # Bulk index every 1000 events
                            if len(events) >= 1000:
                                bulk_index_events(index_name, events)
                                events = []
                                
                                # Update progress
                                case_file.event_count = event_count
                                db.session.commit()
                                
                                # Update task progress
                                self.update_state(
                                    state='PROGRESS',
                                    meta={'current': event_count, 'status': f'Indexed {event_count:,} events'}
                                )
                                
                                logger.info(f"Progress: {event_count:,} events indexed")
                    
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
            case_file = CaseFile.query.get(file_id)
            if case_file:
                case_file.indexing_status = 'Failed'
                db.session.commit()
            
            return {'status': 'error', 'message': str(e)}


@celery_app.task(bind=True, name='tasks.process_sigma_rules')
def process_sigma_rules(self, file_id, index_name):
    """
    Run SIGMA rules against indexed events
    
    Args:
        file_id: Database ID of the CaseFile
        index_name: OpenSearch index to scan
    """
    logger.info("="*80)
    logger.info(f"SIGMA RULE PROCESSING TASK RECEIVED")
    logger.info(f"Task ID: {self.request.id}")
    logger.info(f"File ID: {file_id}")
    logger.info(f"Index Name: {index_name}")
    logger.info("="*80)
    
    with app.app_context():
        try:
            logger.info(f"Querying database for CaseFile ID {file_id}...")
            case_file = CaseFile.query.get(file_id)
            if not case_file:
                logger.error(f"File ID {file_id} not found in database")
                return {'status': 'error', 'message': f'File ID {file_id} not found'}
            
            logger.info(f"Found file: {case_file.original_filename}, Case ID: {case_file.case_id}")
            logger.info(f"Current status: {case_file.indexing_status}, Indexed: {case_file.is_indexed}")
            
            case = Case.query.get(case_file.case_id)
            if not case:
                logger.error(f"Case ID {case_file.case_id} not found in database")
                return {'status': 'error', 'message': f'Case ID {case_file.case_id} not found'}
            
            logger.info(f"Processing rules for case: {case.name}")
            
            # Get all enabled SIGMA rules
            logger.info("Querying for enabled SIGMA rules...")
            enabled_rules = SigmaRule.query.filter_by(is_enabled=True).all()
            logger.info(f"Found {len(enabled_rules)} enabled SIGMA rules to process")
            
            if not enabled_rules:
                logger.info("No enabled rules found, marking as completed")
                case_file.indexing_status = 'Completed'
                db.session.commit()
                return {'status': 'success', 'message': 'No enabled rules', 'violations': 0}
            
            # Create pipeline for field mapping
            pipeline = create_casescope_pipeline()
            backend = OpensearchLuceneBackend(processing_pipeline=pipeline)
            
            total_violations = 0
            rules_processed = 0
            rules_failed = 0
            
            for rule in enabled_rules:
                try:
                    logger.info(f"Processing rule: {rule.title}")
                    
                    # Parse Sigma rule
                    try:
                        sigma_collection = SigmaCollection.from_yaml(rule.rule_yaml)
                    except Exception as e:
                        logger.warning(f"Failed to parse rule {rule.title}: {e}")
                        rules_failed += 1
                        continue
                    
                    # Convert to OpenSearch query
                    try:
                        queries = backend.convert(sigma_collection)
                        # Backend returns a list of queries (one per rule in collection)
                        if isinstance(queries, list):
                            opensearch_query = queries[0] if queries else None
                        else:
                            opensearch_query = queries
                        
                        if not opensearch_query:
                            logger.warning(f"No query generated for rule {rule.title}")
                            rules_failed += 1
                            continue
                    except Exception as e:
                        logger.warning(f"Failed to convert rule {rule.title}: {e}")
                        rules_failed += 1
                        continue
                    
                    # Execute query against index
                    try:
                        # Build complete search body
                        # pySigma backend returns a dict query, use it directly (not in query_string)
                        if isinstance(opensearch_query, dict):
                            search_body = {
                                "query": opensearch_query,
                                "size": 1000,  # Max results per rule
                                "track_total_hits": 10000  # Avoid expensive exact counts for huge result sets
                            }
                        else:
                            # Fallback for string queries
                            search_body = {
                                "query": {
                                    "query_string": {
                                        "query": opensearch_query,
                                        "analyze_wildcard": True,
                                        "default_operator": "AND"
                                    }
                                },
                                "size": 1000,
                                "track_total_hits": 10000
                            }
                        
                        logger.debug(f"Search body type: {type(opensearch_query)}, Query: {str(opensearch_query)[:200]}")
                        
                        # Execute with extended timeout for complex SIGMA queries (up to 120s)
                        response = opensearch_client.search(
                            index=index_name,
                            body=search_body,
                            request_timeout=120  # Per-request timeout for large boolean queries
                        )
                        
                        hits = response['hits']['hits']
                        logger.info(f"Rule '{rule.title}' matched {len(hits)} events")
                        
                        # Create violation records for matches
                        for hit in hits:
                            # Check if violation already exists for this event/rule combo
                            existing = SigmaViolation.query.filter_by(
                                file_id=file_id,
                                rule_id=rule.id,
                                event_id=hit['_id']
                            ).first()
                            
                            if not existing:
                                violation = SigmaViolation(
                                    case_id=case.id,
                                    file_id=file_id,
                                    rule_id=rule.id,
                                    event_id=hit['_id'],
                                    event_data=json.dumps(hit['_source']),
                                    matched_fields=json.dumps({}),  # Could extract matched fields
                                    severity=rule.level
                                )
                                db.session.add(violation)
                                total_violations += 1
                        
                        # Commit after each rule
                        db.session.commit()
                        rules_processed += 1
                        
                    except Exception as e:
                        logger.warning(f"Search failed for rule {rule.title}: {e}")
                        rules_failed += 1
                        continue
                
                except Exception as e:
                    logger.error(f"Unexpected error processing rule {rule.title}: {e}")
                    rules_failed += 1
                    continue
                
                # Update task progress
                progress = int((rules_processed + rules_failed) / len(enabled_rules) * 100)
                self.update_state(
                    state='PROGRESS',
                    meta={
                        'current': rules_processed + rules_failed,
                        'total': len(enabled_rules),
                        'violations': total_violations,
                        'status': f'Processed {rules_processed}/{len(enabled_rules)} rules'
                    }
                )
            
            # Update file record with violation count
            case_file.violation_count = total_violations
            case_file.indexing_status = 'Completed'
            db.session.commit()
            
            logger.info("="*80)
            logger.info(f"SIGMA PROCESSING COMPLETED: {total_violations} violations found")
            logger.info(f"Rules processed: {rules_processed}, Failed: {rules_failed}")
            logger.info("="*80)
            
            return {
                'status': 'success',
                'message': f'Processed {rules_processed} rules, found {total_violations} violations',
                'violations': total_violations,
                'rules_processed': rules_processed,
                'rules_failed': rules_failed
            }
        
        except Exception as e:
            logger.error("="*80)
            logger.error(f"SIGMA PROCESSING FAILED: {e}")
            logger.error("="*80)
            import traceback
            logger.error(traceback.format_exc())
            
            case_file = CaseFile.query.get(file_id)
            if case_file:
                case_file.indexing_status = 'Failed'
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
            case_file = CaseFile.query.get(file_id)
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
            case_file = CaseFile.query.get(file_id)
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
