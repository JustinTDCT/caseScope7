#!/usr/bin/env python3
"""
caseScope 7.1 - Background Tasks
EVTX parsing, indexing, and SIGMA rule processing
"""

import os
import sys
import time
import json
from datetime import datetime
from celery_app import celery_app
from opensearchpy import OpenSearch, helpers
import Evtx.Evtx as evtx
import xmltodict

# Add app directory to path for imports
sys.path.insert(0, '/opt/casescope/app')
from main import app, db, CaseFile, Case

# OpenSearch connection
opensearch_client = OpenSearch(
    hosts=[{'host': 'localhost', 'port': 9200}],
    http_compress=True,
    use_ssl=False,
    verify_certs=False,
    ssl_assert_hostname=False,
    ssl_show_warn=False
)

@celery_app.task(bind=True, name='tasks.index_evtx_file')
def index_evtx_file(self, file_id):
    """
    Parse and index an EVTX file to OpenSearch
    
    Args:
        file_id: Database ID of the CaseFile to process
    """
    with app.app_context():
        try:
            # Get file record
            case_file = CaseFile.query.get(file_id)
            if not case_file:
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
            print(f"[Indexing] Starting EVTX parsing: {case_file.original_filename}")
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
                                
                                print(f"[Indexing] Progress: {event_count:,} events indexed")
                    
                    except Exception as e:
                        print(f"[Indexing] Error parsing record {record.record_num()}: {e}")
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
            
            print(f"[Indexing] Completed: {event_count:,} events indexed from {case_file.original_filename}")
            
            # Queue SIGMA rule processing
            process_sigma_rules.delay(file_id, index_name)
            
            return {
                'status': 'success',
                'message': f'Indexed {event_count:,} events',
                'event_count': event_count,
                'index_name': index_name
            }
        
        except Exception as e:
            print(f"[Indexing] Fatal error: {e}")
            import traceback
            traceback.print_exc()
            
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
    with app.app_context():
        try:
            case_file = CaseFile.query.get(file_id)
            if not case_file:
                return {'status': 'error', 'message': f'File ID {file_id} not found'}
            
            # TODO: Implement SIGMA rule processing
            # This will be implemented in Phase 4
            print(f"[Rules] SIGMA rule processing for {case_file.original_filename} (placeholder)")
            
            # For now, just mark as completed
            time.sleep(2)  # Simulate processing
            
            case_file.indexing_status = 'Completed'
            db.session.commit()
            
            print(f"[Rules] Completed processing for {case_file.original_filename}")
            
            return {
                'status': 'success',
                'message': 'SIGMA rules processed (placeholder)',
                'violations': 0
            }
        
        except Exception as e:
            print(f"[Rules] Error: {e}")
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


def bulk_index_events(index_name, events):
    """
    Bulk index events to OpenSearch
    
    Args:
        index_name: Name of the index
        events: List of event dictionaries
    """
    if not events:
        return
    
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


@celery_app.task(name='tasks.start_file_indexing')
def start_file_indexing(file_id):
    """
    Trigger to start indexing a file
    This is called immediately after file upload
    """
    return index_evtx_file.delay(file_id)
