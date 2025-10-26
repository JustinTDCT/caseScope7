#!/usr/bin/env python3
"""
caseScope 7.30 - Task Queue Management
Implements queued processing with 2 concurrent file limit
"""

import sys
sys.path.insert(0, '/opt/casescope/app')

from celery_app import celery_app
from celery import chain
from main import app, db, CaseFile
import logging

logger = logging.getLogger(__name__)

@celery_app.task(bind=True, name='tasks.process_file_complete')
def process_file_complete(self, file_id):
    """
    Complete file processing workflow: Index → SIGMA → IOC Hunt
    
    This wrapper task chains all processing steps and manages status updates.
    Files beyond 2 concurrent will show status='Queued' until a slot opens.
    
    Args:
        file_id: Database ID of the CaseFile to process
    
    Status Flow:
        Queued → Indexing → Running Rules → Hunting IOCs → Completed
    """
    logger.info("="*80)
    logger.info(f"COMPLETE FILE PROCESSING STARTED")
    logger.info(f"Task ID: {self.request.id}")
    logger.info(f"File ID: {file_id}")
    logger.info("="*80)
    
    with app.app_context():
        try:
            # Get file record
            case_file = db.session.get(CaseFile, file_id)
            if not case_file:
                logger.error(f"File ID {file_id} not found")
                return {'status': 'error', 'message': f'File ID {file_id} not found'}
            
            # Determine file type and index
            filename = case_file.original_filename.lower()
            
            # Update status to Indexing (task is now running)
            case_file.indexing_status = 'Indexing'
            case_file.celery_task_id = self.request.id
            db.session.commit()
            logger.info(f"Status updated: Queued → Indexing")
            
            # Step 1: Index the file
            if filename.endswith('.evtx'):
                from tasks import index_evtx_file
                index_result = index_evtx_file(file_id)
            elif filename.endswith(('.ndjson', '.json')):
                from tasks import index_ndjson_file
                index_result = index_ndjson_file(file_id)
            else:
                logger.error(f"Unsupported file type: {filename}")
                case_file.indexing_status = 'Failed'
                case_file.celery_task_id = None
                db.session.commit()
                return {'status': 'error', 'message': 'Unsupported file type'}
            
            if index_result.get('status') != 'success':
                logger.error(f"Indexing failed: {index_result}")
                case_file.celery_task_id = None
                db.session.commit()
                return index_result
            
            logger.info(f"✓ Indexing complete: {index_result.get('event_count', 0)} events")
            
            # Get index name from result
            index_name = index_result.get('index_name')
            if not index_name:
                logger.error("No index_name in index_result!")
                case_file.indexing_status = 'Failed'
                case_file.celery_task_id = None
                db.session.commit()
                return {'status': 'error', 'message': 'Missing index_name from indexing'}
            
            # Step 2: Run SIGMA rules (EVTX only)
            if filename.endswith('.evtx'):
                logger.info("Starting SIGMA rule processing...")
                case_file.indexing_status = 'Running SIGMA'
                db.session.commit()
                
                from tasks import process_sigma_rules
                sigma_result = process_sigma_rules(file_id, index_name)
                logger.info(f"✓ SIGMA complete: {sigma_result.get('violations', 0)} violations")
            else:
                logger.info("Skipping SIGMA processing (NDJSON file)")
                sigma_result = {'violations': 0}
            
            # Step 3: Hunt IOCs
            logger.info("Starting IOC hunting...")
            case_file.indexing_status = 'Hunting IOCs'
            db.session.commit()
            
            from tasks import hunt_iocs
            ioc_result = hunt_iocs(case_file.case_id)
            logger.info(f"✓ IOC hunting complete: {ioc_result.get('total_matches', 0)} matches")
            
            # Mark as completed
            case_file.indexing_status = 'Completed'
            case_file.celery_task_id = None
            db.session.commit()
            
            logger.info("="*80)
            logger.info(f"COMPLETE FILE PROCESSING FINISHED")
            logger.info(f"File ID: {file_id}")
            logger.info(f"Events: {index_result.get('event_count', 0)}")
            logger.info(f"Violations: {sigma_result.get('violations', 0) if filename.endswith('.evtx') else 'N/A'}")
            logger.info(f"IOC Matches: {ioc_result.get('total_matches', 0)}")
            logger.info("="*80)
            
            return {
                'status': 'success',
                'file_id': file_id,
                'indexed_events': index_result.get('event_count', 0),
                'violations': sigma_result.get('violations', 0) if filename.endswith('.evtx') else 0,
                'ioc_matches': ioc_result.get('total_matches', 0)
            }
            
        except Exception as e:
            logger.error(f"Complete file processing failed: {e}")
            import traceback
            logger.error(traceback.format_exc())
            
            # Update status to Failed
            try:
                case_file = db.session.get(CaseFile, file_id)
                if case_file:
                    case_file.indexing_status = 'Failed'
                    case_file.celery_task_id = None
                    db.session.commit()
            except:
                pass
            
            return {'status': 'error', 'message': str(e)}

