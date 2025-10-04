#!/usr/bin/env python3
"""
DFIR-IRIS Synchronization Service
Implements the 4-step sync workflow: Company → Case → IOCs → Timeline
"""

import logging
from datetime import datetime
from typing import Dict, List, Tuple
from iris_client import IrisClient

logger = logging.getLogger(__name__)


class IrisSyncService:
    """
    Service for synchronizing caseScope data to DFIR-IRIS
    
    Workflow:
    1. Ensure company exists in IRIS (create if needed)
    2. Ensure case exists in IRIS (create if needed, bind to company)
    3. Sync IOCs to IRIS case
    4. Sync timeline tagged events to IRIS case
    """
    
    def __init__(self, iris_url: str, iris_api_key: str):
        """
        Initialize sync service
        
        Args:
            iris_url: DFIR-IRIS server URL
            iris_api_key: DFIR-IRIS API key
        """
        self.client = IrisClient(iris_url, iris_api_key)
        self.stats = {
            'companies_created': 0,
            'cases_created': 0,
            'iocs_synced': 0,
            'iocs_skipped': 0,
            'timeline_events_synced': 0,
            'timeline_events_skipped': 0,
            'errors': []
        }
    
    def sync_case_to_iris(self, case, db_session) -> Dict[str, any]:
        """
        Full sync of case to DFIR-IRIS
        Implements 4-step workflow
        
        Args:
            case: caseScope Case object
            db_session: SQLAlchemy database session
            
        Returns:
            Dictionary with sync results and statistics
        """
        from main import IOC, EventTag  # Import here to avoid circular imports
        
        logger.info(f"=" * 80)
        logger.info(f"STARTING IRIS SYNC - Case: {case.name} (ID: {case.id})")
        logger.info(f"=" * 80)
        
        try:
            # STEP 1: Ensure company exists
            logger.info("STEP 1: Company Sync")
            company_result = self._sync_company(case, db_session)
            if not company_result['success']:
                return self._build_result(False, company_result['error'])
            
            iris_company_id = company_result['company_id']
            logger.info(f"✓ Company synced (IRIS ID: {iris_company_id})")
            
            # STEP 2: Ensure case exists
            logger.info("STEP 2: Case Sync")
            case_result = self._sync_case(case, iris_company_id, db_session)
            if not case_result['success']:
                return self._build_result(False, case_result['error'])
            
            iris_case_id = case_result['case_id']
            logger.info(f"✓ Case synced (IRIS ID: {iris_case_id})")
            
            # STEP 3: Sync IOCs
            logger.info("STEP 3: IOC Sync")
            ioc_result = self._sync_iocs(case, iris_case_id, db_session)
            logger.info(f"✓ IOCs synced: {ioc_result['synced']} new, {ioc_result['skipped']} already exist")
            
            # STEP 4: Sync timeline events
            logger.info("STEP 4: Timeline Sync")
            timeline_result = self._sync_timeline(case, iris_case_id, db_session)
            logger.info(f"✓ Timeline synced: {timeline_result['synced']} new, {timeline_result['skipped']} already exist")
            
            # Update case with sync timestamp
            case.iris_synced_at = datetime.utcnow()
            db_session.commit()
            
            logger.info(f"=" * 80)
            logger.info(f"SYNC COMPLETED SUCCESSFULLY")
            logger.info(f"=" * 80)
            
            return self._build_result(True, "Sync completed successfully", {
                'iris_company_id': iris_company_id,
                'iris_case_id': iris_case_id,
                'iocs_synced': ioc_result['synced'],
                'iocs_skipped': ioc_result['skipped'],
                'timeline_synced': timeline_result['synced'],
                'timeline_skipped': timeline_result['skipped']
            })
            
        except Exception as e:
            error_msg = f"Sync failed: {str(e)}"
            logger.error(error_msg)
            self.stats['errors'].append(error_msg)
            return self._build_result(False, error_msg)
    
    def _sync_company(self, case, db_session) -> Dict[str, any]:
        """
        Step 1: Ensure company exists in DFIR-IRIS
        
        Args:
            case: caseScope Case object
            db_session: Database session
            
        Returns:
            Result dict with company_id
        """
        try:
            # Check if case has company name
            if not case.company:
                # Use default company name
                company_name = "Default Organization"
                logger.warning(f"Case has no company, using default: {company_name}")
            else:
                company_name = case.company
            
            # Check if we already have IRIS company ID
            if case.iris_company_id:
                logger.info(f"Using cached IRIS company ID: {case.iris_company_id}")
                return {'success': True, 'company_id': case.iris_company_id}
            
            # Get or create company in IRIS
            company = self.client.get_or_create_customer(company_name)
            
            if 'customer_id' in company:
                iris_company_id = company['customer_id']
            elif 'id' in company:
                iris_company_id = company['id']
            else:
                raise Exception(f"Company creation response missing ID: {company}")
            
            # Update case with IRIS company ID
            case.iris_company_id = iris_company_id
            db_session.commit()
            
            self.stats['companies_created'] += 1
            
            return {'success': True, 'company_id': iris_company_id}
            
        except Exception as e:
            logger.error(f"Company sync failed: {str(e)}")
            return {'success': False, 'error': f"Company sync failed: {str(e)}"}
    
    def _sync_case(self, case, iris_company_id: int, db_session) -> Dict[str, any]:
        """
        Step 2: Ensure case exists in DFIR-IRIS and is bound to company
        
        Args:
            case: caseScope Case object
            iris_company_id: IRIS company ID from step 1
            db_session: Database session
            
        Returns:
            Result dict with case_id
        """
        try:
            # Check if we already have IRIS case ID
            if case.iris_case_id:
                logger.info(f"Using cached IRIS case ID: {case.iris_case_id}")
                return {'success': True, 'case_id': case.iris_case_id}
            
            # Get or create case in IRIS
            iris_case = self.client.get_or_create_case(
                soc_id=case.case_number,
                name=case.name,
                customer_id=iris_company_id,
                description=case.description or f"Case synced from caseScope - Priority: {case.priority}, Status: {case.status}"
            )
            
            if 'case_id' in iris_case:
                iris_case_id = iris_case['case_id']
            elif 'id' in iris_case:
                iris_case_id = iris_case['id']
            else:
                raise Exception(f"Case creation response missing ID: {iris_case}")
            
            # Update case with IRIS case ID
            case.iris_case_id = iris_case_id
            db_session.commit()
            
            self.stats['cases_created'] += 1
            
            return {'success': True, 'case_id': iris_case_id}
            
        except Exception as e:
            logger.error(f"Case sync failed: {str(e)}")
            return {'success': False, 'error': f"Case sync failed: {str(e)}"}
    
    def _sync_iocs(self, case, iris_case_id: int, db_session) -> Dict[str, int]:
        """
        Step 3: Sync all IOCs from caseScope case to DFIR-IRIS case
        
        Args:
            case: caseScope Case object
            iris_case_id: IRIS case ID from step 2
            db_session: Database session
            
        Returns:
            Dict with synced and skipped counts
        """
        from main import IOC  # Import here to avoid circular imports
        
        synced = 0
        skipped = 0
        
        try:
            # Get all active IOCs for this case
            iocs = db_session.query(IOC).filter_by(case_id=case.id, is_active=True).all()
            
            logger.info(f"Found {len(iocs)} IOCs to sync")
            
            for ioc in iocs:
                try:
                    # Check if IOC already exists in IRIS case
                    if self.client.ioc_exists(iris_case_id, ioc.ioc_value, ioc.ioc_type):
                        logger.debug(f"IOC already exists: {ioc.ioc_type}={ioc.ioc_value}")
                        skipped += 1
                        continue
                    
                    # Add IOC to IRIS case
                    self.client.add_ioc(
                        case_id=iris_case_id,
                        ioc_value=ioc.ioc_value,
                        ioc_type=ioc.ioc_type,
                        ioc_description=ioc.notes or f"IOC synced from caseScope - Matches: {ioc.match_count}",
                        ioc_tags=f"casescope,priority-{case.priority.lower()}"
                    )
                    
                    logger.debug(f"Synced IOC: {ioc.ioc_type}={ioc.ioc_value}")
                    synced += 1
                    
                except Exception as e:
                    logger.warning(f"Failed to sync IOC {ioc.ioc_value}: {str(e)}")
                    self.stats['errors'].append(f"IOC sync error: {ioc.ioc_value} - {str(e)}")
                    continue
            
            self.stats['iocs_synced'] += synced
            self.stats['iocs_skipped'] += skipped
            
            return {'synced': synced, 'skipped': skipped}
            
        except Exception as e:
            logger.error(f"IOC sync failed: {str(e)}")
            self.stats['errors'].append(f"IOC sync error: {str(e)}")
            return {'synced': synced, 'skipped': skipped}
    
    def _sync_timeline(self, case, iris_case_id: int, db_session) -> Dict[str, int]:
        """
        Step 4: Sync tagged events from caseScope to DFIR-IRIS timeline
        
        Args:
            case: caseScope Case object
            iris_case_id: IRIS case ID from step 2
            db_session: Database session
            
        Returns:
            Dict with synced and skipped counts
        """
        from main import EventTag  # Import here to avoid circular imports
        
        synced = 0
        skipped = 0
        
        try:
            # Get all tagged events for this case
            tagged_events = db_session.query(EventTag).filter_by(case_id=case.id).all()
            
            logger.info(f"Found {len(tagged_events)} tagged events to sync")
            
            for event in tagged_events:
                try:
                    # Build event title from tag type
                    event_title = f"[{event.tag_type}] Event {event.event_id[:8]}"
                    
                    # Check if event already exists in IRIS timeline
                    if self.client.timeline_event_exists(iris_case_id, event.event_timestamp, event_title):
                        logger.debug(f"Timeline event already exists: {event_title}")
                        skipped += 1
                        continue
                    
                    # Build event content
                    event_content = f"Tagged event from caseScope\\n\\n"
                    event_content += f"Event ID: {event.event_id}\\n"
                    event_content += f"Tag Type: {event.tag_type}\\n"
                    event_content += f"Color: {event.color}\\n"
                    if event.notes:
                        event_content += f"\\nNotes:\\n{event.notes}\\n"
                    event_content += f"\\nTagged by: {event.tagged_by}\\n"
                    event_content += f"Index: {event.index_name}"
                    
                    # Add to IRIS timeline
                    self.client.add_timeline_event(
                        case_id=iris_case_id,
                        event_title=event_title,
                        event_date=event.event_timestamp,
                        event_content=event_content,
                        event_source="caseScope"
                    )
                    
                    logger.debug(f"Synced timeline event: {event_title}")
                    synced += 1
                    
                except Exception as e:
                    logger.warning(f"Failed to sync timeline event {event.event_id}: {str(e)}")
                    self.stats['errors'].append(f"Timeline sync error: {event.event_id} - {str(e)}")
                    continue
            
            self.stats['timeline_events_synced'] += synced
            self.stats['timeline_events_skipped'] += skipped
            
            return {'synced': synced, 'skipped': skipped}
            
        except Exception as e:
            logger.error(f"Timeline sync failed: {str(e)}")
            self.stats['errors'].append(f"Timeline sync error: {str(e)}")
            return {'synced': synced, 'skipped': skipped}
    
    def _build_result(self, success: bool, message: str, data: Dict = None) -> Dict[str, any]:
        """
        Build standardized result dictionary
        
        Args:
            success: Success status
            message: Result message
            data: Additional data (optional)
            
        Returns:
            Result dictionary
        """
        result = {
            'success': success,
            'message': message,
            'stats': self.stats
        }
        
        if data:
            result.update(data)
        
        return result
    
    def get_stats(self) -> Dict[str, any]:
        """
        Get current sync statistics
        
        Returns:
            Statistics dictionary
        """
        return self.stats.copy()

