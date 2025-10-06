#!/usr/bin/env python3
"""
DFIR-IRIS Synchronization Service
Implements the 4-step sync workflow: Company → Case → IOCs → Timeline
"""

import logging
import json
from datetime import datetime
from typing import Dict, List, Tuple
from iris_client import IrisClient
from opensearchpy import OpenSearch

logger = logging.getLogger(__name__)


# ============================================================================
# IRIS Timeline Sync Helper Functions (Refactored from _sync_timeline)
# ============================================================================

def extract_event_title_for_iris(event_data):
    """
    Extract event title from event data for IRIS timeline.
    
    Args:
        event_data: OpenSearch event document
        
    Returns:
        str: Event title
    """
    # For EVTX files: use event_type field (added during indexing)
    event_type = event_data.get('event_type')
    
    if event_type:
        return event_type
    
    # NDJSON/EDR file - build meaningful title from available fields
    command_line = event_data.get('command_line', '')
    process_name = event_data.get('process', {}).get('name', '') if isinstance(event_data.get('process'), dict) else ''
    image = event_data.get('image', '')
    
    # Try to extract just the executable name from command_line
    if command_line:
        # Get first part before space (the executable)
        exe = command_line.split()[0] if command_line.split() else command_line
        # Get just filename from path
        if '\\' in exe:
            exe = exe.split('\\')[-1]
        elif '/' in exe:
            exe = exe.split('/')[-1]
        # Remove quotes
        exe = exe.strip('"\'')
        return f"Process: {exe}"
    elif process_name:
        return f"Process: {process_name}"
    elif image:
        # Get just filename from image path
        image_name = image.split('\\')[-1] if '\\' in image else image.split('/')[-1] if '/' in image else image
        return f"Process: {image_name}"
    
    return 'EDR Event'

def format_timestamp_for_iris(raw_timestamp):
    """
    Format timestamp for DFIR-IRIS (must have exactly 6-digit microseconds, no timezone).
    
    Args:
        raw_timestamp: Raw timestamp string
        
    Returns:
        str: Formatted timestamp (YYYY-MM-DDTHH:MM:SS.mmmmmm)
    """
    event_timestamp = str(raw_timestamp)
    
    # Replace space with T (for timestamps like "2025-08-21 22:19:53")
    event_timestamp = event_timestamp.replace(' ', 'T', 1)
    
    # Remove timezone indicators from END of string only
    if event_timestamp.endswith('Z'):
        event_timestamp = event_timestamp[:-1]
    
    # Handle +HH:MM or -HH:MM timezone
    if 'T' in event_timestamp:
        date_part, time_part = event_timestamp.split('T', 1)
        if '+' in time_part:
            time_part = time_part.split('+')[0]
        elif time_part.count('-') > 0:
            parts = time_part.split('-')
            if len(parts) > 1 and ':' in parts[0]:
                time_part = parts[0]
        event_timestamp = f"{date_part}T{time_part}"
    
    # Ensure exactly 6 digits for microseconds
    if '.' in event_timestamp:
        base_time, fractional = event_timestamp.rsplit('.', 1)
        fractional = fractional.ljust(6, '0')[:6]
        event_timestamp = f"{base_time}.{fractional}"
    else:
        # No fractional seconds - add .000000
        event_timestamp = f"{event_timestamp}.000000"
    
    return event_timestamp

def extract_event_source_for_iris(event_data):
    """
    Extract event source information for IRIS timeline.
    
    Args:
        event_data: OpenSearch event document
        
    Returns:
        tuple: (filename, computer_name, combined_source)
    """
    # Get filename from metadata
    filename = event_data.get('_casescope_metadata', {}).get('filename', 'Unknown')
    
    # Extract computer/hostname - different fields for EVTX vs NDJSON
    computer = None
    
    # Try EVTX fields first
    if 'System.Computer' in event_data:
        computer = event_data['System.Computer']
    elif 'System_Computer' in event_data:
        computer = event_data['System_Computer']
    # Try NDJSON/EDR fields
    elif 'hostname' in event_data:
        computer = event_data['hostname']
    elif 'host' in event_data and isinstance(event_data['host'], dict):
        computer = event_data['host'].get('name') or event_data['host'].get('hostname')
    elif 'computer_name' in event_data:
        computer = event_data['computer_name']
    elif 'endpoint_id' in event_data:
        computer = event_data['endpoint_id']
    
    # If still no computer, try to extract from filename
    if not computer and filename and filename != 'Unknown':
        if '_' in filename:
            computer = filename.split('_')[0].replace('.ndjson', '').replace('.evtx', '')
        elif '-' in filename:
            parts = filename.split('-')
            if len(parts) >= 2:
                computer = '-'.join(parts[:-1])
    
    if not computer:
        computer = 'Unknown'
    
    # Combine filename and computer
    event_source = f"{filename}-{computer}"
    
    return (filename, computer, event_source)


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
        
        # Initialize OpenSearch client for querying event data
        self.opensearch_client = OpenSearch(
            hosts=[{'host': 'localhost', 'port': 9200}],
            http_compress=True,
            use_ssl=False,
            verify_certs=False,
            timeout=30
        )
        
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
        Verifies cached company ID still exists, creates new if not
        
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
            
            # VERIFY cached company ID still exists in IRIS
            if case.iris_company_id:
                logger.info(f"Verifying cached IRIS company ID: {case.iris_company_id}")
                try:
                    # Get all companies and check if our cached ID exists
                    companies = self.client.get_customers()
                    cached_company = next((c for c in companies if c.get('customer_id') == case.iris_company_id), None)
                    
                    if cached_company:
                        # Verify the name matches (in case it was renamed)
                        cached_name = cached_company.get('customer_name', '')
                        if cached_name.lower() == company_name.lower():
                            logger.info(f"✓ Cached company ID {case.iris_company_id} still valid")
                            return {'success': True, 'company_id': case.iris_company_id}
                        else:
                            logger.warning(f"Company name mismatch: cached='{cached_name}', current='{company_name}'")
                            logger.info("Clearing cached company ID and looking up by name")
                            case.iris_company_id = None
                    else:
                        logger.warning(f"Cached company ID {case.iris_company_id} not found in IRIS (deleted?)")
                        logger.info("Clearing cached company ID and creating new")
                        case.iris_company_id = None
                except Exception as e:
                    logger.warning(f"Failed to verify cached company ID: {str(e)}")
                    case.iris_company_id = None
            
            # Get or create company in IRIS (by name)
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
        Verifies cached case ID still exists, creates new if not
        
        Args:
            case: caseScope Case object
            iris_company_id: IRIS company ID from step 1
            db_session: Database session
            
        Returns:
            Result dict with case_id
        """
        try:
            # VERIFY cached case ID still exists in IRIS
            if case.iris_case_id:
                logger.info(f"Verifying cached IRIS case ID: {case.iris_case_id}")
                try:
                    # Get all cases and check if our cached ID exists
                    cases = self.client.get_cases()
                    cached_case = next((c for c in cases if c.get('case_id') == case.iris_case_id), None)
                    
                    if cached_case:
                        # Verify the SOC ID matches
                        cached_soc_id = cached_case.get('case_soc_id', '')
                        if cached_soc_id == case.case_number:
                            logger.info(f"✓ Cached case ID {case.iris_case_id} still valid")
                            return {'success': True, 'case_id': case.iris_case_id}
                        else:
                            logger.warning(f"Case SOC ID mismatch: cached='{cached_soc_id}', current='{case.case_number}'")
                            logger.info("Clearing cached case ID and looking up by SOC ID")
                            case.iris_case_id = None
                    else:
                        logger.warning(f"Cached case ID {case.iris_case_id} not found in IRIS (deleted?)")
                        logger.info("Clearing cached case ID and creating new")
                        case.iris_case_id = None
                except Exception as e:
                    logger.warning(f"Failed to verify cached case ID: {str(e)}")
                    case.iris_case_id = None
            
            # Get or create case in IRIS (by SOC ID)
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
        
        # Map caseScope IOC types to IRIS IOC type names (for ioc_exists check)
        type_name_mapping = {
            'ip': 'ip-any',
            'domain': 'domain',
            'fqdn': 'domain',
            'hostname': 'hostname',
            'username': 'account',
            'hash_md5': 'md5',
            'hash_sha1': 'sha1',
            'hash_sha256': 'sha256',
            'command': 'text',
            'filename': 'filename',
            'process_name': 'filename',
            'malware_name': 'malware-type',
            'registry_key': 'regkey',
            'email': 'email',
            'url': 'url'
        }
        
        synced = 0
        skipped = 0
        
        try:
            # Get all active IOCs for this case
            iocs = db_session.query(IOC).filter_by(case_id=case.id, is_active=True).all()
            
            logger.info(f"Found {len(iocs)} IOCs to sync")
            
            for ioc in iocs:
                try:
                    # Get IRIS type name for existence check
                    iris_type_name = type_name_mapping.get(ioc.ioc_type, 'other')
                    
                    # Check if IOC already exists in IRIS case
                    if self.client.ioc_exists(iris_case_id, ioc.ioc_value, iris_type_name):
                        logger.debug(f"IOC already exists: {ioc.ioc_type}={ioc.ioc_value}")
                        skipped += 1
                        continue
                    
                    # Build IOC description for IRIS
                    # Use caseScope description field + import note at bottom
                    ioc_description = ""
                    if ioc.description:
                        ioc_description = ioc.description
                    else:
                        # Fallback if no description
                        ioc_description = f"IOC: {ioc.ioc_type} - Matches: {ioc.match_count}"
                    
                    # Add import note at the bottom
                    ioc_description += f"\n\n---\nImported from caseScope"
                    
                    # Add IOC to IRIS case
                    self.client.add_ioc(
                        case_id=iris_case_id,
                        ioc_value=ioc.ioc_value,
                        ioc_type=ioc.ioc_type,  # add_ioc handles type mapping to type_id
                        ioc_description=ioc_description,
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
            from sqlalchemy import select
            tagged_events = db_session.execute(
                select(EventTag).where(EventTag.case_id == case.id)
            ).scalars().all()
            
            logger.info(f"Found {len(tagged_events)} tagged events to sync for case ID {case.id}")
            
            # Debug: Log each tagged event
            if tagged_events:
                for evt in tagged_events:
                    logger.debug(f"Tagged event: ID={evt.event_id[:12]}, timestamp={evt.event_timestamp}, type={evt.tag_type}")
            
            for event in tagged_events:
                try:
                    # Query OpenSearch to get full event data
                    event_data = {}
                    try:
                        # Try direct get with stored index name
                        os_event = self.opensearch_client.get(index=event.index_name, id=event.event_id)
                        event_data = os_event['_source']
                    except Exception as e:
                        logger.debug(f"Direct get failed for {event.event_id} in {event.index_name}: {str(e)}")
                        
                        # Fallback: Search across all case indices
                        try:
                            # Get case number from event (stored in EventTag)
                            search_result = self.opensearch_client.search(
                                index=f"case{case.id}_*",  # All indices for this case
                                body={
                                    "query": {
                                        "ids": {
                                            "values": [event.event_id]
                                        }
                                    }
                                },
                                size=1
                            )
                            
                            if search_result['hits']['total']['value'] > 0:
                                event_data = search_result['hits']['hits'][0]['_source']
                                logger.debug(f"Found event via search in index: {search_result['hits']['hits'][0]['_index']}")
                            else:
                                logger.warning(f"Event not found in any case index: {event.event_id}")
                                event_data = {}
                        except Exception as search_err:
                            logger.warning(f"Search fallback also failed for {event.event_id}: {str(search_err)}")
                            event_data = {}
                    
                    # Extract Event Information using helper
                    event_title = extract_event_title_for_iris(event_data)
                    
                    # Extract actual event timestamp from the event source
                    raw_timestamp = (
                        event_data.get('System.TimeCreated.#attributes.SystemTime') or
                        event_data.get('System.TimeCreated.@SystemTime') or
                        event_data.get('System_TimeCreated_SystemTime') or
                        event_data.get('@timestamp') or
                        event.event_timestamp
                    )
                    
                    # Format timestamp for IRIS using helper
                    event_timestamp = format_timestamp_for_iris(raw_timestamp)
                    
                    # Extract Event Source using helper
                    filename, computer, event_source = extract_event_source_for_iris(event_data)
                    
                    # Get IOC matches for this event
                    # Query IOCMatch table to find IOCs linked to this event
                    from main import IOCMatch, IOC
                    ioc_iris_ids = []
                    try:
                        ioc_matches = db_session.execute(
                            select(IOCMatch).where(IOCMatch.event_id == event.event_id)
                        ).scalars().all()
                        
                        # For each matched IOC, get the corresponding IRIS IOC ID
                        # We need to query IRIS to get the IOC ID by value
                        for match in ioc_matches:
                            ioc = db_session.execute(
                                select(IOC).where(IOC.id == match.ioc_id)
                            ).scalar_one_or_none()
                            
                            if ioc:
                                # Get IRIS IOCs for this case and find matching one
                                iris_iocs = self.client.get_case_iocs(iris_case_id)
                                for iris_ioc in iris_iocs:
                                    if iris_ioc.get('ioc_value') == ioc.ioc_value:
                                        ioc_iris_ids.append(iris_ioc.get('ioc_id'))
                                        break
                    except Exception as e:
                        logger.warning(f"Failed to get IOC matches for event {event.event_id}: {str(e)}")
                    
                    # Check if event already exists in IRIS timeline
                    if self.client.timeline_event_exists(iris_case_id, event_timestamp, event_title):
                        logger.debug(f"Timeline event already exists: {event_title}")
                        skipped += 1
                        continue
                    
                    # Build event description (first line: "Synced from caseScope")
                    event_content = "Synced from caseScope\n\n"
                    event_content += f"Tag Type: {event.tag_type}\n"
                    event_content += f"Tag Color: {event.color}\n"
                    if event.notes:
                        event_content += f"\nAnalyst Notes:\n{event.notes}\n"
                    event_content += f"\nTagged by: {event.tagged_by}\n"
                    event_content += f"Tagged at: {event.tagged_at}\n"
                    event_content += f"Event ID: {event.event_id}\n"
                    event_content += f"Index: {event.index_name}"
                    
                    # Prepare raw event data (full JSON)
                    event_raw = json.dumps(event_data, indent=2, default=str)
                    
                    # Add to IRIS timeline
                    self.client.add_timeline_event(
                        case_id=iris_case_id,
                        event_title=event_title,
                        event_date=event_timestamp,
                        event_content=event_content,
                        event_source=event_source,
                        event_raw=event_raw,
                        event_iocs=ioc_iris_ids,
                        event_in_summary=True
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


# Standalone helper functions for use in main.py

def delete_ioc_from_iris(ioc_value: str, ioc_type: str, case_id: int):
    """
    Delete an IOC from DFIR-IRIS when it's removed from caseScope
    
    Args:
        ioc_value: The IOC value to delete
        ioc_type: The IOC type
        case_id: caseScope case ID
    """
    from main import db, SystemSettings, Case
    
    # Get IRIS settings
    settings = db.session.query(SystemSettings).first()
    if not settings or not settings.iris_enabled:
        logger.debug("IRIS integration not enabled, skipping IOC deletion")
        return
    
    # Get case
    case = db.session.get(Case, case_id)
    if not case:
        logger.warning(f"Case {case_id} not found for IOC deletion")
        return
    
    try:
        # Initialize client
        client = IrisClient(settings.iris_url, settings.iris_api_key)
        
        # Get all IRIS cases to find the matching one
        iris_cases = client.get_cases()
        iris_case_id = None
        
        for iris_case in iris_cases:
            if iris_case.get('case_name') == case.name:
                iris_case_id = iris_case.get('case_id')
                break
        
        if not iris_case_id:
            logger.warning(f"Case '{case.name}' not found in IRIS, cannot delete IOC")
            return
        
        # Get all IOCs for this case in IRIS
        iris_iocs = client.get_case_iocs(iris_case_id)
        
        # Find the matching IOC
        ioc_id_to_delete = None
        for iris_ioc in iris_iocs:
            # Match by value (exact match, case-insensitive)
            if iris_ioc.get('ioc_value', '').lower() == ioc_value.lower():
                ioc_id_to_delete = iris_ioc.get('ioc_id')
                break
        
        if ioc_id_to_delete:
            # Delete the IOC from IRIS
            client.delete_case_ioc(iris_case_id, ioc_id_to_delete)
            logger.info(f"✓ Deleted IOC from DFIR-IRIS: {ioc_value} (IRIS IOC ID: {ioc_id_to_delete})")
        else:
            logger.warning(f"IOC '{ioc_value}' not found in IRIS case '{case.name}', nothing to delete")
            
    except Exception as e:
        logger.error(f"Failed to delete IOC from IRIS: {str(e)}")
        raise


def sync_case_to_iris(case_id: int):
    """
    Standalone function to sync a case to IRIS (for use in background threads)
    
    Args:
        case_id: caseScope case ID to sync
    """
    from main import db, SystemSettings, Case
    
    # Get settings
    settings = db.session.query(SystemSettings).first()
    if not settings or not settings.iris_enabled:
        return
    
    # Get case
    case = db.session.get(Case, case_id)
    if not case:
        logger.warning(f"Case {case_id} not found for sync")
        return
    
    try:
        # Initialize sync service
        sync_service = IrisSyncService(settings.iris_url, settings.iris_api_key)
        
        # Perform sync
        result = sync_service.sync_case_to_iris(case, db.session)
        
        if result['success']:
            logger.info(f"✓ Case synced to IRIS: {case.name}")
        else:
            logger.error(f"Failed to sync case to IRIS: {result.get('message')}")
            
    except Exception as e:
        logger.error(f"Error syncing case to IRIS: {str(e)}")

