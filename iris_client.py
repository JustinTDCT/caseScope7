#!/usr/bin/env python3
"""
DFIR-IRIS API Client
Handles all communication with DFIR-IRIS API for case/IOC/timeline synchronization
"""

import requests
import logging
from typing import Optional, Dict, List, Any

logger = logging.getLogger(__name__)


class IrisClient:
    """
    Client for interacting with DFIR-IRIS API
    
    DFIR-IRIS API Reference: https://docs.dfir-iris.org/
    """
    
    def __init__(self, base_url: str, api_key: str):
        """
        Initialize IRIS client
        
        Args:
            base_url: DFIR-IRIS server URL (e.g., https://iris.company.com)
            api_key: API authentication key
        """
        import urllib3
        from urllib3.exceptions import InsecureRequestWarning
        
        # Suppress SSL warnings for self-signed certificates
        urllib3.disable_warnings(InsecureRequestWarning)
        
        self.base_url = base_url.rstrip('/')
        self.api_key = api_key
        self.session = requests.Session()
        self.session.headers.update({
            'Authorization': f'Bearer {api_key}',
            'Content-Type': 'application/json'
        })
        # Disable SSL verification for self-signed certificates (common in internal deployments)
        self.session.verify = False
    
    def _request(self, method: str, endpoint: str, **kwargs) -> Dict[str, Any]:
        """
        Make API request with error handling
        
        Args:
            method: HTTP method (GET, POST, PUT, DELETE)
            endpoint: API endpoint path
            **kwargs: Additional arguments for requests
            
        Returns:
            Response JSON data
            
        Raises:
            Exception: On API errors
        """
        url = f"{self.base_url}{endpoint}"
        
        try:
            response = self.session.request(method, url, timeout=30, **kwargs)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            logger.error(f"IRIS API timeout: {method} {endpoint}")
            raise Exception("DFIR-IRIS connection timeout")
        except requests.exceptions.ConnectionError:
            logger.error(f"IRIS API connection error: {method} {endpoint}")
            raise Exception("Cannot connect to DFIR-IRIS server")
        except requests.exceptions.HTTPError as e:
            logger.error(f"IRIS API HTTP error: {e.response.status_code} - {e.response.text}")
            raise Exception(f"DFIR-IRIS API error: {e.response.status_code}")
        except Exception as e:
            logger.error(f"IRIS API error: {str(e)}")
            raise
    
    # ============================================================================
    # COMPANY/CUSTOMER OPERATIONS
    # ============================================================================
    
    def get_customers(self) -> List[Dict[str, Any]]:
        """
        Get list of all customers/companies
        
        Returns:
            List of customer objects
        """
        response = self._request('GET', '/manage/customers/list')
        return response.get('data', [])
    
    def get_customer_by_name(self, name: str) -> Optional[Dict[str, Any]]:
        """
        Find customer by name (case-insensitive)
        
        Args:
            name: Customer name to search for
            
        Returns:
            Customer object if found, None otherwise
        """
        customers = self.get_customers()
        name_lower = name.lower()
        
        for customer in customers:
            if customer.get('customer_name', '').lower() == name_lower:
                return customer
        
        return None
    
    def create_customer(self, name: str, description: str = "") -> Dict[str, Any]:
        """
        Create new customer/company in DFIR-IRIS
        
        Args:
            name: Customer name
            description: Customer description (optional)
            
        Returns:
            Created customer object with customer_id
        """
        data = {
            'customer_name': name,
            'customer_description': description or f'Auto-created from caseScope for {name}'
        }
        
        response = self._request('POST', '/manage/customers/add', json=data)
        return response.get('data', {})
    
    def get_or_create_customer(self, name: str) -> Dict[str, Any]:
        """
        Get existing customer or create if doesn't exist
        
        Args:
            name: Customer name
            
        Returns:
            Customer object with customer_id
        """
        # Try to find existing
        customer = self.get_customer_by_name(name)
        if customer:
            logger.info(f"Found existing IRIS customer: {name} (ID: {customer['customer_id']})")
            return customer
        
        # Create new
        logger.info(f"Creating new IRIS customer: {name}")
        customer = self.create_customer(name)
        logger.info(f"Created IRIS customer: {name} (ID: {customer['customer_id']})")
        return customer
    
    # ============================================================================
    # CASE OPERATIONS
    # ============================================================================
    
    def get_cases(self, customer_id: int = None) -> List[Dict[str, Any]]:
        """
        Get list of cases, optionally filtered by customer
        
        Args:
            customer_id: Filter by customer ID (optional)
            
        Returns:
            List of case objects
        """
        response = self._request('GET', '/manage/cases/list')
        cases = response.get('data', [])
        
        if customer_id:
            cases = [c for c in cases if c.get('customer_id') == customer_id]
        
        return cases
    
    def get_case_by_soc_id(self, soc_id: str, customer_id: int = None) -> Optional[Dict[str, Any]]:
        """
        Find case by SOC ID (case number)
        
        Args:
            soc_id: Case SOC ID to search for
            customer_id: Filter by customer ID (optional)
            
        Returns:
            Case object if found, None otherwise
        """
        cases = self.get_cases(customer_id)
        
        for case in cases:
            if case.get('case_soc_id') == soc_id:
                return case
        
        return None
    
    def create_case(self, soc_id: str, name: str, customer_id: int, 
                   description: str = "", classification: int = 1) -> Dict[str, Any]:
        """
        Create new case in DFIR-IRIS
        
        Args:
            soc_id: Case SOC ID (case number)
            name: Case name
            customer_id: Customer ID to associate case with
            description: Case description (optional)
            classification: Case classification (default: 1)
            
        Returns:
            Created case object with case_id
        """
        data = {
            'case_soc_id': soc_id,
            'case_name': name,
            'case_customer': customer_id,
            'case_description': description or f'Synced from caseScope: {name}',
            'case_classification': classification
        }
        
        response = self._request('POST', '/manage/cases/add', json=data)
        return response.get('data', {})
    
    def get_or_create_case(self, soc_id: str, name: str, customer_id: int, 
                          description: str = "") -> Dict[str, Any]:
        """
        Get existing case or create if doesn't exist
        
        Args:
            soc_id: Case SOC ID
            name: Case name
            customer_id: Customer ID
            description: Case description
            
        Returns:
            Case object with case_id
        """
        # Try to find existing
        case = self.get_case_by_soc_id(soc_id, customer_id)
        if case:
            logger.info(f"Found existing IRIS case: {soc_id} (ID: {case['case_id']})")
            return case
        
        # Create new
        logger.info(f"Creating new IRIS case: {soc_id}")
        case = self.create_case(soc_id, name, customer_id, description)
        logger.info(f"Created IRIS case: {soc_id} (ID: {case['case_id']})")
        return case
    
    # ============================================================================
    # IOC OPERATIONS
    # ============================================================================
    
    def get_case_iocs(self, case_id: int) -> List[Dict[str, Any]]:
        """
        Get all IOCs for a specific case
        
        Args:
            case_id: IRIS case ID
            
        Returns:
            List of IOC objects
        """
        response = self._request('GET', f'/case/ioc/list?cid={case_id}')
        return response.get('data', {}).get('ioc', [])
    
    def ioc_exists(self, case_id: int, ioc_value: str, ioc_type_name: str) -> bool:
        """
        Check if IOC already exists in case
        
        Args:
            case_id: IRIS case ID
            ioc_value: IOC value to check
            ioc_type_name: IOC type name (e.g., 'ip-any', 'account', 'filename')
            
        Returns:
            True if IOC exists, False otherwise
        """
        iocs = self.get_case_iocs(case_id)
        
        for ioc in iocs:
            # ioc_type is returned as a string directly, not an object
            if (ioc.get('ioc_value') == ioc_value and 
                ioc.get('ioc_type') == ioc_type_name):
                return True
        
        return False
    
    def get_ioc_types(self) -> List[Dict[str, Any]]:
        """
        Get available IOC types from IRIS
        
        Returns:
            List of IOC type objects with id and type_name
        """
        response = self._request('GET', '/manage/ioc-types/list')
        return response.get('data', [])
    
    def add_ioc(self, case_id: int, ioc_value: str, ioc_type: str, 
                ioc_description: str = "", ioc_tags: str = "", 
                ioc_tlp: int = 2) -> Dict[str, Any]:
        """
        Add IOC to case
        
        Args:
            case_id: IRIS case ID
            ioc_value: IOC value (IP, domain, hash, etc.)
            ioc_type: IOC type from caseScope (will be mapped to IRIS type ID)
            ioc_description: IOC description (optional)
            ioc_tags: Comma-separated tags (optional)
            ioc_tlp: TLP level (0=white, 1=green, 2=amber, 3=red)
            
        Returns:
            Created IOC object
        """
        # Map caseScope IOC types to IRIS IOC type IDs
        # Based on actual DFIR-IRIS installation IOC types
        type_id_mapping = {
            'ip': 76,                  # ip-any (source or destination IP)
            'domain': 20,              # domain
            'fqdn': 20,                # domain
            'hostname': 69,            # hostname
            'username': 3,             # account
            'hash_md5': 90,            # md5
            'hash_sha1': 111,          # sha1
            'hash_sha256': 113,        # sha256
            'command': 135,            # text (no specific command-line type)
            'filename': 37,            # filename
            'process_name': 37,        # filename
            'malware_name': 89,        # malware-type
            'registry_key': 109,       # regkey
            'email': 22,               # email
            'url': 141                 # url
        }
        
        ioc_type_id = type_id_mapping.get(ioc_type)
        if not ioc_type_id:
            logger.warning(f"Unknown IOC type '{ioc_type}', defaulting to 'other' (ID: 1)")
            ioc_type_id = 1  # 'other' type
        
        data = {
            'ioc_value': ioc_value,
            'ioc_type_id': ioc_type_id,
            'ioc_description': ioc_description or f'Synced from caseScope',
            'ioc_tags': ioc_tags,
            'ioc_tlp_id': ioc_tlp,
            'cid': case_id
        }
        
        response = self._request('POST', '/case/ioc/add', json=data)
        return response.get('data', {})
    
    def delete_case_ioc(self, case_id: int, ioc_id: int) -> bool:
        """
        Delete an IOC from a case
        
        Args:
            case_id: IRIS case ID
            ioc_id: IRIS IOC ID to delete
            
        Returns:
            True if successful, False otherwise
        """
        try:
            # DFIR-IRIS API endpoint for IOC deletion
            endpoint = f'/case/ioc/delete/{ioc_id}'
            data = {'cid': case_id}
            response = self._request('POST', endpoint, json=data)
            return response.get('success', False)
        except Exception as e:
            logger.error(f"Failed to delete IOC {ioc_id} from case {case_id}: {str(e)}")
            return False
    
    # ============================================================================
    # TIMELINE OPERATIONS
    # ============================================================================
    
    def get_timeline_events(self, case_id: int) -> List[Dict[str, Any]]:
        """
        Get timeline events for a case
        
        Args:
            case_id: IRIS case ID
            
        Returns:
            List of timeline event objects
        """
        response = self._request('GET', f'/case/timeline/events/list?cid={case_id}')
        return response.get('data', {}).get('timeline', [])
    
    def timeline_event_exists(self, case_id: int, event_timestamp: str, 
                             event_title: str) -> bool:
        """
        Check if timeline event already exists (by timestamp and title)
        
        Args:
            case_id: IRIS case ID
            event_timestamp: Event timestamp
            event_title: Event title
            
        Returns:
            True if event exists, False otherwise
        """
        events = self.get_timeline_events(case_id)
        
        for event in events:
            if (event.get('event_date') == event_timestamp and 
                event.get('event_title') == event_title):
                return True
        
        return False
    
    def add_timeline_event(self, case_id: int, event_title: str, event_date: str,
                          event_content: str = "", event_source: str = "caseScope",
                          event_category: int = 1, event_raw: str = "", 
                          event_iocs: List[int] = None, event_in_summary: bool = True) -> Dict[str, Any]:
        """
        Add event to case timeline
        
        Args:
            case_id: IRIS case ID
            event_title: Event title/summary
            event_date: Event timestamp (must include microseconds: YYYY-MM-DDTHH:MM:SS.mmmmmm)
            event_content: Event description/details
            event_source: Event source (default: caseScope)
            event_category: Event category ID (default: 1)
            event_raw: Raw event data (full JSON/NDJSON)
            event_iocs: List of IRIS IOC IDs to link to this event
            event_in_summary: Whether event should appear in summary (default: True)
            
        Returns:
            Created timeline event object
        """
        # Ensure event_date has microseconds format: YYYY-MM-DDTHH:MM:SS.mmmmmm
        if '.' not in event_date:
            # Add .000000 if no microseconds present
            if 'T' in event_date:
                event_date = event_date + '.000000'
            else:
                # If it's just a date, add time and microseconds
                event_date = event_date + 'T00:00:00.000000'
        
        data = {
            'event_title': event_title,
            'event_date': event_date,
            'event_tz': '+00:00',  # UTC timezone
            'event_content': event_content or 'Tagged event from caseScope',
            'event_source': event_source,
            'event_category_id': event_category,
            'event_assets': [],  # Required field
            'event_iocs': event_iocs or [],  # Link to IOCs in IRIS
            'event_in_summary': event_in_summary,  # Add to summary by default
            'cid': case_id
        }
        
        # Add raw event data if provided
        if event_raw:
            data['event_raw'] = event_raw
        
        response = self._request('POST', '/case/timeline/events/add', json=data)
        return response.get('data', {})
    
    # ============================================================================
    # HEALTH CHECK
    # ============================================================================
    
    def ping(self) -> bool:
        """
        Test connection to DFIR-IRIS
        
        Returns:
            True if connected, False otherwise
        """
        try:
            self._request('GET', '/api/ping')
            return True
        except:
            return False

