#!/usr/bin/env python3
"""
OpenCTI API Client
Handles all communication with OpenCTI for threat intelligence enrichment
"""

import logging
from typing import Optional, Dict, List, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class OpenCTIClient:
    """
    Client for interacting with OpenCTI API for indicator enrichment
    
    OpenCTI API Reference: https://docs.opencti.io/
    """
    
    def __init__(self, url: str, api_key: str, ssl_verify: bool = True):
        """
        Initialize OpenCTI client using pycti library
        
        Args:
            url: OpenCTI server URL (e.g., https://opencti.company.com)
            api_key: API authentication key
            ssl_verify: Verify SSL certificates (default: True)
        """
        try:
            from pycti import OpenCTIApiClient
            
            self.url = url.rstrip('/')
            self.api_key = api_key
            
            # Initialize the official pycti client
            self.client = OpenCTIApiClient(
                url=self.url,
                token=api_key,
                ssl_verify=ssl_verify
            )
            
            logger.info(f"OpenCTI client initialized: {self.url}")
            
        except ImportError:
            logger.error("pycti library not installed. Run: pip install pycti")
            raise Exception("pycti library required for OpenCTI integration")
        except Exception as e:
            logger.error(f"Failed to initialize OpenCTI client: {str(e)}")
            raise
    
    # ============================================================================
    # HEALTH CHECK
    # ============================================================================
    
    def ping(self) -> bool:
        """
        Test connection to OpenCTI
        
        Returns:
            True if connected and authenticated, False otherwise
        """
        try:
            # Try to get server health/info
            result = self.client.health_check()
            logger.info("OpenCTI connection successful")
            return True
        except Exception as e:
            logger.error(f"OpenCTI connection failed: {str(e)}")
            return False
    
    # ============================================================================
    # IOC TYPE MAPPING
    # ============================================================================
    
    def _map_ioc_type_to_opencti(self, casescope_type: str) -> str:
        """
        Map caseScope IOC types to OpenCTI observable types
        
        Args:
            casescope_type: IOC type from caseScope
            
        Returns:
            OpenCTI observable type string
        """
        type_mapping = {
            'ip': 'IPv4-Addr',
            'domain': 'Domain-Name',
            'fqdn': 'Domain-Name',
            'hostname': 'Hostname',
            'username': 'User-Account',
            'hash_md5': 'StixFile',
            'hash_sha1': 'StixFile',
            'hash_sha256': 'StixFile',
            'command': 'Text',
            'filename': 'StixFile',
            'process_name': 'Process',
            'malware_name': 'Malware',
            'registry_key': 'Windows-Registry-Key',
            'email': 'Email-Addr',
            'url': 'Url'
        }
        
        return type_mapping.get(casescope_type, 'Text')
    
    # ============================================================================
    # INDICATOR ENRICHMENT
    # ============================================================================
    
    def check_indicator(self, ioc_value: str, ioc_type: str) -> Dict[str, Any]:
        """
        Check if indicator exists in OpenCTI and get enrichment data
        
        Args:
            ioc_value: The indicator value (IP, domain, hash, etc.)
            ioc_type: caseScope IOC type
            
        Returns:
            Dict containing enrichment data:
            {
                'found': bool,
                'indicator_id': str,
                'name': str,
                'description': str,
                'score': int (0-100),
                'labels': list,
                'threat_actors': list,
                'campaigns': list,
                'malware_families': list,
                'created_at': str,
                'updated_at': str,
                'tlp': str,
                'confidence': int
            }
        """
        try:
            logger.info(f"Checking indicator in OpenCTI: {ioc_type}={ioc_value}")
            
            # Map to OpenCTI type
            opencti_type = self._map_ioc_type_to_opencti(ioc_type)
            
            # Search for the indicator/observable
            result = self._search_indicator(ioc_value, opencti_type)
            
            if not result:
                logger.info(f"Indicator not found in OpenCTI: {ioc_value}")
                return {
                    'found': False,
                    'message': 'Not found in OpenCTI',
                    'checked_at': datetime.utcnow().isoformat()
                }
            
            # Parse and structure the enrichment data
            enrichment = self._parse_indicator_data(result)
            enrichment['found'] = True
            enrichment['checked_at'] = datetime.utcnow().isoformat()
            
            logger.info(f"Indicator found in OpenCTI: {ioc_value} (Score: {enrichment.get('score', 'N/A')})")
            
            return enrichment
            
        except Exception as e:
            logger.error(f"Error checking indicator in OpenCTI: {str(e)}")
            return {
                'found': False,
                'error': str(e),
                'checked_at': datetime.utcnow().isoformat()
            }
    
    def _search_indicator(self, value: str, observable_type: str) -> Optional[Dict]:
        """
        Search for indicator/observable in OpenCTI
        
        Args:
            value: Indicator value
            observable_type: OpenCTI observable type
            
        Returns:
            Indicator data if found, None otherwise
        """
        try:
            # Try searching as an Indicator first (higher confidence)
            indicators = self.client.indicator.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "pattern", "values": [value], "operator": "match"}
                    ],
                    "filterGroups": []
                },
                first=10
            )
            
            if indicators and len(indicators) > 0:
                # Found as Indicator - return first match
                return indicators[0]
            
            # Try searching as Observable (lower confidence, just seen in data)
            observables = self.client.stix_cyber_observable.list(
                filters={
                    "mode": "and",
                    "filters": [
                        {"key": "value", "values": [value], "operator": "eq"}
                    ],
                    "filterGroups": []
                },
                first=10
            )
            
            if observables and len(observables) > 0:
                # Found as Observable
                return observables[0]
            
            return None
            
        except Exception as e:
            logger.warning(f"Search failed, trying alternate method: {str(e)}")
            # Fallback: try simpler search
            try:
                # Search using read method if we have an exact match
                result = self.client.stix_cyber_observable.read(
                    filters={
                        "mode": "and",
                        "filters": [
                            {"key": "value", "values": [value]}
                        ],
                        "filterGroups": []
                    }
                )
                return result
            except:
                return None
    
    def _parse_indicator_data(self, data: Dict) -> Dict[str, Any]:
        """
        Parse OpenCTI indicator data into structured enrichment
        
        Args:
            data: Raw OpenCTI indicator/observable data
            
        Returns:
            Structured enrichment dict
        """
        enrichment = {
            'indicator_id': data.get('id', ''),
            'name': data.get('name') or data.get('value', 'Unknown'),
            'description': data.get('description', ''),
            'score': self._calculate_score(data),
            'labels': self._extract_labels(data),
            'threat_actors': self._extract_related_entities(data, 'Threat-Actor'),
            'campaigns': self._extract_related_entities(data, 'Campaign'),
            'malware_families': self._extract_related_entities(data, 'Malware'),
            'created_at': data.get('created_at', ''),
            'updated_at': data.get('updated_at', ''),
            'tlp': self._extract_tlp(data),
            'confidence': data.get('confidence', 0),
            'indicator_types': data.get('indicator_types', [])
        }
        
        return enrichment
    
    def _calculate_score(self, data: Dict) -> int:
        """
        Calculate a risk score (0-100) based on OpenCTI data
        
        Higher score = more malicious
        
        Args:
            data: OpenCTI indicator data
            
        Returns:
            Risk score 0-100
        """
        score = 0
        
        # Base score from confidence
        confidence = data.get('confidence', 0)
        if confidence:
            score += min(confidence, 50)  # Max 50 points from confidence
        
        # Add score for indicator types (malicious patterns)
        indicator_types = data.get('indicator_types', [])
        malicious_types = ['malicious-activity', 'anomalous-activity', 'compromised']
        if any(t in str(indicator_types).lower() for t in malicious_types):
            score += 30
        
        # Add score for threat actor relationships
        if data.get('objectRefs') or data.get('relationships'):
            score += 20
        
        return min(score, 100)  # Cap at 100
    
    def _extract_labels(self, data: Dict) -> List[str]:
        """Extract labels/tags from indicator data"""
        labels = []
        
        # Get objectLabel
        if 'objectLabel' in data:
            obj_labels = data['objectLabel']
            if isinstance(obj_labels, list):
                labels.extend([l.get('value', '') for l in obj_labels if l.get('value')])
            elif isinstance(obj_labels, dict):
                if 'edges' in obj_labels:
                    labels.extend([edge['node']['value'] for edge in obj_labels['edges'] if 'node' in edge])
        
        # Get labels field
        if 'labels' in data:
            if isinstance(data['labels'], list):
                labels.extend(data['labels'])
        
        return list(set(labels))  # Remove duplicates
    
    def _extract_related_entities(self, data: Dict, entity_type: str) -> List[str]:
        """
        Extract related entities of specific type (threat actors, campaigns, malware)
        
        Args:
            data: Indicator data
            entity_type: Type of entity to extract (e.g., 'Threat-Actor', 'Campaign', 'Malware')
            
        Returns:
            List of entity names
        """
        entities = []
        
        # Check if we have relationships
        if 'objectRefs' in data:
            refs = data['objectRefs']
            if isinstance(refs, list):
                for ref in refs:
                    if isinstance(ref, dict) and ref.get('entity_type') == entity_type:
                        name = ref.get('name') or ref.get('value', '')
                        if name:
                            entities.append(name)
        
        return entities
    
    def _extract_tlp(self, data: Dict) -> str:
        """Extract TLP (Traffic Light Protocol) marking"""
        # Check objectMarking
        if 'objectMarking' in data:
            markings = data['objectMarking']
            if isinstance(markings, list):
                for marking in markings:
                    if isinstance(marking, dict):
                        definition = marking.get('definition', '')
                        if 'TLP' in definition.upper():
                            return definition
            elif isinstance(markings, dict) and 'edges' in markings:
                for edge in markings['edges']:
                    if 'node' in edge:
                        definition = edge['node'].get('definition', '')
                        if 'TLP' in definition.upper():
                            return definition
        
        return 'TLP:CLEAR'  # Default
    
    # ============================================================================
    # BATCH ENRICHMENT
    # ============================================================================
    
    def check_indicators_batch(self, iocs: List[Dict[str, str]]) -> Dict[str, Dict[str, Any]]:
        """
        Check multiple indicators at once
        
        Args:
            iocs: List of dicts with 'value' and 'type' keys
            
        Returns:
            Dict mapping ioc_value to enrichment data
        """
        results = {}
        
        for ioc in iocs:
            value = ioc.get('value')
            ioc_type = ioc.get('type')
            
            if value and ioc_type:
                try:
                    enrichment = self.check_indicator(value, ioc_type)
                    results[value] = enrichment
                except Exception as e:
                    logger.error(f"Error enriching {value}: {str(e)}")
                    results[value] = {
                        'found': False,
                        'error': str(e)
                    }
        
        return results
    
    # ============================================================================
    # STATISTICS
    # ============================================================================
    
    def get_statistics(self) -> Dict[str, Any]:
        """
        Get OpenCTI instance statistics
        
        Returns:
            Statistics about the OpenCTI instance
        """
        try:
            # Get various counts
            stats = {
                'connected': True,
                'url': self.url,
                'indicators_count': 0,
                'observables_count': 0,
                'threat_actors_count': 0,
                'campaigns_count': 0
            }
            
            try:
                # Try to get counts (may not work on all OpenCTI versions)
                indicators = self.client.indicator.list(first=1)
                stats['indicators_available'] = len(indicators) > 0
            except:
                pass
            
            return stats
            
        except Exception as e:
            logger.error(f"Error getting OpenCTI statistics: {str(e)}")
            return {
                'connected': False,
                'error': str(e)
            }

