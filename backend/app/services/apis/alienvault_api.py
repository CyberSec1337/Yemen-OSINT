"""
AlienVault OTX API integration for threat intelligence pulses.
"""

import requests
from datetime import datetime
from typing import Dict, List, Any
from .base import BaseAPIService
from app.models.result import Severity


class AlienVaultAPI(BaseAPIService):
    """
    AlienVault OTX API service for threat intelligence pulses.
    """
    
    def __init__(self, api_key: str, timeout: int = 30, rate_limit: int = 30):
        """
        Initialize AlienVault OTX API.
        
        Args:
            api_key: AlienVault OTX API key
            timeout: Request timeout in seconds
            rate_limit: Rate limit in requests per minute (OTX free tier: 30/minute)
        """
        super().__init__(api_key, timeout, rate_limit)
        self.base_url = "https://otx.alienvault.com/api/v1"
    
    def get_default_headers(self) -> Dict[str, str]:
        """Get default headers for AlienVault OTX API."""
        return {
            'User-Agent': 'OSINT-Platform/1.0',
            'Accept': 'application/json',
            'X-OTX-API-KEY': self.api_key
        }
    
    def validate_api_key(self) -> bool:
        """
        Validate AlienVault OTX API key.
        
        Returns:
            True if valid, False otherwise
        """
        try:
            # Test with a simple user info request
            url = f"{self.base_url}/user/me"
            
            response = self.make_request('GET', url)
            data = response.json()
            
            # Check if we have a valid response with user info
            return 'username' in data
            
        except Exception as e:
            self.logger.error(f"API key validation failed: {str(e)}")
            return False
    
    def search(self, target: str, query_type: str = 'default') -> Dict[str, Any]:
        """
        Search AlienVault OTX for target information.
        
        Args:
            target: Target to search for
            query_type: Type of query (ip, domain, hostname, url, hash)
            
        Returns:
            Raw API response
        """
        try:
            if query_type == 'ip' or query_type == 'default':
                return self._search_ip(target)
            elif query_type == 'domain':
                return self._search_domain(target)
            elif query_type == 'hostname':
                return self._search_hostname(target)
            elif query_type == 'url':
                return self._search_url(target)
            elif query_type == 'hash':
                return self._search_hash(target)
            else:
                raise ValueError(f"Unsupported query type: {query_type}")
                
        except Exception as e:
            self.logger.error(f"Search failed for {target}: {str(e)}")
            raise
    
    def _search_ip(self, ip: str) -> Dict[str, Any]:
        """
        Search for IP indicators.
        
        Args:
            ip: IP address
            
        Returns:
            IP indicators from OTX
        """
        url = f"{self.base_url}/indicators/IPv4/{ip}/reputation"
        params = {'include_sections': 'general,reputation'}
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def _search_domain(self, domain: str) -> Dict[str, Any]:
        """
        Search for domain indicators.
        
        Args:
            domain: Domain name
            
        Returns:
            Domain indicators from OTX
        """
        url = f"{self.base_url}/indicators/domain/{domain}/reputation"
        params = {'include_sections': 'general,reputation'}
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def _search_hostname(self, hostname: str) -> Dict[str, Any]:
        """
        Search for hostname indicators.
        
        Args:
            hostname: Hostname
            
        Returns:
            Hostname indicators from OTX
        """
        url = f"{self.base_url}/indicators/hostname/{hostname}/reputation"
        params = {'include_sections': 'general,reputation'}
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def _search_url(self, url: str) -> Dict[str, Any]:
        """
        Search for URL indicators.
        
        Args:
            url: URL to check
            
        Returns:
            URL indicators from OTX
        """
        # URL needs to be encoded
        import urllib.parse
        encoded_url = urllib.parse.quote(url, safe='')
        
        url_endpoint = f"{self.base_url}/indicators/URL/{encoded_url}/reputation"
        params = {'include_sections': 'general,reputation'}
        
        response = self.make_request('GET', url_endpoint, params=params)
        return response.json()
    
    def _search_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Search for file hash indicators.
        
        Args:
            file_hash: File hash
            
        Returns:
            File hash indicators from OTX
        """
        url = f"{self.base_url}/indicators/file/{file_hash}/reputation"
        params = {'include_sections': 'general,reputation'}
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def normalize_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Convert AlienVault OTX response to standard format.
        
        Args:
            raw_data: Raw OTX response
            target: Original target
            
        Returns:
            Normalized response
        """
        if not raw_data or 'reputation' not in raw_data:
            return self._create_error_response("No OTX data found", target)
        
        try:
            reputation = raw_data.get('reputation', {})
            
            # Extract key information
            threat_score = reputation.get('threat_score', 0)
            first_seen = reputation.get('first_seen', '')
            last_seen = reputation.get('last_seen', '')
            
            # Get activities/pulses
            activities = raw_data.get('activities', [])
            pulses = raw_data.get('pulse_info', {}).get('pulses', [])
            
            # Determine severity based on threat score
            severity = self._calculate_severity(threat_score, len(pulses))
            
            # Create summary
            summary_parts = []
            summary_parts.append(f"OTX threat score: {threat_score}")
            
            if pulses:
                summary_parts.append(f"with {len(pulses)} related pulses")
            
            if activities:
                summary_parts.append(f"and {len(activities)} recorded activities")
            
            summary = ' '.join(summary_parts) + '.'
            
            # Extract indicators
            indicators = []
            
            # Threat score indicator
            if threat_score > 0:
                indicators.append({
                    'type': 'threat_score',
                    'value': str(threat_score),
                    'severity': severity
                })
            
            # Pulse indicators
            for pulse in pulses[:10]:  # Limit to top 10
                pulse_name = pulse.get('name', 'Unknown pulse')
                pulse_id = pulse.get('id', '')
                indicators.append({
                    'type': 'threat_pulse',
                    'value': f"{pulse_name} (ID: {pulse_id})",
                    'severity': 'medium'
                })
            
            # Activity indicators
            for activity in activities[:5]:  # Limit to top 5
                activity_type = activity.get('action', 'unknown')
                indicators.append({
                    'type': 'malicious_activity',
                    'value': activity_type,
                    'severity': 'high'
                })
            
            # Create details
            details = {
                'threat_score': threat_score,
                'first_seen': first_seen,
                'last_seen': last_seen,
                'activities_count': len(activities),
                'pulses_count': len(pulses),
                'reputation': reputation
            }
            
            # Add pulse details
            if pulses:
                details['pulses'] = [{
                    'name': pulse.get('name', ''),
                    'id': pulse.get('id', ''),
                    'description': pulse.get('description', ''),
                    'tags': pulse.get('tags', []),
                    'created': pulse.get('created', '')
                } for pulse in pulses[:10]]
            
            # Add activity details
            if activities:
                details['activities'] = [{
                    'action': activity.get('action', ''),
                    'actor': activity.get('actor', ''),
                    'timestamp': activity.get('timestamp', '')
                } for activity in activities[:5]]
            
            # Create metadata
            metadata = {
                'source': 'alienvault',
                'query_time': datetime.utcnow().isoformat(),
                'threat_score': threat_score,
                'pulses_analyzed': len(pulses),
                'activities_analyzed': len(activities)
            }
            
            return {
                'source': 'alienvault',
                'target': target,
                'timestamp': datetime.utcnow().isoformat(),
                'status': 'success',
                'severity': severity,
                'data': {
                    'summary': summary,
                    'details': details,
                    'indicators': indicators,
                    'metadata': metadata
                },
                'error': None
            }
            
        except Exception as e:
            self.logger.error(f"Response normalization failed: {str(e)}")
            return self._create_error_response(f"Failed to process response: {str(e)}", target)
    
    def _calculate_severity(self, threat_score: int, pulse_count: int) -> str:
        """
        Calculate severity based on threat score and pulse count.
        
        Args:
            threat_score: OTX threat score
            pulse_count: Number of related pulses
            
        Returns:
            Severity level
        """
        if threat_score >= 7 or pulse_count >= 10:
            return Severity.CRITICAL.value
        elif threat_score >= 5 or pulse_count >= 5:
            return Severity.HIGH.value
        elif threat_score >= 3 or pulse_count >= 2:
            return Severity.MEDIUM.value
        elif threat_score > 0 or pulse_count > 0:
            return Severity.LOW.value
        else:
            return Severity.INFO.value
    
    def _create_error_response(self, error_message: str, target: str) -> Dict[str, Any]:
        """
        Create error response.
        
        Args:
            error_message: Error message
            target: Original target
            
        Returns:
            Error response
        """
        return {
            'source': 'alienvault',
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'error',
            'severity': Severity.INFO.value,
            'data': {
                'summary': 'Failed to retrieve AlienVault OTX data',
                'details': {},
                'indicators': [],
                'metadata': {}
            },
            'error': error_message
        }
    
    def get_supported_targets(self) -> List[str]:
        """Get list of supported target types."""
        return ['ip', 'domain', 'hostname', 'url', 'hash']
    
    def search_pulses(self, query: str, limit: int = 10) -> Dict[str, Any]:
        """
        Search for threat pulses.
        
        Args:
            query: Search query
            limit: Maximum number of results
            
        Returns:
            Pulse search results
        """
        try:
            url = f"{self.base_url}/search/pulses"
            params = {
                'q': query,
                'limit': limit
            }
            
            response = self.make_request('GET', url, params=params)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Pulse search failed for {query}: {str(e)}")
            raise
    
    def get_pulse_details(self, pulse_id: str) -> Dict[str, Any]:
        """
        Get detailed information about a specific pulse.
        
        Args:
            pulse_id: Pulse ID
            
        Returns:
            Pulse details
        """
        try:
            url = f"{self.base_url}/pulses/{pulse_id}"
            
            response = self.make_request('GET', url)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Failed to get pulse details for {pulse_id}: {str(e)}")
            raise
    
    def get_subscribed_pulses(self, limit: int = 20) -> Dict[str, Any]:
        """
        Get pulses subscribed by the user.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            Subscribed pulses
        """
        try:
            url = f"{self.base_url}/pulses/subscribed"
            params = {'limit': limit}
            
            response = self.make_request('GET', url, params=params)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Failed to get subscribed pulses: {str(e)}")
            raise
    
    def get_user_pulses(self, limit: int = 20) -> Dict[str, Any]:
        """
        Get pulses created by the user.
        
        Args:
            limit: Maximum number of results
            
        Returns:
            User pulses
        """
        try:
            url = f"{self.base_url}/pulses"
            params = {'limit': limit}
            
            response = self.make_request('GET', url, params=params)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Failed to get user pulses: {str(e)}")
            raise