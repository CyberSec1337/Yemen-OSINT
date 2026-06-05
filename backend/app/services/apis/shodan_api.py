"""
Shodan API integration for IP intelligence and port scanning.
"""

import requests
from datetime import datetime
from typing import Dict, List, Any
from .base import BaseAPIService
from app.models.result import Severity


class ShodanAPI(BaseAPIService):
    """
    Shodan API service for IP intelligence, port scanning, and vulnerability data.
    """
    
    def __init__(self, api_key: str, timeout: int = 30, rate_limit: int = 60):
        """
        Initialize Shodan API.
        
        Args:
            api_key: Shodan API key
            timeout: Request timeout in seconds
            rate_limit: Rate limit in requests per minute (Shodan free tier: 60/minute)
        """
        super().__init__(api_key, timeout, rate_limit)
        self.base_url = "https://api.shodan.io"
    
    def get_default_headers(self) -> Dict[str, str]:
        """Get default headers for Shodan API."""
        return {
            'User-Agent': 'OSINT-Platform/1.0',
            'Accept': 'application/json'
        }
    
    def validate_api_key(self) -> bool:
        """
        Validate Shodan API key.
        
        Returns:
            True if valid, False otherwise
        """
        try:
            url = f"{self.base_url}/api-info"
            params = {'key': self.api_key}
            
            response = self.make_request('GET', url, params=params)
            data = response.json()
            
            # Check if we have a valid response with plan info
            return 'plan' in data and 'credits' in data
            
        except Exception as e:
            self.logger.error(f"API key validation failed: {str(e)}")
            return False
    
    def search(self, target: str, query_type: str = 'default') -> Dict[str, Any]:
        """
        Search Shodan for target information.
        
        Args:
            target: Target to search for (IP address)
            query_type: Type of query (ip, host, etc.)
            
        Returns:
            Raw API response
        """
        try:
            if query_type == 'ip' or query_type == 'default':
                return self._search_ip(target)
            elif query_type == 'host':
                return self._search_host(target)
            else:
                raise ValueError(f"Unsupported query type: {query_type}")
                
        except Exception as e:
            self.logger.error(f"Search failed for {target}: {str(e)}")
            raise
    
    def _search_ip(self, ip: str) -> Dict[str, Any]:
        """
        Search for IP information.
        
        Args:
            ip: IP address
            
        Returns:
            IP information from Shodan
        """
        url = f"{self.base_url}/shodan/host/{ip}"
        params = {
            'key': self.api_key,
            'minify': False
        }
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def _search_host(self, host: str) -> Dict[str, Any]:
        """
        Search for host information.
        
        Args:
            host: Hostname or IP
            
        Returns:
            Host information from Shodan
        """
        # First try to resolve hostname to IP
        import socket
        try:
            ip = socket.gethostbyname(host)
            return self._search_ip(ip)
        except socket.gaierror:
            # If hostname resolution fails, search as hostname
            url = f"{self.base_url}/shodan/host/search"
            params = {
                'key': self.api_key,
                'query': f'hostname:{host}',
                'limit': 1
            }
            
            response = self.make_request('GET', url, params=params)
            return response.json()
    
    def normalize_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Convert Shodan response to standard format.
        
        Args:
            raw_data: Raw Shodan response
            target: Original target
            
        Returns:
            Normalized response
        """
        if not raw_data or 'error' in raw_data:
            return self._create_error_response(raw_data.get('error', 'Unknown error'), target)
        
        try:
            # Extract key information
            ip_str = raw_data.get('ip_str', target)
            country = raw_data.get('country_name', 'Unknown')
            org = raw_data.get('org', 'Unknown')
            ports = raw_data.get('ports', [])
            services = raw_data.get('services', {})
            vulnerabilities = raw_data.get('vulns', [])
            
            # Determine severity based on findings
            severity = self._calculate_severity(ports, vulnerabilities)
            
            # Create summary
            summary_parts = []
            summary_parts.append(f"Host {ip_str} in {country}")
            if org != 'Unknown':
                summary_parts.append(f"({org})")
            summary_parts.append(f"has {len(ports)} open ports")
            
            if vulnerabilities:
                summary_parts.append(f"and {len(vulnerabilities)} vulnerabilities")
            
            summary = ' '.join(summary_parts) + '.'
            
            # Extract indicators
            indicators = []
            
            # Port indicators
            for port in ports:
                indicators.append({
                    'type': 'port',
                    'value': str(port),
                    'severity': 'medium' if port in [22, 23, 80, 443] else 'low'
                })
            
            # Vulnerability indicators
            for vuln in vulnerabilities:
                indicators.append({
                    'type': 'vulnerability',
                    'value': vuln,
                    'severity': 'high'
                })
            
            # Service indicators
            for port, service_info in services.items():
                if isinstance(service_info, dict):
                    product = service_info.get('product', '')
                    version = service_info.get('version', '')
                    if product:
                        service_str = f"{product} {version}".strip()
                        indicators.append({
                            'type': 'service',
                            'value': service_str,
                            'severity': 'low'
                        })
            
            # Create details
            details = {
                'ip': ip_str,
                'country': country,
                'country_code': raw_data.get('country_code', ''),
                'organization': org,
                'asn': raw_data.get('asn', ''),
                'ports': ports,
                'services': services,
                'vulnerabilities': vulnerabilities,
                'last_update': raw_data.get('last_update', ''),
                'hostnames': raw_data.get('hostnames', []),
                'domains': raw_data.get('domains', [])
            }
            
            # Create metadata
            metadata = {
                'source': 'shodan',
                'query_time': datetime.utcnow().isoformat(),
                'data_age': raw_data.get('last_update', ''),
                'total_results': 1,
                'api_credits_used': 1
            }
            
            return {
                'source': 'shodan',
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
    
    def _calculate_severity(self, ports: List[int], vulnerabilities: List[str]) -> str:
        """
        Calculate severity based on ports and vulnerabilities.
        
        Args:
            ports: List of open ports
            vulnerabilities: List of vulnerabilities
            
        Returns:
            Severity level
        """
        if vulnerabilities:
            return Severity.HIGH.value
        
        # Check for sensitive ports
        sensitive_ports = [21, 22, 23, 25, 53, 135, 139, 445, 1433, 1521, 3306, 3389, 5432, 5900]
        if any(port in sensitive_ports for port in ports):
            return Severity.MEDIUM.value
        
        # Check for many open ports
        if len(ports) > 10:
            return Severity.MEDIUM.value
        
        return Severity.LOW.value if ports else Severity.INFO.value
    
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
            'source': 'shodan',
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'error',
            'severity': Severity.INFO.value,
            'data': {
                'summary': 'Failed to retrieve Shodan data',
                'details': {},
                'indicators': [],
                'metadata': {}
            },
            'error': error_message
        }
    
    def get_supported_targets(self) -> List[str]:
        """Get list of supported target types."""
        return ['ip', 'domain']
    
    def search_exploits(self, target: str) -> Dict[str, Any]:
        """
        Search for exploits related to target.
        
        Args:
            target: Target to search for
            
        Returns:
            Exploit information
        """
        try:
            url = f"{self.base_url}/shodan/exploitdb/search"
            params = {
                'key': self.api_key,
                'query': target,
                'page': 1
            }
            
            response = self.make_request('GET', url, params=params)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Exploit search failed for {target}: {str(e)}")
            raise
    
    def get_account_info(self) -> Dict[str, Any]:
        """
        Get account information and API credits.
        
        Returns:
            Account information
        """
        try:
            url = f"{self.base_url}/api-info"
            params = {'key': self.api_key}
            
            response = self.make_request('GET', url, params=params)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Failed to get account info: {str(e)}")
            raise