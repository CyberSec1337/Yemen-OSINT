"""
SecurityTrails API integration for DNS history, subdomains, and WHOIS data.
"""

import requests
from datetime import datetime
from typing import Dict, List, Any
from .base import BaseAPIService
from app.models.result import Severity


class SecurityTrailsAPI(BaseAPIService):
    """
    SecurityTrails API service for DNS history, subdomains, and WHOIS data.
    """
    
    def __init__(self, api_key: str, timeout: int = 30, rate_limit: int = 50):
        """
        Initialize SecurityTrails API.
        
        Args:
            api_key: SecurityTrails API key
            timeout: Request timeout in seconds
            rate_limit: Rate limit in requests per minute (SecurityTrails free tier: 50/minute)
        """
        super().__init__(api_key, timeout, rate_limit)
        self.base_url = "https://api.securitytrails.com/v1"
    
    def get_default_headers(self) -> Dict[str, str]:
        """Get default headers for SecurityTrails API."""
        return {
            'User-Agent': 'OSINT-Platform/1.0',
            'Accept': 'application/json',
            'apikey': self.api_key
        }
    
    def validate_api_key(self) -> bool:
        """
        Validate SecurityTrails API key.
        
        Returns:
            True if valid, False otherwise
        """
        try:
            # Test with a simple domain lookup
            url = f"{self.base_url}/domain/google.com"
            
            response = self.make_request('GET', url)
            data = response.json()
            
            # Check if we have a valid response
            return 'hostname' in data or 'message' not in data
            
        except Exception as e:
            self.logger.error(f"API key validation failed: {str(e)}")
            return False
    
    def search(self, target: str, query_type: str = 'default') -> Dict[str, Any]:
        """
        Search SecurityTrails for target information.
        
        Args:
            target: Target to search for
            query_type: Type of query (domain, subdomains, history, whois)
            
        Returns:
            Raw API response
        """
        try:
            if query_type == 'domain' or query_type == 'default':
                return self._search_domain(target)
            elif query_type == 'subdomains':
                return self._search_subdomains(target)
            elif query_type == 'history':
                return self._search_history(target)
            elif query_type == 'whois':
                return self._search_whois(target)
            elif query_type == 'ips':
                return self._search_domain_ips(target)
            else:
                raise ValueError(f"Unsupported query type: {query_type}")
                
        except Exception as e:
            self.logger.error(f"Search failed for {target}: {str(e)}")
            raise
    
    def _search_domain(self, domain: str) -> Dict[str, Any]:
        """
        Search for domain information.
        
        Args:
            domain: Domain name
            
        Returns:
            Domain information from SecurityTrails
        """
        url = f"{self.base_url}/domain/{domain}"
        
        response = self.make_request('GET', url)
        return response.json()
    
    def _search_subdomains(self, domain: str) -> Dict[str, Any]:
        """
        Search for subdomains.
        
        Args:
            domain: Domain name
            
        Returns:
            Subdomains from SecurityTrails
        """
        url = f"{self.base_url}/domain/{domain}/subdomains"
        params = {'include_inactive': 'true'}
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def _search_history(self, domain: str) -> Dict[str, Any]:
        """
        Search for DNS history.
        
        Args:
            domain: Domain name
            
        Returns:
            DNS history from SecurityTrails
        """
        url = f"{self.base_url}/domain/{domain}/history/dns"
        params = {'type': 'a'}  # Get A record history
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def _search_whois(self, domain: str) -> Dict[str, Any]:
        """
        Search for WHOIS data.
        
        Args:
            domain: Domain name
            
        Returns:
            WHOIS data from SecurityTrails
        """
        url = f"{self.base_url}/domain/{domain}/whois"
        
        response = self.make_request('GET', url)
        return response.json()
    
    def _search_domain_ips(self, domain: str) -> Dict[str, Any]:
        """
        Search for domain IP addresses.
        
        Args:
            domain: Domain name
            
        Returns:
            IP addresses from SecurityTrails
        """
        url = f"{self.base_url}/domain/{domain}/ips"
        
        response = self.make_request('GET', url)
        return response.json()
    
    def normalize_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Convert SecurityTrails response to standard format.
        
        Args:
            raw_data: Raw SecurityTrails response
            target: Original target
            
        Returns:
            Normalized response
        """
        if not raw_data or ('message' in raw_data and 'error' in raw_data['message'].lower()):
            error_msg = raw_data.get('message', 'Unknown error') if raw_data else 'No data found'
            return self._create_error_response(error_msg, target)
        
        try:
            # Handle different response types
            if 'subdomains' in raw_data:
                return self._normalize_subdomains_response(raw_data, target)
            elif 'records' in raw_data:
                return self._normalize_history_response(raw_data, target)
            elif 'whois' in raw_data:
                return self._normalize_whois_response(raw_data, target)
            else:
                return self._normalize_domain_response(raw_data, target)
                
        except Exception as e:
            self.logger.error(f"Response normalization failed: {str(e)}")
            return self._create_error_response(f"Failed to process response: {str(e)}", target)
    
    def _normalize_domain_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Normalize domain information response."""
        hostname = raw_data.get('hostname', target)
        current_dns = raw_data.get('current_dns', {})
        a_records = current_dns.get('a', {}).get('values', [])
        ns_records = current_dns.get('ns', {}).get('values', [])
        mx_records = current_dns.get('mx', {}).get('values', [])
        
        # Determine severity based on findings
        severity = self._calculate_domain_severity(raw_data)
        
        # Create summary
        summary_parts = []
        summary_parts.append(f"Domain {hostname}")
        
        if a_records:
            summary_parts.append(f"resolves to {len(a_records)} IP addresses")
        
        if ns_records:
            summary_parts.append(f"with {len(ns_records)} nameservers")
        
        if mx_records:
            summary_parts.append(f"and {len(mx_records)} mail servers")
        
        summary = ' '.join(summary_parts) + '.'
        
        # Extract indicators
        indicators = []
        
        # IP indicators
        for ip in a_records[:10]:  # Limit to top 10
            indicators.append({
                'type': 'ip_address',
                'value': ip['ip'] if isinstance(ip, dict) else ip,
                'severity': 'low'
            })
        
        # Nameserver indicators
        for ns in ns_records[:5]:  # Limit to top 5
            ns_value = ns['value'] if isinstance(ns, dict) else ns
            indicators.append({
                'type': 'nameserver',
                'value': ns_value,
                'severity': 'info'
            })
        
        # Create details
        details = {
            'hostname': hostname,
            'current_dns': current_dns,
            'endpoint': raw_data.get('endpoint', {}),
            'tags': raw_data.get('tags', []),
            'alexa': raw_data.get('alexa', {}),
            'hostnames': raw_data.get('hostnames', [])
        }
        
        # Create metadata
        metadata = {
            'source': 'securitytrails',
            'query_time': datetime.utcnow().isoformat(),
            'record_type': 'domain_info',
            'ip_count': len(a_records),
            'nameserver_count': len(ns_records)
        }
        
        return {
            'source': 'securitytrails',
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
    
    def _normalize_subdomains_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Normalize subdomains response."""
        subdomains = raw_data.get('subdomains', [])
        
        # Determine severity based on number of subdomains
        severity = self._calculate_subdomain_severity(len(subdomains))
        
        # Create summary
        summary = f"Found {len(subdomains)} subdomains for {target}."
        
        # Extract indicators
        indicators = []
        
        for subdomain in subdomains[:20]:  # Limit to top 20
            indicators.append({
                'type': 'subdomain',
                'value': subdomain,
                'severity': 'low'
            })
        
        # Create details
        details = {
            'subdomain_count': len(subdomains),
            'subdomains': subdomains
        }
        
        # Create metadata
        metadata = {
            'source': 'securitytrails',
            'query_time': datetime.utcnow().isoformat(),
            'record_type': 'subdomains',
            'total_subdomains': len(subdomains)
        }
        
        return {
            'source': 'securitytrails',
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
    
    def _normalize_history_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Normalize DNS history response."""
        records = raw_data.get('records', [])
        
        # Determine severity based on history changes
        severity = self._calculate_history_severity(records)
        
        # Create summary
        summary = f"Found {len(records)} historical DNS records for {target}."
        
        # Extract indicators
        indicators = []
        
        for record in records[:10]:  # Limit to top 10
            record_type = record.get('type', 'unknown')
            values = record.get('values', [])
            first_seen = record.get('first_seen', '')
            
            for value in values[:3]:  # Limit values per record
                indicators.append({
                    'type': f'dns_{record_type}',
                    'value': value,
                    'severity': 'low',
                    'first_seen': first_seen
                })
        
        # Create details
        details = {
            'record_count': len(records),
            'records': records
        }
        
        # Create metadata
        metadata = {
            'source': 'securitytrails',
            'query_time': datetime.utcnow().isoformat(),
            'record_type': 'dns_history',
            'total_records': len(records)
        }
        
        return {
            'source': 'securitytrails',
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
    
    def _normalize_whois_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """Normalize WHOIS response."""
        whois_data = raw_data.get('whois', {})
        
        # Determine severity based on WHOIS findings
        severity = self._calculate_whois_severity(whois_data)
        
        # Create summary
        summary = f"Retrieved WHOIS information for {target}."
        
        # Extract indicators
        indicators = []
        
        # Registrar indicator
        registrar = whois_data.get('registrar', '')
        if registrar:
            indicators.append({
                'type': 'registrar',
                'value': registrar,
                'severity': 'info'
            })
        
        # Creation date indicator
        created_date = whois_data.get('createdDate', '')
        if created_date:
            indicators.append({
                'type': 'creation_date',
                'value': created_date,
                'severity': 'info'
            })
        
        # Expiration date indicator
        expires_date = whois_data.get('expiresDate', '')
        if expires_date:
            indicators.append({
                'type': 'expiration_date',
                'value': expires_date,
                'severity': 'low'
            })
        
        # Create details
        details = {
            'whois': whois_data
        }
        
        # Create metadata
        metadata = {
            'source': 'securitytrails',
            'query_time': datetime.utcnow().isoformat(),
            'record_type': 'whois'
        }
        
        return {
            'source': 'securitytrails',
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
    
    def _calculate_domain_severity(self, data: Dict[str, Any]) -> str:
        """Calculate severity for domain information."""
        # Check for suspicious indicators
        tags = data.get('tags', [])
        if any(tag in ['suspicious', 'malicious', 'phishing'] for tag in tags):
            return Severity.HIGH.value
        
        return Severity.INFO.value
    
    def _calculate_subdomain_severity(self, count: int) -> str:
        """Calculate severity based on subdomain count."""
        if count > 100:
            return Severity.MEDIUM.value
        elif count > 50:
            return Severity.LOW.value
        else:
            return Severity.INFO.value
    
    def _calculate_history_severity(self, records: List[Dict]) -> str:
        """Calculate severity based on DNS history."""
        if len(records) > 100:
            return Severity.MEDIUM.value
        elif len(records) > 50:
            return Severity.LOW.value
        else:
            return Severity.INFO.value
    
    def _calculate_whois_severity(self, whois_data: Dict) -> str:
        """Calculate severity for WHOIS data."""
        # Check for recently registered domains
        created_date = whois_data.get('createdDate', '')
        if created_date:
            try:
                from datetime import datetime
                created = datetime.fromisoformat(created_date.replace('Z', '+00:00'))
                days_old = (datetime.utcnow() - created.replace(tzinfo=None)).days
                
                if days_old < 30:
                    return Severity.MEDIUM.value
                elif days_old < 90:
                    return Severity.LOW.value
            except:
                pass
        
        return Severity.INFO.value
    
    def _create_error_response(self, error_message: str, target: str) -> Dict[str, Any]:
        """Create error response."""
        return {
            'source': 'securitytrails',
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'error',
            'severity': Severity.INFO.value,
            'data': {
                'summary': 'Failed to retrieve SecurityTrails data',
                'details': {},
                'indicators': [],
                'metadata': {}
            },
            'error': error_message
        }
    
    def get_supported_targets(self) -> List[str]:
        """Get list of supported target types."""
        return ['domain']
    
    def search_associated_domains(self, domain: str) -> Dict[str, Any]:
        """
        Search for associated domains.
        
        Args:
            domain: Domain name
            
        Returns:
            Associated domains
        """
        try:
            url = f"{self.base_url}/domain/{domain}/associated"
            
            response = self.make_request('GET', url)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Associated domains search failed for {domain}: {str(e)}")
            raise