"""
VirusTotal API integration for domain/IP/URL reputation and malware analysis.
"""

import requests
from datetime import datetime
from typing import Dict, List, Any
from .base import BaseAPIService
from app.models.result import Severity


class VirusTotalAPI(BaseAPIService):
    """
    VirusTotal API service for domain/IP/URL reputation and malware analysis.
    """
    
    def __init__(self, api_key: str, timeout: int = 30, rate_limit: int = 4):
        """
        Initialize VirusTotal API.
        
        Args:
            api_key: VirusTotal API key
            timeout: Request timeout in seconds
            rate_limit: Rate limit in requests per minute (VirusTotal free tier: 4/minute)
        """
        super().__init__(api_key, timeout, rate_limit)
        self.base_url = "https://www.virustotal.com/vtapi/v2"
    
    def get_default_headers(self) -> Dict[str, str]:
        """Get default headers for VirusTotal API."""
        return {
            'User-Agent': 'OSINT-Platform/1.0',
            'Accept': 'application/json'
        }
    
    def validate_api_key(self) -> bool:
        """
        Validate VirusTotal API key.
        
        Returns:
            True if valid, False otherwise
        """
        try:
            # Test with a simple IP lookup
            url = f"{self.base_url}/ip-address/report"
            params = {
                'apikey': self.api_key,
                'ip': '8.8.8.8'  # Use Google DNS for testing
            }
            
            response = self.make_request('GET', url, params=params)
            data = response.json()
            
            # Check if we have a valid response
            return 'response_code' in data
            
        except Exception as e:
            self.logger.error(f"API key validation failed: {str(e)}")
            return False
    
    def search(self, target: str, query_type: str = 'default') -> Dict[str, Any]:
        """
        Search VirusTotal for target information.
        
        Args:
            target: Target to search for
            query_type: Type of query (ip, domain, url, hash)
            
        Returns:
            Raw API response
        """
        try:
            if query_type == 'ip' or query_type == 'default':
                return self._search_ip(target)
            elif query_type == 'domain':
                return self._search_domain(target)
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
        Search for IP reputation.
        
        Args:
            ip: IP address
            
        Returns:
            IP reputation from VirusTotal
        """
        url = f"{self.base_url}/ip-address/report"
        params = {
            'apikey': self.api_key,
            'ip': ip
        }
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def _search_domain(self, domain: str) -> Dict[str, Any]:
        """
        Search for domain reputation.
        
        Args:
            domain: Domain name
            
        Returns:
            Domain reputation from VirusTotal
        """
        url = f"{self.base_url}/domain/report"
        params = {
            'apikey': self.api_key,
            'domain': domain
        }
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def _search_url(self, url: str) -> Dict[str, Any]:
        """
        Search for URL reputation.
        
        Args:
            url: URL to check
            
        Returns:
            URL reputation from VirusTotal
        """
        # First need to get scan ID for the URL
        scan_url = f"{self.base_url}/url/scan"
        scan_params = {
            'apikey': self.api_key,
            'url': url
        }
        
        scan_response = self.make_request('POST', scan_url, data=scan_params)
        scan_data = scan_response.json()
        
        if 'scan_id' in scan_data:
            # Get the report using scan_id
            report_url = f"{self.base_url}/url/report"
            report_params = {
                'apikey': self.api_key,
                'resource': scan_data['scan_id']
            }
            
            report_response = self.make_request('GET', report_url, params=report_params)
            return report_response.json()
        
        return scan_data
    
    def _search_hash(self, file_hash: str) -> Dict[str, Any]:
        """
        Search for file hash reputation.
        
        Args:
            file_hash: File hash (MD5, SHA1, SHA256)
            
        Returns:
            File hash reputation from VirusTotal
        """
        url = f"{self.base_url}/file/report"
        params = {
            'apikey': self.api_key,
            'resource': file_hash
        }
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def normalize_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Convert VirusTotal response to standard format.
        
        Args:
            raw_data: Raw VirusTotal response
            target: Original target
            
        Returns:
            Normalized response
        """
        if not raw_data or raw_data.get('response_code') == 0:
            error_msg = raw_data.get('verbose_msg', 'Unknown error') if raw_data else 'No data found'
            return self._create_error_response(error_msg, target)
        
        try:
            # Extract key information
            positives = raw_data.get('positives', 0)
            total = raw_data.get('total', 0)
            scan_date = raw_data.get('scan_date', '')
            permalink = raw_data.get('permalink', '')
            
            # Calculate detection ratio
            detection_ratio = f"{positives}/{total}"
            
            # Determine severity based on detection ratio
            severity = self._calculate_severity(positives, total)
            
            # Create summary
            if total > 0:
                detection_percentage = (positives / total) * 100
                summary = f"VirusTotal detection ratio: {detection_ratio} ({detection_percentage:.1f}% malicious)"
            else:
                summary = "No VirusTotal data available"
            
            # Extract indicators
            indicators = []
            
            # Add detection indicators
            if positives > 0:
                indicators.append({
                    'type': 'malicious_detection',
                    'value': f"{positives}/{total} engines detected as malicious",
                    'severity': severity
                })
            
            # Add scan results as indicators
            scans = raw_data.get('scans', {})
            for engine, result in scans.items():
                if isinstance(result, dict) and result.get('detected', False):
                    indicators.append({
                        'type': 'antivirus_detection',
                        'value': f"{engine}: {result.get('result', 'Malicious')}",
                        'severity': 'high'
                    })
            
            # Create details
            details = {
                'detection_ratio': detection_ratio,
                'positives': positives,
                'total': total,
                'scan_date': scan_date,
                'permalink': permalink,
                'scans': scans
            }
            
            # Add target-specific details
            if 'country' in raw_data:
                details['country'] = raw_data['country']
            if 'subdomains' in raw_data:
                details['subdomains'] = raw_data['subdomains']
            if 'resolutions' in raw_data:
                details['resolutions'] = raw_data['resolutions']
            if 'categories' in raw_data:
                details['categories'] = raw_data['categories']
            
            # Create metadata
            metadata = {
                'source': 'virustotal',
                'query_time': datetime.utcnow().isoformat(),
                'scan_date': scan_date,
                'total_engines': total,
                'api_response_code': raw_data.get('response_code', 0)
            }
            
            return {
                'source': 'virustotal',
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
    
    def _calculate_severity(self, positives: int, total: int) -> str:
        """
        Calculate severity based on detection ratio.
        
        Args:
            positives: Number of positive detections
            total: Total number of engines
            
        Returns:
            Severity level
        """
        if total == 0:
            return Severity.INFO.value
        
        detection_percentage = (positives / total) * 100
        
        if detection_percentage >= 50:
            return Severity.CRITICAL.value
        elif detection_percentage >= 25:
            return Severity.HIGH.value
        elif detection_percentage >= 10:
            return Severity.MEDIUM.value
        elif detection_percentage > 0:
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
            'source': 'virustotal',
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'error',
            'severity': Severity.INFO.value,
            'data': {
                'summary': 'Failed to retrieve VirusTotal data',
                'details': {},
                'indicators': [],
                'metadata': {}
            },
            'error': error_message
        }
    
    def get_supported_targets(self) -> List[str]:
        """Get list of supported target types."""
        return ['ip', 'domain', 'url', 'hash']
    
    def submit_url(self, url: str) -> Dict[str, Any]:
        """
        Submit URL for scanning.
        
        Args:
            url: URL to submit
            
        Returns:
            Submission response
        """
        try:
            scan_url = f"{self.base_url}/url/scan"
            params = {
                'apikey': self.api_key,
                'url': url
            }
            
            response = self.make_request('POST', scan_url, data=params)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"URL submission failed for {url}: {str(e)}")
            raise
    
    def submit_file(self, file_path: str) -> Dict[str, Any]:
        """
        Submit file for scanning.
        
        Args:
            file_path: Path to file to submit
            
        Returns:
            Submission response
        """
        try:
            scan_url = f"{self.base_url}/file/scan"
            params = {'apikey': self.api_key}
            
            with open(file_path, 'rb') as file:
                files = {'file': file}
                response = self.make_request('POST', scan_url, params=params, files=files)
                return response.json()
                
        except Exception as e:
            self.logger.error(f"File submission failed: {str(e)}")
            raise