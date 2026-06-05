"""
AbuseIPDB API integration for IP abuse reports and confidence scores.
"""

import requests
from datetime import datetime, timedelta
from typing import Dict, List, Any
from .base import BaseAPIService
from app.models.result import Severity


class AbuseIPDBAPI(BaseAPIService):
    """
    AbuseIPDB API service for IP abuse reports and confidence scores.
    """
    
    def __init__(self, api_key: str, timeout: int = 30, rate_limit: int = 1000):
        """
        Initialize AbuseIPDB API.
        
        Args:
            api_key: AbuseIPDB API key
            timeout: Request timeout in seconds
            rate_limit: Rate limit in requests per minute (AbuseIPDB free tier: 1000/day)
        """
        super().__init__(api_key, timeout, rate_limit)
        self.base_url = "https://api.abuseipdb.com/api/v2"
    
    def get_default_headers(self) -> Dict[str, str]:
        """Get default headers for AbuseIPDB API."""
        return {
            'User-Agent': 'OSINT-Platform/1.0',
            'Accept': 'application/json',
            'Key': self.api_key
        }
    
    def validate_api_key(self) -> bool:
        """
        Validate AbuseIPDB API key.
        
        Returns:
            True if valid, False otherwise
        """
        try:
            # Test with a simple check endpoint
            url = f"{self.base_url}/check"
            params = {
                'ipAddress': '8.8.8.8',  # Use Google DNS for testing
                'maxAgeInDays': 30,
                'verbose': ''
            }
            
            response = self.make_request('GET', url, params=params)
            data = response.json()
            
            # Check if we have a valid response
            return 'data' in data
            
        except Exception as e:
            self.logger.error(f"API key validation failed: {str(e)}")
            return False
    
    def search(self, target: str, query_type: str = 'default') -> Dict[str, Any]:
        """
        Search AbuseIPDB for target information.
        
        Args:
            target: Target to search for (IP address)
            query_type: Type of query (ip, check, reports)
            
        Returns:
            Raw API response
        """
        try:
            if query_type == 'ip' or query_type == 'default' or query_type == 'check':
                return self._check_ip(target)
            elif query_type == 'reports':
                return self._get_reports(target)
            else:
                raise ValueError(f"Unsupported query type: {query_type}")
                
        except Exception as e:
            self.logger.error(f"Search failed for {target}: {str(e)}")
            raise
    
    def _check_ip(self, ip: str) -> Dict[str, Any]:
        """
        Check IP reputation and confidence score.
        
        Args:
            ip: IP address
            
        Returns:
            IP reputation from AbuseIPDB
        """
        url = f"{self.base_url}/check"
        params = {
            'ipAddress': ip,
            'maxAgeInDays': 90,
            'verbose': ''
        }
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def _get_reports(self, ip: str, days: int = 30) -> Dict[str, Any]:
        """
        Get detailed abuse reports for IP.
        
        Args:
            ip: IP address
            days: Number of days to look back
            
        Returns:
            Abuse reports from AbuseIPDB
        """
        url = f"{self.base_url}/reports"
        params = {
            'ipAddress': ip,
            'maxAgeInDays': days,
            'limit': 100
        }
        
        response = self.make_request('GET', url, params=params)
        return response.json()
    
    def normalize_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Convert AbuseIPDB response to standard format.
        
        Args:
            raw_data: Raw AbuseIPDB response
            target: Original target
            
        Returns:
            Normalized response
        """
        if not raw_data or 'data' not in raw_data:
            error_msg = raw_data.get('errors', [{'detail': 'Unknown error'}])[0]['detail'] if raw_data.get('errors') else 'No data found'
            return self._create_error_response(error_msg, target)
        
        try:
            data = raw_data['data']
            
            # Extract key information
            ip_address = data.get('ipAddress', target)
            is_public = data.get('isPublic', False)
            ip_version = data.get('ipVersion', 4)
            is_whitelisted = data.get('isWhitelisted', False)
            country_code = data.get('countryCode', '')
            abuse_confidence_score = data.get('abuseConfidenceScore', 0)
            usage_type = data.get('usageType', '')
            isp = data.get('isp', '')
            domain = data.get('domain', '')
            total_reports = data.get('totalReports', 0)
            num_distinct_users = data.get('numDistinctUsers', 0)
            last_reported_at = data.get('lastReportedAt', '')
            
            # Determine severity based on confidence score and reports
            severity = self._calculate_severity(abuse_confidence_score, total_reports)
            
            # Create summary
            summary_parts = []
            summary_parts.append(f"IP {ip_address}")
            
            if country_code:
                summary_parts.append(f"({country_code})")
            
            if isp:
                summary_parts.append(f"ISP: {isp}")
            
            summary_parts.append(f"has {total_reports} abuse reports")
            summary_parts.append(f"with {abuse_confidence_score}% confidence score")
            
            if is_whitelisted:
                summary_parts.append("(whitelisted)")
            
            summary = ' '.join(summary_parts) + '.'
            
            # Extract indicators
            indicators = []
            
            # Confidence score indicator
            if abuse_confidence_score > 0:
                indicators.append({
                    'type': 'abuse_confidence',
                    'value': f"{abuse_confidence_score}%",
                    'severity': severity
                })
            
            # Report count indicator
            if total_reports > 0:
                indicators.append({
                    'type': 'abuse_reports',
                    'value': f"{total_reports} reports from {num_distinct_users} users",
                    'severity': severity
                })
            
            # Usage type indicator
            if usage_type:
                indicators.append({
                    'type': 'usage_type',
                    'value': usage_type,
                    'severity': 'low'
                })
            
            # Country indicator
            if country_code:
                indicators.append({
                    'type': 'country',
                    'value': country_code,
                    'severity': 'info'
                })
            
            # Create details
            details = {
                'ip_address': ip_address,
                'is_public': is_public,
                'ip_version': ip_version,
                'is_whitelisted': is_whitelisted,
                'country_code': country_code,
                'abuse_confidence_score': abuse_confidence_score,
                'usage_type': usage_type,
                'isp': isp,
                'domain': domain,
                'total_reports': total_reports,
                'num_distinct_users': num_distinct_users,
                'last_reported_at': last_reported_at
            }
            
            # Create metadata
            metadata = {
                'source': 'abuseipdb',
                'query_time': datetime.utcnow().isoformat(),
                'last_reported_at': last_reported_at,
                'reports_analyzed': total_reports,
                'confidence_score': abuse_confidence_score
            }
            
            return {
                'source': 'abuseipdb',
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
    
    def _calculate_severity(self, confidence_score: int, total_reports: int) -> str:
        """
        Calculate severity based on confidence score and report count.
        
        Args:
            confidence_score: Abuse confidence score (0-100)
            total_reports: Total number of reports
            
        Returns:
            Severity level
        """
        if confidence_score >= 75 or total_reports >= 50:
            return Severity.CRITICAL.value
        elif confidence_score >= 50 or total_reports >= 25:
            return Severity.HIGH.value
        elif confidence_score >= 25 or total_reports >= 10:
            return Severity.MEDIUM.value
        elif confidence_score > 0 or total_reports > 0:
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
            'source': 'abuseipdb',
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'error',
            'severity': Severity.INFO.value,
            'data': {
                'summary': 'Failed to retrieve AbuseIPDB data',
                'details': {},
                'indicators': [],
                'metadata': {}
            },
            'error': error_message
        }
    
    def get_supported_targets(self) -> List[str]:
        """Get list of supported target types."""
        return ['ip']
    
    def report_ip(self, ip: str, categories: List[int], comment: str = "") -> Dict[str, Any]:
        """
        Report an IP address for abuse.
        
        Args:
            ip: IP address to report
            categories: List of category IDs
            comment: Optional comment
            
        Returns:
            Report response
        """
        try:
            url = f"{self.base_url}/report"
            data = {
                'ip': ip,
                'categories': ','.join(map(str, categories)),
                'comment': comment
            }
            
            response = self.make_request('POST', url, data=data)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"IP report failed for {ip}: {str(e)}")
            raise
    
    def check_blocklist(self, ip: str) -> Dict[str, Any]:
        """
        Check if IP is in blocklist.
        
        Args:
            ip: IP address to check
            
        Returns:
            Blocklist status
        """
        try:
            url = f"{self.base_url}/check-blocklist"
            params = {
                'ipAddress': ip,
                'maxAgeInDays': 30
            }
            
            response = self.make_request('GET', url, params=params)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Blocklist check failed for {ip}: {str(e)}")
            raise
    
    def get_blacklist(self) -> Dict[str, Any]:
        """
        Get the current blacklist.
        
        Returns:
            Blacklist data
        """
        try:
            url = f"{self.base_url}/blacklist"
            params = {
                'limit': 10000,
                'confidenceMinimum': 90
            }
            
            response = self.make_request('GET', url, params=params)
            return response.json()
            
        except Exception as e:
            self.logger.error(f"Failed to get blacklist: {str(e)}")
            raise