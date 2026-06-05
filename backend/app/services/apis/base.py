"""
Base API service class for all OSINT API integrations.
"""

import time
import requests
from abc import ABC, abstractmethod
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging

from app.models.result import Result, Severity, ResultStatus


class BaseAPIService(ABC):
    """
    Base class for all API integrations.
    Provides common functionality and interface for all OSINT APIs.
    """
    
    def __init__(self, api_key: str, timeout: int = 30, rate_limit: int = 60):
        """
        Initialize API service.
        
        Args:
            api_key: API key for the service
            timeout: Request timeout in seconds
            rate_limit: Rate limit in requests per minute
        """
        self.api_key = api_key
        self.base_url = ""
        self.timeout = timeout
        self.rate_limit = rate_limit
        self.last_request_time = 0
        self.request_count = 0
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Session for connection pooling
        self.session = requests.Session()
        self.session.headers.update(self.get_default_headers())
    
    @abstractmethod
    def get_default_headers(self) -> Dict[str, str]:
        """
        Get default headers for API requests.
        
        Returns:
            Dictionary of default headers
        """
        pass
    
    @abstractmethod
    def validate_api_key(self) -> bool:
        """
        Validate API key.
        
        Returns:
            True if valid, False otherwise
        """
        pass
    
    @abstractmethod
    def search(self, target: str, query_type: str = 'default') -> Dict[str, Any]:
        """
        Perform search on the target.
        
        Args:
            target: Target to search for
            query_type: Type of query to perform
            
        Returns:
            Raw API response
        """
        pass
    
    @abstractmethod
    def normalize_response(self, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Convert API response to standard format.
        
        Args:
            raw_data: Raw API response
            target: Original target
            
        Returns:
            Normalized response
        """
        pass
    
    def handle_rate_limit(self):
        """
        Handle rate limiting by sleeping if necessary.
        """
        current_time = time.time()
        time_since_last_request = current_time - self.last_request_time
        
        # Calculate minimum time between requests
        min_interval = 60.0 / self.rate_limit
        
        if time_since_last_request < min_interval:
            sleep_time = min_interval - time_since_last_request
            self.logger.info(f"Rate limiting: sleeping for {sleep_time:.2f} seconds")
            time.sleep(sleep_time)
        
        self.last_request_time = time.time()
        self.request_count += 1
    
    def make_request(self, method: str, url: str, **kwargs) -> requests.Response:
        """
        Make HTTP request with error handling and rate limiting.
        
        Args:
            method: HTTP method
            url: Request URL
            **kwargs: Additional request arguments
            
        Returns:
            Response object
        """
        self.handle_rate_limit()
        
        try:
            response = self.session.request(
                method=method,
                url=url,
                timeout=self.timeout,
                **kwargs
            )
            response.raise_for_status()
            return response
            
        except requests.exceptions.Timeout:
            self.logger.error(f"Request timeout for {url}")
            raise
        except requests.exceptions.ConnectionError:
            self.logger.error(f"Connection error for {url}")
            raise
        except requests.exceptions.HTTPError as e:
            self.logger.error(f"HTTP error for {url}: {e}")
            raise
        except requests.exceptions.RequestException as e:
            self.logger.error(f"Request error for {url}: {e}")
            raise
    
    def handle_error(self, error: Exception, target: str) -> Dict[str, Any]:
        """
        Standardized error handling.
        
        Args:
            error: Exception that occurred
            target: Original target
            
        Returns:
            Error response in standard format
        """
        error_message = str(error)
        
        if isinstance(error, requests.exceptions.Timeout):
            status = ResultStatus.TIMEOUT
            error_message = "Request timed out"
        elif isinstance(error, requests.exceptions.ConnectionError):
            status = ResultStatus.ERROR
            error_message = "Connection error"
        elif isinstance(error, requests.exceptions.HTTPError):
            if error.response.status_code == 429:
                status = ResultStatus.RATE_LIMITED
                error_message = "Rate limit exceeded"
            elif error.response.status_code == 401:
                status = ResultStatus.ERROR
                error_message = "Invalid API key"
            elif error.response.status_code == 403:
                status = ResultStatus.ERROR
                error_message = "Access forbidden"
            else:
                status = ResultStatus.ERROR
                error_message = f"HTTP {error.response.status_code}: {error_message}"
        else:
            status = ResultStatus.ERROR
        
        return {
            'source': self.__class__.__name__.lower().replace('api', ''),
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'status': status.value,
            'severity': Severity.INFO.value,
            'data': {
                'summary': 'Error occurred during API request',
                'details': {},
                'indicators': [],
                'metadata': {}
            },
            'error': error_message
        }
    
    def create_result(self, scan_id: int, target: str, raw_data: Dict[str, Any]) -> Result:
        """
        Create a Result object from API response.
        
        Args:
            scan_id: Scan ID
            target: Target
            raw_data: Raw API response
            
        Returns:
            Result object
        """
        try:
            # Normalize response
            normalized = self.normalize_response(raw_data, target)
            
            # Create result
            result = Result(
                scan_id=scan_id,
                source=normalized['source'],
                target=target,
                status=ResultStatus[normalized['status'].upper()],
                severity=Severity[normalized['severity'].upper()]
            )
            
            # Set data
            result.summary = normalized['data']['summary']
            result.set_details(normalized['data']['details'])
            result.set_indicators(normalized['data']['indicators'])
            result.set_metadata(normalized['data']['metadata'])
            
            if 'error' in normalized:
                result.error_message = normalized['error']
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error creating result: {str(e)}")
            
            # Create error result
            result = Result(
                scan_id=scan_id,
                source=self.__class__.__name__.lower().replace('api', ''),
                target=target,
                status=ResultStatus.ERROR,
                severity=Severity.INFO
            )
            result.error_message = f"Failed to process API response: {str(e)}"
            
            return result
    
    def get_supported_targets(self) -> List[str]:
        """
        Get list of supported target types.
        
        Returns:
            List of supported target types
        """
        return ['ip', 'domain', 'url', 'email', 'username', 'hash']
    
    def test_connection(self) -> bool:
        """
        Test connection to the API.
        
        Returns:
            True if connection successful, False otherwise
        """
        try:
            return self.validate_api_key()
        except Exception as e:
            self.logger.error(f"Connection test failed: {str(e)}")
            return False
    
    def get_rate_limit_info(self) -> Dict[str, Any]:
        """
        Get rate limit information.
        
        Returns:
            Dictionary with rate limit info
        """
        return {
            'rate_limit': self.rate_limit,
            'request_count': self.request_count,
            'last_request_time': self.last_request_time
        }
    
    def __del__(self):
        """
        Cleanup when service is destroyed.
        """
        if hasattr(self, 'session'):
            self.session.close()