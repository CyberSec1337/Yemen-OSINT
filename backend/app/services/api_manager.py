"""
API Manager for coordinating multiple API integrations.
Handles API key management, request orchestration, and response aggregation.
"""

import asyncio
import concurrent.futures
from datetime import datetime
from typing import Dict, List, Any, Optional, Tuple
import logging

from app.models.api_key import APIKey
from app.models.result import Result, ResultStatus
from app.services.apis import (
    ShodanAPI, VirusTotalAPI, AbuseIPDBAPI, 
    AlienVaultAPI, SecurityTrailsAPI
)


class APIManager:
    """
    Manages and coordinates multiple API integrations.
    Handles API key retrieval, service instantiation, and parallel execution.
    """
    
    def __init__(self, user_id: int):
        """
        Initialize API Manager for a user.
        
        Args:
            user_id: User ID to get API keys for
        """
        self.user_id = user_id
        self.logger = logging.getLogger(self.__class__.__name__)
        self.services = {}
        self.api_keys = {}
        
        # API service mapping
        self.service_classes = {
            'shodan': ShodanAPI,
            'virustotal': VirusTotalAPI,
            'abuseipdb': AbuseIPDBAPI,
            'alienvault': AlienVaultAPI,
            'securitytrails': SecurityTrailsAPI
        }
        
        # Load user's API keys
        self._load_api_keys()
    
    def _load_api_keys(self):
        """Load and cache user's API keys."""
        try:
            api_keys = APIKey.get_active_keys_for_user(self.user_id)
            
            for api_key_obj in api_keys:
                service_name = api_key_obj.service_name
                decrypted_key = api_key_obj.get_decrypted_key()
                
                self.api_keys[service_name] = {
                    'key': decrypted_key,
                    'object': api_key_obj
                }
                
                # Instantiate service if key is available
                if service_name in self.service_classes:
                    self.services[service_name] = self.service_classes[service_name](decrypted_key)
            
            self.logger.info(f"Loaded {len(self.api_keys)} API keys for user {self.user_id}")
            
        except Exception as e:
            self.logger.error(f"Failed to load API keys: {str(e)}")
    
    def get_available_services(self) -> List[str]:
        """
        Get list of available API services.
        
        Returns:
            List of service names that have valid API keys
        """
        return list(self.services.keys())
    
    def validate_service(self, service_name: str) -> bool:
        """
        Validate if a service is available and has valid API key.
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if service is available, False otherwise
        """
        if service_name not in self.services:
            return False
        
        try:
            return self.services[service_name].validate_api_key()
        except Exception as e:
            self.logger.error(f"Service validation failed for {service_name}: {str(e)}")
            return False
    
    def validate_all_services(self) -> Dict[str, bool]:
        """
        Validate all available services.
        
        Returns:
            Dictionary mapping service names to validation status
        """
        validation_results = {}
        
        for service_name in self.services:
            validation_results[service_name] = self.validate_service(service_name)
        
        return validation_results
    
    def execute_single_query(self, service_name: str, target: str, query_type: str = 'default') -> Optional[Dict[str, Any]]:
        """
        Execute a single API query.
        
        Args:
            service_name: Name of the service
            target: Target to query
            query_type: Type of query
            
        Returns:
            API response or None if failed
        """
        if service_name not in self.services:
            self.logger.error(f"Service {service_name} not available")
            return None
        
        try:
            service = self.services[service_name]
            
            # Record API key usage
            if service_name in self.api_keys:
                self.api_keys[service_name]['object'].record_usage()
            
            # Execute query
            start_time = datetime.utcnow()
            response = service.search(target, query_type)
            end_time = datetime.utcnow()
            
            # Calculate response time
            response_time = int((end_time - start_time).total_seconds() * 1000)
            
            self.logger.info(f"Query executed: {service_name} for {target} in {response_time}ms")
            
            return response
            
        except Exception as e:
            self.logger.error(f"Query failed for {service_name} on {target}: {str(e)}")
            return None
    
    def execute_parallel_queries(self, target: str, services: List[str], query_types: Dict[str, str] = None) -> Dict[str, Any]:
        """
        Execute multiple API queries in parallel.
        
        Args:
            target: Target to query
            services: List of service names to query
            query_types: Optional mapping of service names to query types
            
        Returns:
            Dictionary mapping service names to responses
        """
        if query_types is None:
            query_types = {}
        
        # Filter available services
        available_services = [s for s in services if s in self.services]
        
        if not available_services:
            self.logger.warning("No available services for parallel query")
            return {}
        
        results = {}
        
        # Use ThreadPoolExecutor for parallel execution
        with concurrent.futures.ThreadPoolExecutor(max_workers=min(len(available_services), 5)) as executor:
            # Submit all tasks
            future_to_service = {}
            
            for service_name in available_services:
                query_type = query_types.get(service_name, 'default')
                future = executor.submit(self.execute_single_query, service_name, target, query_type)
                future_to_service[future] = service_name
            
            # Collect results as they complete
            for future in concurrent.futures.as_completed(future_to_service):
                service_name = future_to_service[future]
                
                try:
                    result = future.result(timeout=60)  # 60 second timeout per service
                    results[service_name] = result
                except Exception as e:
                    self.logger.error(f"Parallel query failed for {service_name}: {str(e)}")
                    results[service_name] = None
        
        self.logger.info(f"Parallel query completed: {len(results)} results for {target}")
        return results
    
    def get_service_info(self, service_name: str) -> Optional[Dict[str, Any]]:
        """
        Get information about a specific service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            Service information or None if not available
        """
        if service_name not in self.services:
            return None
        
        service = self.services[service_name]
        api_key_info = self.api_keys.get(service_name, {})
        
        return {
            'name': service_name,
            'class_name': service.__class__.__name__,
            'base_url': service.base_url,
            'rate_limit': service.rate_limit,
            'timeout': service.timeout,
            'supported_targets': service.get_supported_targets(),
            'api_key_last_used': api_key_info.get('object', {}).last_used.isoformat() if api_key_info.get('object') else None,
            'api_key_usage_count': api_key_info.get('object', {}).usage_count if api_key_info.get('object') else 0,
            'rate_limit_info': service.get_rate_limit_info()
        }
    
    def get_all_services_info(self) -> Dict[str, Dict[str, Any]]:
        """
        Get information about all available services.
        
        Returns:
            Dictionary mapping service names to service information
        """
        services_info = {}
        
        for service_name in self.services:
            services_info[service_name] = self.get_service_info(service_name)
        
        return services_info
    
    def test_service_connection(self, service_name: str) -> bool:
        """
        Test connection to a specific service.
        
        Args:
            service_name: Name of the service
            
        Returns:
            True if connection successful, False otherwise
        """
        if service_name not in self.services:
            return False
        
        try:
            service = self.services[service_name]
            return service.test_connection()
        except Exception as e:
            self.logger.error(f"Connection test failed for {service_name}: {str(e)}")
            return False
    
    def test_all_connections(self) -> Dict[str, bool]:
        """
        Test connections to all available services.
        
        Returns:
            Dictionary mapping service names to connection status
        """
        connection_results = {}
        
        for service_name in self.services:
            connection_results[service_name] = self.test_service_connection(service_name)
        
        return connection_results
    
    def get_optimal_query_type(self, service_name: str, target: str) -> str:
        """
        Determine the optimal query type for a service and target.
        
        Args:
            service_name: Name of the service
            target: Target to query
            
        Returns:
            Optimal query type
        """
        if service_name not in self.services:
            return 'default'
        
        service = self.services[service_name]
        supported_targets = service.get_supported_targets()
        
        # Simple target type detection
        if self._is_ip(target):
            return 'ip' if 'ip' in supported_targets else 'default'
        elif self._is_domain(target):
            return 'domain' if 'domain' in supported_targets else 'default'
        elif self._is_url(target):
            return 'url' if 'url' in supported_targets else 'default'
        elif self._is_hash(target):
            return 'hash' if 'hash' in supported_targets else 'default'
        else:
            return 'default'
    
    def _is_ip(self, target: str) -> bool:
        """Check if target is an IP address."""
        import ipaddress
        try:
            ipaddress.ip_address(target)
            return True
        except ValueError:
            return False
    
    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain name."""
        import re
        pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
        return re.match(pattern, target) is not None and len(target) <= 253
    
    def _is_url(self, target: str) -> bool:
        """Check if target is a URL."""
        from urllib.parse import urlparse
        try:
            result = urlparse(target)
            return all([result.scheme, result.netloc])
        except Exception:
            return False
    
    def _is_hash(self, target: str) -> bool:
        """Check if target is a hash."""
        import re
        patterns = [
            r'^[a-f0-9]{32}$',   # MD5
            r'^[a-f0-9]{40}$',   # SHA1
            r'^[a-f0-9]{64}$',   # SHA256
        ]
        return any(re.match(pattern, target.lower()) for pattern in patterns)
    
    def get_service_statistics(self) -> Dict[str, Any]:
        """
        Get usage statistics for all services.
        
        Returns:
            Statistics dictionary
        """
        stats = {
            'total_services': len(self.services),
            'available_services': list(self.services.keys()),
            'api_keys_count': len(self.api_keys),
            'services': {}
        }
        
        for service_name in self.services:
            service_info = self.get_service_info(service_name)
            stats['services'][service_name] = {
                'rate_limit': service_info['rate_limit'],
                'usage_count': service_info['api_key_usage_count'],
                'last_used': service_info['api_key_last_used'],
                'supported_targets': service_info['supported_targets']
            }
        
        return stats
    
    def refresh_api_keys(self):
        """Refresh API keys from database."""
        self._load_api_keys()
        self.logger.info("API keys refreshed")
    
    def __del__(self):
        """Cleanup when manager is destroyed."""
        for service_name in self.services:
            try:
                if hasattr(self.services[service_name], '__del__'):
                    self.services[service_name].__del__()
            except Exception as e:
                self.logger.error(f"Error cleaning up service {service_name}: {str(e)}")