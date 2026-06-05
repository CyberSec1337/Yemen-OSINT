"""
Data Processor for normalizing and correlating OSINT data.
Handles data normalization, deduplication, and correlation analysis.
"""

import re
import hashlib
from datetime import datetime
from typing import Dict, List, Any, Set, Tuple, Optional
import logging

from app.models.result import Result, Severity
from app.utils.helpers import (
    extract_domains_from_text, extract_ips_from_text, 
    extract_urls_from_text, extract_emails_from_text,
    calculate_confidence_score, create_summary_from_indicators
)


class DataProcessor:
    """
    Processes and normalizes OSINT data from multiple sources.
    Handles deduplication, correlation, and threat scoring.
    """
    
    def __init__(self):
        """Initialize data processor."""
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Correlation rules
        self.correlation_rules = {
            'ip_domain': self._correlate_ip_domain,
            'domain_subdomain': self._correlate_domain_subdomain,
            'email_domain': self._correlate_email_domain,
            'url_domain': self._correlate_url_domain,
            'hash_ip': self._correlate_hash_ip,
            'similar_indicators': self._correlate_similar_indicators
        }
        
        # Severity weights
        self.severity_weights = {
            'critical': 5,
            'high': 4,
            'medium': 3,
            'low': 2,
            'info': 1
        }
    
    def normalize_api_response(self, api_name: str, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Normalize API response to standard format.
        
        Args:
            api_name: Name of the API
            raw_data: Raw API response
            target: Original target
            
        Returns:
            Normalized response
        """
        try:
            # Get the appropriate API service and normalize
            from app.services.api_manager import APIManager
            
            # Create a temporary API manager to get the service
            # This is a bit inefficient but ensures proper normalization
            temp_manager = APIManager(user_id=0)  # Temporary user ID
            
            if api_name in temp_manager.services:
                service = temp_manager.services[api_name]
                return service.normalize_response(raw_data, target)
            else:
                # Fallback normalization
                return self._fallback_normalization(api_name, raw_data, target)
                
        except Exception as e:
            self.logger.error(f"Normalization failed for {api_name}: {str(e)}")
            return self._create_error_response(api_name, target, str(e))
    
    def _fallback_normalization(self, api_name: str, raw_data: Dict[str, Any], target: str) -> Dict[str, Any]:
        """
        Fallback normalization when specific API service is not available.
        
        Args:
            api_name: Name of the API
            raw_data: Raw API response
            target: Original target
            
        Returns:
            Normalized response
        """
        # Extract basic indicators from raw data
        indicators = self._extract_indicators_from_raw_data(raw_data)
        
        # Calculate severity based on indicators
        severity = self._calculate_severity_from_indicators(indicators)
        
        # Create summary
        summary = f"Data from {api_name} for {target}: {len(indicators)} indicators found"
        
        return {
            'source': api_name,
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'success',
            'severity': severity,
            'data': {
                'summary': summary,
                'details': raw_data,
                'indicators': indicators,
                'metadata': {
                    'source': api_name,
                    'processing_time': datetime.utcnow().isoformat(),
                    'indicator_count': len(indicators)
                }
            },
            'error': None
        }
    
    def _extract_indicators_from_raw_data(self, raw_data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """
        Extract indicators from raw API data.
        
        Args:
            raw_data: Raw API response
            
        Returns:
            List of indicators
        """
        indicators = []
        data_str = str(raw_data).lower()
        
        # Extract IPs
        ips = extract_ips_from_text(data_str)
        for ip in ips:
            indicators.append({
                'type': 'ip',
                'value': ip,
                'severity': 'medium'
            })
        
        # Extract domains
        domains = extract_domains_from_text(data_str)
        for domain in domains:
            indicators.append({
                'type': 'domain',
                'value': domain,
                'severity': 'low'
            })
        
        # Extract URLs
        urls = extract_urls_from_text(data_str)
        for url in urls:
            indicators.append({
                'type': 'url',
                'value': url,
                'severity': 'medium'
            })
        
        # Extract emails
        emails = extract_emails_from_text(data_str)
        for email in emails:
            indicators.append({
                'type': 'email',
                'value': email,
                'severity': 'low'
            })
        
        return indicators
    
    def _calculate_severity_from_indicators(self, indicators: List[Dict[str, Any]]) -> str:
        """
        Calculate severity based on indicators.
        
        Args:
            indicators: List of indicators
            
        Returns:
            Severity level
        """
        if not indicators:
            return Severity.INFO.value
        
        # Count indicators by severity
        severity_counts = {}
        for indicator in indicators:
            severity = indicator.get('severity', 'info')
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        # Determine overall severity
        if severity_counts.get('critical', 0) > 0:
            return Severity.CRITICAL.value
        elif severity_counts.get('high', 0) > 0:
            return Severity.HIGH.value
        elif severity_counts.get('medium', 0) >= 3:
            return Severity.HIGH.value
        elif severity_counts.get('medium', 0) > 0:
            return Severity.MEDIUM.value
        elif len(indicators) > 10:
            return Severity.MEDIUM.value
        elif len(indicators) > 0:
            return Severity.LOW.value
        else:
            return Severity.INFO.value
    
    def deduplicate_results(self, results: List[Result]) -> List[Result]:
        """
        Remove duplicate results based on content.
        
        Args:
            results: List of results to deduplicate
            
        Returns:
            Deduplicated list of results
        """
        if not results:
            return results
        
        seen_hashes = set()
        deduplicated = []
        
        for result in results:
            # Create content hash
            content = f"{result.source}_{result.target}_{result.summary}"
            content_hash = hashlib.md5(content.encode()).hexdigest()
            
            if content_hash not in seen_hashes:
                seen_hashes.add(content_hash)
                deduplicated.append(result)
        
        self.logger.info(f"Deduplicated {len(results)} results to {len(deduplicated)}")
        return deduplicated
    
    def correlate_results(self, results: List[Result]) -> List[Tuple[Result, Result, str]]:
        """
        Find correlations between results.
        
        Args:
            results: List of results to correlate
            
        Returns:
            List of tuples (result1, result2, correlation_type)
        """
        correlations = []
        
        for i, result1 in enumerate(results):
            for result2 in results[i+1:]:
                correlation_type = self._find_correlation(result1, result2)
                if correlation_type:
                    correlations.append((result1, result2, correlation_type))
        
        self.logger.info(f"Found {len(correlations)} correlations")
        return correlations
    
    def _find_correlation(self, result1: Result, result2: Result) -> Optional[str]:
        """
        Find correlation type between two results.
        
        Args:
            result1: First result
            result2: Second result
            
        Returns:
            Correlation type or None if no correlation
        """
        # Check different correlation rules
        for rule_name, rule_func in self.correlation_rules.items():
            if rule_func(result1, result2):
                return rule_name
        
        return None
    
    def _correlate_ip_domain(self, result1: Result, result2: Result) -> bool:
        """Check if results are correlated via IP-domain relationship."""
        indicators1 = result1.get_indicators()
        indicators2 = result2.get_indicators()
        
        # Extract IPs from result1
        ips1 = [ind['value'] for ind in indicators1 if ind['type'] == 'ip']
        # Extract domains from result2
        domains2 = [ind['value'] for ind in indicators2 if ind['type'] == 'domain']
        
        # Simple correlation: if result1 has IPs and result2 has domains
        return len(ips1) > 0 and len(domains2) > 0
    
    def _correlate_domain_subdomain(self, result1: Result, result2: Result) -> bool:
        """Check if results are correlated via domain-subdomain relationship."""
        indicators1 = result1.get_indicators()
        indicators2 = result2.get_indicators()
        
        domains1 = [ind['value'] for ind in indicators1 if ind['type'] == 'domain']
        domains2 = [ind['value'] for ind in indicators2 if ind['type'] == 'domain']
        
        # Check if any domain is a subdomain of another
        for domain1 in domains1:
            for domain2 in domains2:
                if self._is_subdomain(domain1, domain2) or self._is_subdomain(domain2, domain1):
                    return True
        
        return False
    
    def _correlate_email_domain(self, result1: Result, result2: Result) -> bool:
        """Check if results are correlated via email-domain relationship."""
        indicators1 = result1.get_indicators()
        indicators2 = result2.get_indicators()
        
        emails1 = [ind['value'] for ind in indicators1 if ind['type'] == 'email']
        domains2 = [ind['value'] for ind in indicators2 if ind['type'] == 'domain']
        
        # Check if any email domain matches any domain
        for email in emails1:
            email_domain = email.split('@')[-1] if '@' in email else ''
            if email_domain in domains2:
                return True
        
        return False
    
    def _correlate_url_domain(self, result1: Result, result2: Result) -> bool:
        """Check if results are correlated via URL-domain relationship."""
        indicators1 = result1.get_indicators()
        indicators2 = result2.get_indicators()
        
        urls1 = [ind['value'] for ind in indicators1 if ind['type'] == 'url']
        domains2 = [ind['value'] for ind in indicators2 if ind['type'] == 'domain']
        
        # Check if any URL domain matches any domain
        for url in urls1:
            try:
                from urllib.parse import urlparse
                parsed = urlparse(url)
                url_domain = parsed.netloc
                if url_domain in domains2:
                    return True
            except:
                pass
        
        return False
    
    def _correlate_hash_ip(self, result1: Result, result2: Result) -> bool:
        """Check if results are correlated via hash-IP relationship."""
        indicators1 = result1.get_indicators()
        indicators2 = result2.get_indicators()
        
        hashes1 = [ind['value'] for ind in indicators1 if ind['type'] == 'hash']
        ips2 = [ind['value'] for ind in indicators2 if ind['type'] == 'ip']
        
        # Simple correlation: if result1 has hashes and result2 has IPs
        return len(hashes1) > 0 and len(ips2) > 0
    
    def _correlate_similar_indicators(self, result1: Result, result2: Result) -> bool:
        """Check if results have similar indicators."""
        indicators1 = result1.get_indicators()
        indicators2 = result2.get_indicators()
        
        # Check for overlapping indicator values
        values1 = set(ind['value'] for ind in indicators1)
        values2 = set(ind['value'] for ind in indicators2)
        
        overlap = values1.intersection(values2)
        return len(overlap) > 0
    
    def _is_subdomain(self, potential_subdomain: str, domain: str) -> bool:
        """Check if potential_subdomain is a subdomain of domain."""
        return potential_subdomain.endswith(f'.{domain}') and potential_subdomain != domain
    
    def calculate_overall_severity(self, results: List[Result]) -> str:
        """
        Calculate overall severity from multiple results.
        
        Args:
            results: List of results
            
        Returns:
            Overall severity
        """
        if not results:
            return Severity.INFO.value
        
        # Weight severity calculation
        total_weight = 0
        total_score = 0
        
        for result in results:
            severity = result.severity
            weight = self.severity_weights.get(severity.value, 1)
            
            total_weight += weight
            total_score += weight
        
        if total_score == 0:
            return Severity.INFO.value
        
        average_score = total_score / len(results)
        
        # Determine overall severity based on average
        if average_score >= 4.5:
            return Severity.CRITICAL.value
        elif average_score >= 3.5:
            return Severity.HIGH.value
        elif average_score >= 2.5:
            return Severity.MEDIUM.value
        elif average_score >= 1.5:
            return Severity.LOW.value
        else:
            return Severity.INFO.value
    
    def create_summary_report(self, results: List[Result]) -> Dict[str, Any]:
        """
        Create a summary report from multiple results.
        
        Args:
            results: List of results
            
        Returns:
            Summary report
        """
        if not results:
            return {
                'summary': 'No results found',
                'total_results': 0,
                'severity_breakdown': {},
                'source_breakdown': {},
                'indicator_breakdown': {},
                'correlations': []
            }
        
        # Count results by severity
        severity_breakdown = {}
        for result in results:
            severity = result.severity.value
            severity_breakdown[severity] = severity_breakdown.get(severity, 0) + 1
        
        # Count results by source
        source_breakdown = {}
        for result in results:
            source = result.source
            source_breakdown[source] = source_breakdown.get(source, 0) + 1
        
        # Count indicators by type
        indicator_breakdown = {}
        all_indicators = []
        
        for result in results:
            indicators = result.get_indicators()
            all_indicators.extend(indicators)
            
            for indicator in indicators:
                indicator_type = indicator['type']
                indicator_breakdown[indicator_type] = indicator_breakdown.get(indicator_type, 0) + 1
        
        # Find correlations
        correlations = self.correlate_results(results)
        
        # Create summary
        overall_severity = self.calculate_overall_severity(results)
        
        summary = f"Analysis complete: {len(results)} results from {len(source_breakdown)} sources"
        summary += f" with overall severity: {overall_severity}"
        
        if severity_breakdown.get('critical', 0) > 0:
            summary += f". {severity_breakdown['critical']} critical findings"
        
        return {
            'summary': summary,
            'total_results': len(results),
            'overall_severity': overall_severity,
            'severity_breakdown': severity_breakdown,
            'source_breakdown': source_breakdown,
            'indicator_breakdown': indicator_breakdown,
            'correlation_count': len(correlations),
            'unique_indicators': len(set(ind['value'] for ind in all_indicators)),
            'processing_time': datetime.utcnow().isoformat()
        }
    
    def enrich_result(self, result: Result) -> Result:
        """
        Enrich a result with additional analysis.
        
        Args:
            result: Result to enrich
            
        Returns:
            Enriched result
        """
        try:
            # Extract and process indicators
            indicators = result.get_indicators()
            
            # Calculate confidence score
            confidence = calculate_confidence_score(indicators, 75)  # Base confidence of 75%
            result.confidence = confidence
            
            # Create enhanced summary
            enhanced_summary = create_summary_from_indicators(indicators)
            if enhanced_summary != result.summary:
                result.summary = enhanced_summary
            
            # Mark as processed
            result.processed = True
            
            return result
            
        except Exception as e:
            self.logger.error(f"Result enrichment failed: {str(e)}")
            return result
    
    def _create_error_response(self, api_name: str, target: str, error_message: str) -> Dict[str, Any]:
        """Create error response."""
        return {
            'source': api_name,
            'target': target,
            'timestamp': datetime.utcnow().isoformat(),
            'status': 'error',
            'severity': Severity.INFO.value,
            'data': {
                'summary': f'Failed to process {api_name} data',
                'details': {},
                'indicators': [],
                'metadata': {}
            },
            'error': error_message
        }