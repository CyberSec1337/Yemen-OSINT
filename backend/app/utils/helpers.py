"""
Helper functions for the OSINT Platform.
"""

import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from urllib.parse import urlparse
import ipaddress


def format_timestamp(timestamp: datetime, format_str: str = '%Y-%m-%d %H:%M:%S UTC') -> str:
    """
    Format timestamp to string.
    
    Args:
        timestamp: DateTime object
        format_str: Format string
        
    Returns:
        Formatted timestamp string
    """
    if not timestamp:
        return ''
    
    return timestamp.strftime(format_str)


def calculate_severity(indicators: List[Dict], base_severity: str = 'info') -> str:
    """
    Calculate overall severity from indicators.
    
    Args:
        indicators: List of indicators with severity
        base_severity: Base severity level
        
    Returns:
        Calculated severity
    """
    severity_levels = {
        'info': 1,
        'low': 2,
        'medium': 3,
        'high': 4,
        'critical': 5
    }
    
    max_severity = base_severity
    max_score = severity_levels.get(base_severity, 1)
    
    for indicator in indicators:
        indicator_severity = indicator.get('severity', 'info')
        indicator_score = severity_levels.get(indicator_severity, 1)
        
        if indicator_score > max_score:
            max_severity = indicator_severity
            max_score = indicator_score
    
    return max_severity


def normalize_domain(domain: str) -> str:
    """
    Normalize domain name.
    
    Args:
        domain: Domain name to normalize
        
    Returns:
        Normalized domain
    """
    if not domain:
        return ''
    
    # Remove protocol
    domain = domain.replace('http://', '').replace('https://', '')
    
    # Remove path
    domain = domain.split('/')[0]
    
    # Remove port
    domain = domain.split(':')[0]
    
    # Convert to lowercase
    domain = domain.lower()
    
    # Remove trailing dot
    domain = domain.rstrip('.')
    
    return domain


def normalize_ip(ip: str) -> str:
    """
    Normalize IP address.
    
    Args:
        ip: IP address to normalize
        
    Returns:
        Normalized IP address
    """
    if not ip:
        return ''
    
    try:
        # Parse and format IP address
        ip_obj = ipaddress.ip_address(ip)
        return str(ip_obj)
    except ValueError:
        return ip


def extract_domains_from_text(text: str) -> List[str]:
    """
    Extract domain names from text.
    
    Args:
        text: Text to extract domains from
        
    Returns:
        List of domain names
    """
    if not text:
        return []
    
    # Domain regex pattern
    domain_pattern = r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b'
    
    domains = re.findall(domain_pattern, text, re.IGNORECASE)
    
    # Normalize and deduplicate
    normalized_domains = []
    seen = set()
    
    for domain in domains:
        normalized = normalize_domain(domain)
        if normalized and normalized not in seen:
            seen.add(normalized)
            normalized_domains.append(normalized)
    
    return normalized_domains


def extract_ips_from_text(text: str) -> List[str]:
    """
    Extract IP addresses from text.
    
    Args:
        text: Text to extract IPs from
        
    Returns:
        List of IP addresses
    """
    if not text:
        return []
    
    # IP regex patterns
    ipv4_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    ipv6_pattern = r'\b(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}\b'
    
    ips = re.findall(f'{ipv4_pattern}|{ipv6_pattern}', text)
    
    # Validate and normalize
    valid_ips = []
    seen = set()
    
    for ip in ips:
        normalized = normalize_ip(ip)
        if normalized and validate_ip(normalized) and normalized not in seen:
            seen.add(normalized)
            valid_ips.append(normalized)
    
    return valid_ips


def extract_urls_from_text(text: str) -> List[str]:
    """
    Extract URLs from text.
    
    Args:
        text: Text to extract URLs from
        
    Returns:
        List of URLs
    """
    if not text:
        return []
    
    # URL regex pattern
    url_pattern = r'https?://(?:[-\w.])+(?:[:\d]+)?(?:/(?:[\w/_.])*(?:\?(?:[\w&=%.])*)?(?:#(?:[\w.])*)?)?'
    
    urls = re.findall(url_pattern, text)
    
    # Deduplicate
    return list(set(urls))


def extract_emails_from_text(text: str) -> List[str]:
    """
    Extract email addresses from text.
    
    Args:
        text: Text to extract emails from
        
    Returns:
        List of email addresses
    """
    if not text:
        return []
    
    # Email regex pattern
    email_pattern = r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b'
    
    emails = re.findall(email_pattern, text)
    
    # Normalize and deduplicate
    normalized_emails = []
    seen = set()
    
    for email in emails:
        normalized = email.lower()
        if normalized not in seen:
            seen.add(normalized)
            normalized_emails.append(normalized)
    
    return normalized_emails


def calculate_confidence_score(indicators: List[Dict], source_reliability: int = 50) -> int:
    """
    Calculate confidence score based on indicators and source reliability.
    
    Args:
        indicators: List of indicators
        source_reliability: Reliability score of the source (0-100)
        
    Returns:
        Confidence score (0-100)
    """
    if not indicators:
        return source_reliability
    
    # Base confidence from source reliability
    confidence = source_reliability
    
    # Adjust based on number of indicators
    indicator_count = len(indicators)
    if indicator_count > 10:
        confidence += 20
    elif indicator_count > 5:
        confidence += 10
    elif indicator_count > 2:
        confidence += 5
    
    # Adjust based on indicator diversity
    indicator_types = set(ind.get('type', 'unknown') for ind in indicators)
    if len(indicator_types) > 3:
        confidence += 15
    elif len(indicator_types) > 2:
        confidence += 10
    elif len(indicator_types) > 1:
        confidence += 5
    
    # Ensure confidence is within bounds
    return max(0, min(100, confidence))


def create_summary_from_indicators(indicators: List[Dict]) -> str:
    """
    Create a summary from indicators.
    
    Args:
        indicators: List of indicators
        
    Returns:
        Summary string
    """
    if not indicators:
        return 'No indicators found'
    
    # Count indicators by type
    type_counts = {}
    severity_counts = {}
    
    for indicator in indicators:
        indicator_type = indicator.get('type', 'unknown')
        severity = indicator.get('severity', 'info')
        
        type_counts[indicator_type] = type_counts.get(indicator_type, 0) + 1
        severity_counts[severity] = severity_counts.get(severity, 0) + 1
    
    # Build summary
    summary_parts = []
    
    # Total indicators
    summary_parts.append(f"Found {len(indicators)} indicators")
    
    # Types
    if type_counts:
        types_str = ', '.join([f"{count} {type_}" for type_, count in type_counts.items()])
        summary_parts.append(f"({types_str})")
    
    # Severity
    if severity_counts:
        high_count = severity_counts.get('high', 0) + severity_counts.get('critical', 0)
        if high_count > 0:
            summary_parts.append(f"including {high_count} high-severity findings")
    
    return ' '.join(summary_parts)


def sanitize_json_response(data: Any) -> Any:
    """
    Sanitize data for JSON response.
    
    Args:
        data: Data to sanitize
        
    Returns:
        Sanitized data
    """
    if isinstance(data, dict):
        return {key: sanitize_json_response(value) for key, value in data.items()}
    elif isinstance(data, list):
        return [sanitize_json_response(item) for item in data]
    elif isinstance(data, datetime):
        return data.isoformat()
    elif isinstance(data, bytes):
        return data.decode('utf-8', errors='ignore')
    else:
        return data


def parse_time_range(time_range: str) -> tuple[datetime, datetime]:
    """
    Parse time range string into start and end datetime.
    
    Args:
        time_range: Time range string (e.g., "24h", "7d", "30d")
        
    Returns:
        Tuple of (start_datetime, end_datetime)
    """
    now = datetime.utcnow()
    
    if time_range.endswith('h'):
        hours = int(time_range[:-1])
        start = now - timedelta(hours=hours)
    elif time_range.endswith('d'):
        days = int(time_range[:-1])
        start = now - timedelta(days=days)
    elif time_range.endswith('w'):
        weeks = int(time_range[:-1])
        start = now - timedelta(weeks=weeks)
    elif time_range.endswith('m'):
        months = int(time_range[:-1])
        start = now - timedelta(days=months * 30)
    else:
        # Default to 24 hours
        start = now - timedelta(hours=24)
    
    return start, now


def format_file_size(size_bytes: int) -> str:
    """
    Format file size in human-readable format.
    
    Args:
        size_bytes: Size in bytes
        
    Returns:
        Formatted size string
    """
    if size_bytes == 0:
        return '0 B'
    
    size_names = ['B', 'KB', 'MB', 'GB', 'TB']
    i = 0
    
    while size_bytes >= 1024 and i < len(size_names) - 1:
        size_bytes /= 1024.0
        i += 1
    
    return f'{size_bytes:.1f} {size_names[i]}'


def truncate_string(text: str, max_length: int = 100, suffix: str = '...') -> str:
    """
    Truncate string to maximum length.
    
    Args:
        text: String to truncate
        max_length: Maximum length
        suffix: Suffix to add if truncated
        
    Returns:
        Truncated string
    """
    if not text or len(text) <= max_length:
        return text
    
    return text[:max_length - len(suffix)] + suffix


def validate_ip(ip: str) -> bool:
    """
    Validate IP address.
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if valid, False otherwise
    """
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def is_private_ip(ip: str) -> bool:
    """
    Check if IP address is private.
    
    Args:
        ip: IP address to check
        
    Returns:
        True if private, False otherwise
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        return ip_obj.is_private
    except ValueError:
        return False


def get_ip_geolocation_info(ip: str) -> Dict[str, Any]:
    """
    Get basic geolocation information for an IP.
    
    Args:
        ip: IP address
        
    Returns:
        Dictionary with geolocation info
    """
    try:
        ip_obj = ipaddress.ip_address(ip)
        
        return {
            'ip': str(ip_obj),
            'version': ip_obj.version,
            'is_private': ip_obj.is_private,
            'is_loopback': ip_obj.is_loopback,
            'is_multicast': ip_obj.is_multicast,
            'is_reserved': ip_obj.is_reserved,
        }
    except ValueError:
        return {'ip': ip, 'error': 'Invalid IP address'}