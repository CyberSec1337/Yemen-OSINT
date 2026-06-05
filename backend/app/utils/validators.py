"""
Input validation utilities.
"""

import re
import ipaddress
from urllib.parse import urlparse
from typing import Optional, List


def validate_email(email: str) -> bool:
    """
    Validate email address format.
    
    Args:
        email: Email address to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not email or not isinstance(email, str):
        return False
    
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(pattern, email) is not None


def validate_ip(ip: str) -> bool:
    """
    Validate IP address (IPv4 or IPv6).
    
    Args:
        ip: IP address to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not ip or not isinstance(ip, str):
        return False
    
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False


def validate_domain(domain: str) -> bool:
    """
    Validate domain name.
    
    Args:
        domain: Domain name to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not domain or not isinstance(domain, str):
        return False
    
    # Remove protocol if present
    domain = domain.replace('http://', '').replace('https://', '').split('/')[0]
    
    # Basic domain validation
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return re.match(pattern, domain) is not None and len(domain) <= 253


def validate_url(url: str) -> bool:
    """
    Validate URL format.
    
    Args:
        url: URL to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not url or not isinstance(url, str):
        return False
    
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except Exception:
        return False


def validate_bitcoin_address(address: str) -> bool:
    """
    Validate Bitcoin address format.
    
    Args:
        address: Bitcoin address to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not address or not isinstance(address, str):
        return False
    
    # Basic Bitcoin address validation (legacy, segwit, and taproot)
    patterns = [
        r'^[13][a-km-zA-HJ-NP-Z1-9]{25,34}$',  # Legacy addresses
        r'^bc1[a-z0-9]{39,59}$',               # Bech32 addresses
    ]
    
    return any(re.match(pattern, address) for pattern in patterns)


def validate_hash(hash_string: str) -> bool:
    """
    Validate hash format (MD5, SHA1, SHA256, etc.).
    
    Args:
        hash_string: Hash string to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not hash_string or not isinstance(hash_string, str):
        return False
    
    # Remove common prefixes
    hash_string = hash_string.lower().replace('md5:', '').replace('sha1:', '').replace('sha256:', '')
    
    # Hash length patterns
    patterns = [
        r'^[a-f0-9]{32}$',   # MD5
        r'^[a-f0-9]{40}$',   # SHA1
        r'^[a-f0-9]{64}$',   # SHA256
        r'^[a-f0-9]{128}$',  # SHA512
    ]
    
    return any(re.match(pattern, hash_string) for pattern in patterns)


def validate_username(username: str) -> bool:
    """
    Validate username format.
    
    Args:
        username: Username to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not username or not isinstance(username, str):
        return False
    
    # Username validation (3-30 characters, alphanumeric + underscore + hyphen)
    pattern = r'^[a-zA-Z0-9_-]{3,30}$'
    return re.match(pattern, username) is not None


def validate_target(target: str, target_type: str) -> bool:
    """
    Validate target based on its type.
    
    Args:
        target: Target string to validate
        target_type: Type of target (ip, domain, url, email, username, bitcoin, hash)
        
    Returns:
        True if valid, False otherwise
    """
    validators = {
        'ip': validate_ip,
        'domain': validate_domain,
        'url': validate_url,
        'email': validate_email,
        'username': validate_username,
        'bitcoin': validate_bitcoin_address,
        'hash': validate_hash,
    }
    
    validator = validators.get(target_type.lower())
    if not validator:
        return False
    
    return validator(target)


def validate_api_key(api_key: str) -> bool:
    """
    Validate API key format.
    
    Args:
        api_key: API key to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not api_key or not isinstance(api_key, str):
        return False
    
    # Basic API key validation (16-128 characters, alphanumeric + common symbols)
    pattern = r'^[a-zA-Z0-9_\-\.]{16,128}$'
    return re.match(pattern, api_key) is not None


def validate_scan_name(name: str) -> bool:
    """
    Validate scan name.
    
    Args:
        name: Scan name to validate
        
    Returns:
        True if valid, False otherwise
    """
    if not name or not isinstance(name, str):
        return False
    
    # Scan name validation (1-200 characters)
    return 1 <= len(name.strip()) <= 200


def validate_bulk_targets(targets: List[str], target_type: str) -> tuple[bool, List[str]]:
    """
    Validate list of targets for bulk scanning.
    
    Args:
        targets: List of target strings
        target_type: Type of targets
        
    Returns:
        Tuple of (is_valid, list_of_invalid_targets)
    """
    if not targets or not isinstance(targets, list):
        return False, []
    
    if len(targets) > 100:  # Bulk scan limit
        return False, []
    
    invalid_targets = []
    for target in targets:
        if not validate_target(target.strip(), target_type):
            invalid_targets.append(target)
    
    return len(invalid_targets) == 0, invalid_targets


def sanitize_input(input_string: str) -> str:
    """
    Sanitize user input by removing potentially harmful characters.
    
    Args:
        input_string: Input string to sanitize
        
    Returns:
        Sanitized string
    """
    if not input_string or not isinstance(input_string, str):
        return ''
    
    # Remove potential SQL injection and XSS characters
    dangerous_chars = ['<', '>', '"', "'", '&', ';', '(', ')', '{', '}', '[', ']', '|', '\\']
    
    sanitized = input_string
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    
    return sanitized.strip()


def validate_pagination_params(page: int, per_page: int, max_per_page: int = 100) -> tuple[int, int]:
    """
    Validate and normalize pagination parameters.
    
    Args:
        page: Page number
        per_page: Items per page
        max_per_page: Maximum allowed items per page
        
    Returns:
        Tuple of (validated_page, validated_per_page)
    """
    page = max(1, int(page) if page else 1)
    per_page = max(1, min(max_per_page, int(per_page) if per_page else 20))
    
    return page, per_page


def validate_date_range(start_date: Optional[str], end_date: Optional[str]) -> tuple[bool, Optional[str], Optional[str]]:
    """
    Validate date range parameters.
    
    Args:
        start_date: Start date string (ISO format)
        end_date: End date string (ISO format)
        
    Returns:
        Tuple of (is_valid, validated_start_date, validated_end_date)
    """
    from datetime import datetime
    
    try:
        if start_date:
            start_dt = datetime.fromisoformat(start_date.replace('Z', '+00:00'))
        else:
            start_dt = None
            
        if end_date:
            end_dt = datetime.fromisoformat(end_date.replace('Z', '+00:00'))
        else:
            end_dt = None
        
        if start_dt and end_dt and start_dt > end_dt:
            return False, None, None
        
        return True, start_date, end_date
        
    except ValueError:
        return False, None, None