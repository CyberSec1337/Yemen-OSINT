"""
Cryptographic utilities for the OSINT Platform.
"""

import secrets
import hashlib
import string
from datetime import datetime, timedelta
from cryptography.fernet import Fernet
from app.extensions import get_cipher_suite


def generate_token(length=32):
    """
    Generate a secure random token.
    
    Args:
        length: Length of the token
        
    Returns:
        Random token string
    """
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def generate_api_key():
    """
    Generate a secure API key.
    
    Returns:
        API key string
    """
    return generate_token(64)


def generate_scan_id():
    """
    Generate a unique scan identifier.
    
    Returns:
        Scan ID string
    """
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    random_part = generate_token(8)
    return f"scan_{timestamp}_{random_part}"


def generate_report_id():
    """
    Generate a unique report identifier.
    
    Returns:
        Report ID string
    """
    timestamp = datetime.utcnow().strftime('%Y%m%d%H%M%S')
    random_part = generate_token(8)
    return f"report_{timestamp}_{random_part}"


def hash_string(data: str, salt: str = None) -> str:
    """
    Hash a string using SHA-256.
    
    Args:
        data: String to hash
        salt: Optional salt
        
    Returns:
        Hashed string
    """
    if salt:
        data = f"{data}{salt}"
    
    return hashlib.sha256(data.encode()).hexdigest()


def verify_hash(data: str, hashed: str, salt: str = None) -> bool:
    """
    Verify a string against its hash.
    
    Args:
        data: Original string
        hashed: Hashed string
        salt: Salt used for hashing
        
    Returns:
        True if matches, False otherwise
    """
    return hash_string(data, salt) == hashed


def encrypt_sensitive_data(data: str) -> str:
    """
    Encrypt sensitive data.
    
    Args:
        data: Data to encrypt
        
    Returns:
        Encrypted data
    """
    cipher_suite = get_cipher_suite()
    if cipher_suite and data:
        return cipher_suite.encrypt(data.encode()).decode()
    return data


def decrypt_sensitive_data(encrypted_data: str) -> str:
    """
    Decrypt sensitive data.
    
    Args:
        encrypted_data: Encrypted data
        
    Returns:
        Decrypted data
    """
    cipher_suite = get_cipher_suite()
    if cipher_suite and encrypted_data:
        try:
            return cipher_suite.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return encrypted_data
    return encrypted_data


def generate_file_hash(file_content: bytes) -> str:
    """
    Generate SHA-256 hash of file content.
    
    Args:
        file_content: File content as bytes
        
    Returns:
        SHA-256 hash
    """
    return hashlib.sha256(file_content).hexdigest()


def generate_session_token(user_id: int, expires_in: int = 3600) -> dict:
    """
    Generate session token information.
    
    Args:
        user_id: User ID
        expires_in: Expiration time in seconds
        
    Returns:
        Dictionary with token info
    """
    now = datetime.utcnow()
    expires_at = now + timedelta(seconds=expires_in)
    
    return {
        'user_id': user_id,
        'token': generate_token(32),
        'issued_at': now.isoformat(),
        'expires_at': expires_at.isoformat(),
        'expires_in': expires_in
    }


def validate_token_format(token: str) -> bool:
    """
    Validate token format.
    
    Args:
        token: Token to validate
        
    Returns:
        True if valid format, False otherwise
    """
    if not token or not isinstance(token, str):
        return False
    
    # Check if token contains only valid characters
    valid_chars = string.ascii_letters + string.digits + '-_'
    return all(c in valid_chars for c in token) and 16 <= len(token) <= 128


def generate_nonce(length=16):
    """
    Generate a cryptographic nonce.
    
    Args:
        length: Length of the nonce
        
    Returns:
        Nonce string
    """
    return secrets.token_urlsafe(length)


def derive_key(password: str, salt: str = None, iterations: int = 100000) -> str:
    """
    Derive a key from password using PBKDF2.
    
    Args:
        password: Password
        salt: Salt (generated if not provided)
        iterations: Number of iterations
        
    Returns:
        Tuple of (derived_key, salt)
    """
    import hashlib
    
    if salt is None:
        salt = secrets.token_hex(16)
    
    key = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode(),
        salt.encode(),
        iterations
    )
    
    return key.hex(), salt


def generate_csp_nonce():
    """
    Generate a nonce for Content Security Policy.
    
    Returns:
        Base64 encoded nonce
    """
    return secrets.token_urlsafe(16)


def create_secure_filename(filename: str) -> str:
    """
    Create a secure filename.
    
    Args:
        filename: Original filename
        
    Returns:
        Secure filename
    """
    import os
    
    # Get file extension
    name, ext = os.path.splitext(filename)
    
    # Generate random name
    random_name = generate_token(16)
    
    # Sanitize extension
    ext = ext.lower().replace(' ', '_').replace('.', '', 1)
    
    return f"{random_name}.{ext}" if ext else random_name


def generate_webhook_secret() -> str:
    """
    Generate a secret for webhook validation.
    
    Returns:
        Webhook secret
    """
    return generate_token(64)


def verify_webhook_signature(payload: str, signature: str, secret: str) -> bool:
    """
    Verify webhook signature.
    
    Args:
        payload: Request payload
        signature: Received signature
        secret: Webhook secret
        
    Returns:
        True if valid, False otherwise
    """
    import hmac
    
    expected_signature = hmac.new(
        secret.encode(),
        payload.encode(),
        hashlib.sha256
    ).hexdigest()
    
    return hmac.compare_digest(expected_signature, signature)