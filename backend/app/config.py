"""
Configuration classes for the OSINT Platform.
Manages environment variables and app settings.
"""

import os
from datetime import timedelta
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()


class Config:
    """Base configuration class."""
    
    # Basic Flask config
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'dev-secret-key-change-in-production'
    JWT_SECRET_KEY = os.environ.get('JWT_SECRET_KEY') or 'jwt-secret-key-change-in-production'
    
    # Database
    SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///osint_platform.db'
    SQLALCHEMY_TRACK_MODIFICATIONS = False
    
    # JWT Configuration
    JWT_ACCESS_TOKEN_EXPIRES = timedelta(seconds=int(os.environ.get('JWT_ACCESS_TOKEN_EXPIRES', 3600)))
    JWT_REFRESH_TOKEN_EXPIRES = timedelta(seconds=int(os.environ.get('JWT_REFRESH_TOKEN_EXPIRES', 2592000)))
    
    # Rate Limiting
    RATELIMIT_STORAGE_URL = os.environ.get('RATELIMIT_STORAGE_URL') or 'memory://'
    RATELIMIT_DEFAULT = "100 per hour"
    
    # Security
    BCRYPT_LOG_ROUNDS = int(os.environ.get('BCRYPT_LOG_ROUNDS', 12))
    
    # File Upload
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max file size
    UPLOAD_FOLDER = 'uploads'
    
    # Reports
    REPORTS_DIR = os.environ.get('REPORTS_DIR') or 'reports/'
    MAX_REPORT_SIZE = os.environ.get('MAX_REPORT_SIZE', '50MB')
    
    # Logging
    LOG_LEVEL = os.environ.get('LOG_LEVEL', 'INFO')
    LOG_FILE = os.environ.get('LOG_FILE', 'logs/osint_platform.log')
    
    # API Keys (stored as environment variables)
    API_KEYS = {
        'shodan': os.environ.get('SHODAN_API_KEY'),
        'virustotal': os.environ.get('VIRUSTOTAL_API_KEY'),
        'abuseipdb': os.environ.get('ABUSEIPDB_API_KEY'),
        'alienvault': os.environ.get('ALIENVAULT_API_KEY'),
        'securitytrails': os.environ.get('SECURITYTRAILS_API_KEY'),
    }
    
    # API Rate Limits (requests per minute)
    API_RATE_LIMITS = {
        'shodan': 60,
        'virustotal': 4,
        'abuseipdb': 1000,
        'alienvault': 30,
        'securitytrails': 50,
    }
    
    # Scan Configuration
    MAX_CONCURRENT_SCANS = 5
    SCAN_TIMEOUT = 300  # 5 minutes
    BULK_SCAN_LIMIT = 100
    
    # Cache Configuration
    CACHE_TYPE = 'simple'
    CACHE_DEFAULT_TIMEOUT = 300
    
    @staticmethod
    def init_app(app):
        """Initialize app with configuration."""
        # Create necessary directories
        os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
        os.makedirs(app.config['REPORTS_DIR'], exist_ok=True)
        os.makedirs('logs', exist_ok=True)


class DevelopmentConfig(Config):
    """Development configuration."""
    DEBUG = True
    SQLALCHEMY_ECHO = True  # Print SQL statements for debugging


class ProductionConfig(Config):
    """Production configuration."""
    DEBUG = False
    SQLALCHEMY_ECHO = False
    
    # Production security settings
    SESSION_COOKIE_SECURE = True
    SESSION_COOKIE_HTTPONLY = True
    SESSION_COOKIE_SAMESITE = 'Lax'


class TestingConfig(Config):
    """Testing configuration."""
    TESTING = True
    SQLALCHEMY_DATABASE_URI = 'sqlite:///:memory:'
    WTF_CSRF_ENABLED = False


# Configuration dictionary
config = {
    'development': DevelopmentConfig,
    'production': ProductionConfig,
    'testing': TestingConfig,
    'default': DevelopmentConfig
}