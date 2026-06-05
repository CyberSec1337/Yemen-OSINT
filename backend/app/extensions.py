"""
Flask extensions initialization.
Centralizes all extension imports and initialization.
"""

from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from flask_jwt_extended import JWTManager
from flask_cors import CORS
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from cryptography.fernet import Fernet
import logging
from logging.handlers import RotatingFileHandler
import os

# Initialize extensions
db = SQLAlchemy()
migrate = Migrate()
jwt = JWTManager()
cors = CORS()
limiter = Limiter(
    key_func=get_remote_address,
    default_limits=["200 per day", "50 per hour"]
)

# Encryption key for sensitive data
encryption_key = None
cipher_suite = None


def init_extensions(app):
    """Initialize all Flask extensions with the app."""
    
    # Database
    db.init_app(app)
    migrate.init_app(app, db)
    
    # JWT
    jwt.init_app(app)
    
    # CORS
    cors.init_app(app, resources={
        r"/api/*": {
            "origins": ["http://localhost:3000", "http://localhost:5173"],
            "methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
            "allow_headers": ["Content-Type", "Authorization"]
        }
    })
    
    # Rate Limiting
    limiter.init_app(app)
    
    # Encryption
    global encryption_key, cipher_suite
    encryption_key = app.config.get('ENCRYPTION_KEY')
    if not encryption_key:
        # Generate a new key for development
        encryption_key = Fernet.generate_key()
        app.config['ENCRYPTION_KEY'] = encryption_key
    
    cipher_suite = Fernet(encryption_key)
    
    # Logging
    setup_logging(app)


def setup_logging(app):
    """Configure application logging."""
    
    if not app.debug and not app.testing:
        # Create logs directory if it doesn't exist
        if not os.path.exists('logs'):
            os.mkdir('logs')
        
        # Configure rotating file handler
        file_handler = RotatingFileHandler(
            app.config['LOG_FILE'],
            maxBytes=10240000,  # 10MB
            backupCount=10
        )
        file_handler.setFormatter(logging.Formatter(
            '%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]'
        ))
        file_handler.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        
        app.logger.addHandler(file_handler)
        app.logger.setLevel(getattr(logging, app.config['LOG_LEVEL']))
        app.logger.info('OSINT Platform startup')


def get_cipher_suite():
    """Get the encryption cipher suite."""
    return cipher_suite


def encrypt_data(data: str) -> str:
    """Encrypt sensitive data."""
    if cipher_suite and data:
        return cipher_suite.encrypt(data.encode()).decode()
    return data


def decrypt_data(encrypted_data: str) -> str:
    """Decrypt sensitive data."""
    if cipher_suite and encrypted_data:
        try:
            return cipher_suite.decrypt(encrypted_data.encode()).decode()
        except Exception:
            return encrypted_data
    return encrypted_data