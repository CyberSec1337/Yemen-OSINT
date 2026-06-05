"""
API Key model for storing encrypted API credentials.
"""

from datetime import datetime
from app.extensions import db, encrypt_data, decrypt_data

class APIKey(db.Model):
    """API Key model for storing encrypted API credentials."""
    
    __tablename__ = 'api_keys'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    service_name = db.Column(db.String(50), nullable=False, index=True)
    encrypted_key = db.Column(db.Text, nullable=False)
    key_identifier = db.Column(db.String(100))  # Optional identifier for the key
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_used = db.Column(db.DateTime)
    usage_count = db.Column(db.Integer, default=0, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)
    
    # API specific settings
    rate_limit = db.Column(db.Integer)  # Custom rate limit for this key
    monthly_quota = db.Column(db.Integer)  # Monthly request quota
    
    __table_args__ = (db.UniqueConstraint('user_id', 'service_name', name='unique_user_service'),)
    
    def __init__(self, user_id, service_name, api_key, key_identifier=None):
        """Initialize API key."""
        self.user_id = user_id
        self.service_name = service_name.lower()
        self.encrypted_key = encrypt_data(api_key)
        self.key_identifier = key_identifier
    
    def get_decrypted_key(self):
        """Get decrypted API key."""
        return decrypt_data(self.encrypted_key)
    
    def update_key(self, new_api_key):
        """Update API key with new encrypted value."""
        self.encrypted_key = encrypt_data(new_api_key)
        self.updated_at = datetime.utcnow()
    
    def record_usage(self):
        """Record API key usage."""
        self.last_used = datetime.utcnow()
        self.usage_count += 1
        db.session.commit()
    
    def to_dict(self, include_key=False):
        """Convert API key to dictionary."""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'service_name': self.service_name,
            'key_identifier': self.key_identifier,
            'is_active': self.is_active,
            'last_used': self.last_used.isoformat() if self.last_used else None,
            'usage_count': self.usage_count,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None,
            'rate_limit': self.rate_limit,
            'monthly_quota': self.monthly_quota
        }
        
        if include_key:
            data['api_key'] = self.get_decrypted_key()
        else:
            # Show masked version of the key
            decrypted = self.get_decrypted_key()
            if decrypted and len(decrypted) > 8:
                data['masked_key'] = decrypted[:4] + '*' * (len(decrypted) - 8) + decrypted[-4:]
            else:
                data['masked_key'] = '****'
        
        return data
    
    @staticmethod
    def find_by_user_and_service(user_id, service_name):
        """Find API key by user and service."""
        return APIKey.query.filter_by(
            user_id=user_id, 
            service_name=service_name.lower(),
            is_active=True
        ).first()
    
    @staticmethod
    def get_active_keys_for_user(user_id):
        """Get all active API keys for a user."""
        return APIKey.query.filter_by(
            user_id=user_id,
            is_active=True
        ).all()
    
    @staticmethod
    def get_service_keys_for_user(user_id, service_name):
        """Get all keys for a specific service and user."""
        return APIKey.query.filter_by(
            user_id=user_id,
            service_name=service_name.lower()
        ).all()
    
    def __repr__(self):
        """String representation."""
        return f'<APIKey {self.service_name} for User {self.user_id}>'