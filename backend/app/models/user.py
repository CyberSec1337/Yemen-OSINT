"""
User model for authentication and user management.
"""

from datetime import datetime
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from app.extensions import db

class User(db.Model):
    """User model for authentication."""
    
    __tablename__ = 'users'
    
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, default=False, nullable=False)
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    last_login = db.Column(db.DateTime)
    login_count = db.Column(db.Integer, default=0, nullable=False)
    
    # Relationships
    api_keys = db.relationship('APIKey', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    scans = db.relationship('Scan', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='user', lazy='dynamic', cascade='all, delete-orphan')
    
    def __init__(self, username, email=None, is_admin=False):
        """Initialize user."""
        self.username = username
        self.email = email
        self.is_admin = is_admin
    
    def set_password(self, password):
        """Set password hash."""
        self.password_hash = generate_password_hash(password)
    
    def check_password(self, password):
        """Check password against hash."""
        return check_password_hash(self.password_hash, password)
    
    def update_last_login(self):
        """Update last login timestamp and count."""
        self.last_login = datetime.utcnow()
        self.login_count += 1
        db.session.commit()
    
    def to_dict(self, include_sensitive=False):
        """Convert user to dictionary."""
        data = {
            'id': self.id,
            'username': self.username,
            'email': self.email,
            'is_admin': self.is_admin,
            'is_active': self.is_active,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'last_login': self.last_login.isoformat() if self.last_login else None,
            'login_count': self.login_count
        }
        
        if include_sensitive:
            data['api_keys_count'] = self.api_keys.count()
            data['scans_count'] = self.scans.count()
            data['reports_count'] = self.reports.count()
        
        return data
    
    @staticmethod
    def find_by_username(username):
        """Find user by username."""
        return User.query.filter_by(username=username).first()
    
    @staticmethod
    def find_by_email(email):
        """Find user by email."""
        return User.query.filter_by(email=email).first()
    
    @staticmethod
    def find_by_username_or_email(username_or_email):
        """Find user by username or email."""
        return User.query.filter(
            (User.username == username_or_email) | (User.email == username_or_email)
        ).first()
    
    def __repr__(self):
        """String representation."""
        return f'<User {self.username}>'