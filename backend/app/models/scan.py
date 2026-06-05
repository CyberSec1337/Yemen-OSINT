"""
Scan model for managing OSINT scans.
"""

from datetime import datetime
from enum import Enum
from app.extensions import db
import json

class ScanStatus(Enum):
    """Scan status enumeration."""
    PENDING = 'pending'
    RUNNING = 'running'
    COMPLETED = 'completed'
    FAILED = 'failed'
    CANCELLED = 'cancelled'
    PAUSED = 'paused'

class ScanType(Enum):
    """Scan type enumeration."""
    SINGLE = 'single'
    BULK = 'bulk'
    SCHEDULED = 'scheduled'

class TargetType(Enum):
    """Target type enumeration."""
    IP = 'ip'
    DOMAIN = 'domain'
    URL = 'url'
    EMAIL = 'email'
    USERNAME = 'username'
    BITCOIN = 'bitcoin'
    HASH = 'hash'
    COMPANY = 'company'

class Scan(db.Model):
    """Scan model for managing OSINT scans."""
    
    __tablename__ = 'scans'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    
    # Scan details
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    target = db.Column(db.Text, nullable=False)  # JSON array of targets
    target_type = db.Column(db.Enum(TargetType), nullable=False)
    scan_type = db.Column(db.Enum(ScanType), default=ScanType.SINGLE, nullable=False)
    
    # Configuration
    selected_apis = db.Column(db.Text, nullable=False)  # JSON array of API names
    scan_options = db.Column(db.Text)  # JSON object with scan options
    
    # Status and timing
    status = db.Column(db.Enum(ScanStatus), default=ScanStatus.PENDING, nullable=False, index=True)
    progress = db.Column(db.Integer, default=0, nullable=False)  # Progress percentage
    current_step = db.Column(db.String(200))  # Current step description
    
    # Timestamps
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    started_at = db.Column(db.DateTime)
    completed_at = db.Column(db.DateTime)
    estimated_duration = db.Column(db.Integer)  # Estimated duration in seconds
    
    # Results summary
    total_apis = db.Column(db.Integer, default=0)
    completed_apis = db.Column(db.Integer, default=0)
    total_results = db.Column(db.Integer, default=0)
    high_severity_count = db.Column(db.Integer, default=0)
    medium_severity_count = db.Column(db.Integer, default=0)
    low_severity_count = db.Column(db.Integer, default=0)
    
    # Error handling
    error_message = db.Column(db.Text)
    retry_count = db.Column(db.Integer, default=0)
    max_retries = db.Column(db.Integer, default=3)
    
    # Relationships
    results = db.relationship('Result', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    reports = db.relationship('Report', backref='scan', lazy='dynamic', cascade='all, delete-orphan')
    
    def __init__(self, user_id, name, target, target_type, selected_apis, scan_type=ScanType.SINGLE, description=None):
        """Initialize scan."""
        self.user_id = user_id
        self.name = name
        self.target = json.dumps(target) if isinstance(target, list) else target
        self.target_type = target_type
        self.selected_apis = json.dumps(selected_apis) if isinstance(selected_apis, list) else selected_apis
        self.scan_type = scan_type
        self.description = description
        self.total_apis = len(selected_apis) if isinstance(selected_apis, list) else 0
    
    def get_targets(self):
        """Get targets as list."""
        try:
            return json.loads(self.target)
        except (json.JSONDecodeError, TypeError):
            return [self.target] if self.target else []
    
    def get_selected_apis(self):
        """Get selected APIs as list."""
        try:
            return json.loads(self.selected_apis)
        except (json.JSONDecodeError, TypeError):
            return []
    
    def get_scan_options(self):
        """Get scan options as dictionary."""
        try:
            return json.loads(self.scan_options) if self.scan_options else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def update_scan_options(self, options):
        """Update scan options."""
        self.scan_options = json.dumps(options) if isinstance(options, dict) else options
    
    def start_scan(self):
        """Mark scan as started."""
        self.status = ScanStatus.RUNNING
        self.started_at = datetime.utcnow()
        self.progress = 0
        db.session.commit()
    
    def complete_scan(self):
        """Mark scan as completed."""
        self.status = ScanStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.progress = 100
        self.current_step = "Completed"
        db.session.commit()
    
    def fail_scan(self, error_message):
        """Mark scan as failed."""
        self.status = ScanStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error_message = error_message
        db.session.commit()
    
    def cancel_scan(self):
        """Mark scan as cancelled."""
        self.status = ScanStatus.CANCELLED
        self.completed_at = datetime.utcnow()
        self.current_step = "Cancelled"
        db.session.commit()
    
    def pause_scan(self):
        """Mark scan as paused."""
        self.status = ScanStatus.PAUSED
        db.session.commit()
    
    def resume_scan(self):
        """Resume paused scan."""
        self.status = ScanStatus.RUNNING
        db.session.commit()
    
    def update_progress(self, completed_apis, current_step=None):
        """Update scan progress."""
        self.completed_apis = completed_apis
        if self.total_apis > 0:
            self.progress = int((completed_apis / self.total_apis) * 100)
        if current_step:
            self.current_step = current_step
        db.session.commit()
    
    def increment_retry(self):
        """Increment retry count."""
        self.retry_count += 1
        db.session.commit()
    
    def get_duration(self):
        """Get scan duration in seconds."""
        if self.started_at and self.completed_at:
            return int((self.completed_at - self.started_at).total_seconds())
        elif self.started_at:
            return int((datetime.utcnow() - self.started_at).total_seconds())
        return 0
    
    def get_results_summary(self):
        """Get results summary."""
        return {
            'total_results': self.total_results,
            'high_severity': self.high_severity_count,
            'medium_severity': self.medium_severity_count,
            'low_severity': self.low_severity_count,
            'completed_apis': self.completed_apis,
            'total_apis': self.total_apis
        }
    
    def to_dict(self, include_results=False):
        """Convert scan to dictionary."""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'name': self.name,
            'description': self.description,
            'target': self.get_targets(),
            'target_type': self.target_type.value if self.target_type else None,
            'scan_type': self.scan_type.value if self.scan_type else None,
            'selected_apis': self.get_selected_apis(),
            'scan_options': self.get_scan_options(),
            'status': self.status.value if self.status else None,
            'progress': self.progress,
            'current_step': self.current_step,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'started_at': self.started_at.isoformat() if self.started_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'duration': self.get_duration(),
            'estimated_duration': self.estimated_duration,
            'results_summary': self.get_results_summary(),
            'error_message': self.error_message,
            'retry_count': self.retry_count,
            'max_retries': self.max_retries
        }
        
        if include_results:
            data['results'] = [result.to_dict() for result in self.results]
        
        return data
    
    @staticmethod
    def get_user_scans(user_id, status=None, limit=None, offset=None):
        """Get scans for a user with optional filtering."""
        query = Scan.query.filter_by(user_id=user_id)
        
        if status:
            query = query.filter_by(status=status)
        
        query = query.order_by(Scan.created_at.desc())
        
        if limit:
            query = query.limit(limit)
        if offset:
            query = query.offset(offset)
        
        return query.all()
    
    @staticmethod
    def get_running_scans():
        """Get all currently running scans."""
        return Scan.query.filter_by(status=ScanStatus.RUNNING).all()
    
    def __repr__(self):
        """String representation."""
        return f'<Scan {self.name} ({self.status.value if self.status else "unknown"})>'