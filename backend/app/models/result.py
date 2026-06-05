"""
Result model for storing OSINT scan results.
"""

from datetime import datetime
from enum import Enum
from app.extensions import db
import json

class Severity(Enum):
    """Severity levels for results."""
    LOW = 'low'
    MEDIUM = 'medium'
    HIGH = 'high'
    CRITICAL = 'critical'
    INFO = 'info'

class ResultStatus(Enum):
    """Result status enumeration."""
    SUCCESS = 'success'
    ERROR = 'error'
    TIMEOUT = 'timeout'
    RATE_LIMITED = 'rate_limited'
    NO_DATA = 'no_data'

class Result(db.Model):
    """Result model for storing individual API results."""
    
    __tablename__ = 'results'
    
    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    
    # Source information
    source = db.Column(db.String(50), nullable=False, index=True)  # API name
    target = db.Column(db.Text, nullable=False)  # The specific target for this result
    
    # Result metadata
    status = db.Column(db.Enum(ResultStatus), default=ResultStatus.SUCCESS, nullable=False)
    severity = db.Column(db.Enum(Severity), default=Severity.INFO, nullable=False, index=True)
    confidence = db.Column(db.Integer, default=50)  # Confidence score 0-100
    
    # Timing
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    response_time = db.Column(db.Integer)  # Response time in milliseconds
    
    # Data storage
    summary = db.Column(db.Text)  # Brief summary of findings
    details = db.Column(db.Text)  # JSON object with detailed findings
    indicators = db.Column(db.Text)  # JSON array of indicators
    metadata = db.Column(db.Text)  # JSON object with additional metadata
    raw_response = db.Column(db.Text)  # Raw API response (for debugging)
    
    # Error information
    error_message = db.Column(db.Text)
    error_code = db.Column(db.String(50))
    
    # Processing information
    processed = db.Column(db.Boolean, default=False, nullable=False)
    correlated = db.Column(db.Boolean, default=False, nullable=False)
    
    # Relationships
    correlations = db.relationship(
        'Result',
        secondary='result_correlations',
        primaryjoin='(Result.id == result_correlations.c.result_id)',
        secondaryjoin='(Result.id == result_correlations.c.correlated_result_id)',
        backref='correlated_results'
    )
    
    def __init__(self, scan_id, source, target, status=ResultStatus.SUCCESS, severity=Severity.INFO):
        """Initialize result."""
        self.scan_id = scan_id
        self.source = source.lower()
        self.target = target
        self.status = status
        self.severity = severity
    
    def get_details(self):
        """Get details as dictionary."""
        try:
            return json.loads(self.details) if self.details else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_details(self, details_dict):
        """Set details from dictionary."""
        self.details = json.dumps(details_dict) if details_dict else None
    
    def get_indicators(self):
        """Get indicators as list."""
        try:
            return json.loads(self.indicators) if self.indicators else []
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_indicators(self, indicators_list):
        """Set indicators from list."""
        self.indicators = json.dumps(indicators_list) if indicators_list else None
    
    def get_metadata(self):
        """Get metadata as dictionary."""
        try:
            return json.loads(self.metadata) if self.metadata else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_metadata(self, metadata_dict):
        """Set metadata from dictionary."""
        self.metadata = json.dumps(metadata_dict) if metadata_dict else None
    
    def add_indicator(self, indicator_type, value, severity=None):
        """Add an indicator to the result."""
        indicators = self.get_indicators()
        indicators.append({
            'type': indicator_type,
            'value': value,
            'severity': severity or self.severity.value,
            'timestamp': datetime.utcnow().isoformat()
        })
        self.set_indicators(indicators)
    
    def set_error(self, error_message, error_code=None):
        """Set error information."""
        self.status = ResultStatus.ERROR
        self.error_message = error_message
        self.error_code = error_code
    
    def set_timeout(self):
        """Set as timeout."""
        self.status = ResultStatus.TIMEOUT
        self.error_message = "Request timed out"
    
    def set_rate_limited(self):
        """Set as rate limited."""
        self.status = ResultStatus.RATE_LIMITED
        self.error_message = "API rate limit exceeded"
    
    def calculate_severity_score(self):
        """Calculate numeric severity score."""
        severity_scores = {
            Severity.INFO: 1,
            Severity.LOW: 2,
            Severity.MEDIUM: 3,
            Severity.HIGH: 4,
            Severity.CRITICAL: 5
        }
        return severity_scores.get(self.severity, 1)
    
    def normalize_response(self, api_response):
        """Normalize API response to standard format."""
        # This would be implemented by each API service
        # For now, store the raw response
        self.raw_response = json.dumps(api_response) if api_response else None
    
    def to_dict(self, include_raw=False):
        """Convert result to dictionary."""
        data = {
            'id': self.id,
            'scan_id': self.scan_id,
            'source': self.source,
            'target': self.target,
            'status': self.status.value if self.status else None,
            'severity': self.severity.value if self.severity else None,
            'confidence': self.confidence,
            'timestamp': self.timestamp.isoformat() if self.timestamp else None,
            'response_time': self.response_time,
            'summary': self.summary,
            'details': self.get_details(),
            'indicators': self.get_indicators(),
            'metadata': self.get_metadata(),
            'processed': self.processed,
            'correlated': self.correlated,
            'error_message': self.error_message,
            'error_code': self.error_code,
            'severity_score': self.calculate_severity_score()
        }
        
        if include_raw:
            data['raw_response'] = self.raw_response
        
        return data
    
    @staticmethod
    def get_scan_results(scan_id, severity=None, source=None, limit=None, offset=None):
        """Get results for a scan with optional filtering."""
        query = Result.query.filter_by(scan_id=scan_id)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        if source:
            query = query.filter_by(source=source.lower())
        
        query = query.order_by(Result.timestamp.desc())
        
        if limit:
            query = query.limit(limit)
        if offset:
            query = query.offset(offset)
        
        return query.all()
    
    @staticmethod
    def get_user_results(user_id, severity=None, source=None, limit=None, offset=None):
        """Get results for all user scans with filtering."""
        from .scan import Scan
        
        query = Result.query.join(Scan).filter(Scan.user_id == user_id)
        
        if severity:
            query = query.filter_by(severity=severity)
        
        if source:
            query = query.filter_by(source=source.lower())
        
        query = query.order_by(Result.timestamp.desc())
        
        if limit:
            query = query.limit(limit)
        if offset:
            query = query.offset(offset)
        
        return query.all()
    
    @staticmethod
    def get_results_by_target(target, limit=None):
        """Get results for a specific target across all scans."""
        query = Result.query.filter_by(target=target).order_by(Result.timestamp.desc())
        
        if limit:
            query = query.limit(limit)
        
        return query.all()
    
    def __repr__(self):
        """String representation."""
        return f'<Result {self.source} for {self.target} ({self.severity.value if self.severity else "unknown"})>'


# Association table for result correlations
result_correlations = db.Table(
    'result_correlations',
    db.Column('result_id', db.Integer, db.ForeignKey('results.id'), primary_key=True),
    db.Column('correlated_result_id', db.Integer, db.ForeignKey('results.id'), primary_key=True),
    db.Column('correlation_type', db.String(50), nullable=False),
    db.Column('confidence', db.Integer, default=50),
    db.Column('created_at', db.DateTime, default=datetime.utcnow)
)