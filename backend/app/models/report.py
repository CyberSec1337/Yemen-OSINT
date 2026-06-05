"""
Report model for managing generated reports.
"""

from datetime import datetime
from enum import Enum
from app.extensions import db
import json

class ReportFormat(Enum):
    """Report format enumeration."""
    PDF = 'pdf'
    JSON = 'json'
    CSV = 'csv'
    XML = 'xml'
    HTML = 'html'

class ReportStatus(Enum):
    """Report status enumeration."""
    PENDING = 'pending'
    GENERATING = 'generating'
    COMPLETED = 'completed'
    FAILED = 'failed'

class Report(db.Model):
    """Report model for managing generated reports."""
    
    __tablename__ = 'reports'
    
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('users.id'), nullable=False)
    scan_id = db.Column(db.Integer, db.ForeignKey('scans.id'), nullable=False, index=True)
    
    # Report details
    name = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    format = db.Column(db.Enum(ReportFormat), nullable=False)
    template = db.Column(db.String(100), default='standard')  # Report template name
    
    # Status and timing
    status = db.Column(db.Enum(ReportStatus), default=ReportStatus.PENDING, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False, index=True)
    completed_at = db.Column(db.DateTime)
    
    # File information
    file_path = db.Column(db.String(500))
    file_size = db.Column(db.Integer)  # File size in bytes
    file_hash = db.Column(db.String(64))  # SHA-256 hash of file
    
    # Report configuration
    include_sections = db.Column(db.Text)  # JSON array of sections to include
    filters = db.Column(db.Text)  # JSON object with filters applied
    sorting = db.Column(db.Text)  # JSON object with sorting preferences
    
    # Statistics
    total_results = db.Column(db.Integer, default=0)
    high_severity_count = db.Column(db.Integer, default=0)
    medium_severity_count = db.Column(db.Integer, default=0)
    low_severity_count = db.Column(db.Integer, default=0)
    
    # Error handling
    error_message = db.Column(db.Text)
    generation_log = db.Column(db.Text)  # Log of generation process
    
    def __init__(self, user_id, scan_id, name, format, description=None, template='standard'):
        """Initialize report."""
        self.user_id = user_id
        self.scan_id = scan_id
        self.name = name
        self.format = format
        self.description = description
        self.template = template
    
    def get_include_sections(self):
        """Get include sections as list."""
        try:
            return json.loads(self.include_sections) if self.include_sections else []
        except (json.JSONDecodeError, TypeError):
            return []
    
    def set_include_sections(self, sections_list):
        """Set include sections from list."""
        self.include_sections = json.dumps(sections_list) if sections_list else None
    
    def get_filters(self):
        """Get filters as dictionary."""
        try:
            return json.loads(self.filters) if self.filters else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_filters(self, filters_dict):
        """Set filters from dictionary."""
        self.filters = json.dumps(filters_dict) if filters_dict else None
    
    def get_sorting(self):
        """Get sorting as dictionary."""
        try:
            return json.loads(self.sorting) if self.sorting else {}
        except (json.JSONDecodeError, TypeError):
            return {}
    
    def set_sorting(self, sorting_dict):
        """Set sorting from dictionary."""
        self.sorting = json.dumps(sorting_dict) if sorting_dict else None
    
    def start_generation(self):
        """Mark report generation as started."""
        self.status = ReportStatus.GENERATING
        db.session.commit()
    
    def complete_generation(self, file_path, file_size=None):
        """Mark report generation as completed."""
        self.status = ReportStatus.COMPLETED
        self.completed_at = datetime.utcnow()
        self.file_path = file_path
        if file_size:
            self.file_size = file_size
        db.session.commit()
    
    def fail_generation(self, error_message):
        """Mark report generation as failed."""
        self.status = ReportStatus.FAILED
        self.completed_at = datetime.utcnow()
        self.error_message = error_message
        db.session.commit()
    
    def add_log_entry(self, log_message):
        """Add entry to generation log."""
        if self.generation_log:
            self.generation_log += f"\n[{datetime.utcnow().isoformat()}] {log_message}"
        else:
            self.generation_log = f"[{datetime.utcnow().isoformat()}] {log_message}"
        db.session.commit()
    
    def calculate_statistics(self):
        """Calculate report statistics from scan results."""
        from .result import Result, Severity
        
        results = Result.query.filter_by(scan_id=self.scan_id).all()
        
        self.total_results = len(results)
        self.high_severity_count = len([r for r in results if r.severity == Severity.HIGH])
        self.medium_severity_count = len([r for r in results if r.severity == Severity.MEDIUM])
        self.low_severity_count = len([r for r in results if r.severity == Severity.LOW])
        
        db.session.commit()
    
    def get_file_extension(self):
        """Get file extension based on format."""
        extensions = {
            ReportFormat.PDF: '.pdf',
            ReportFormat.JSON: '.json',
            ReportFormat.CSV: '.csv',
            ReportFormat.XML: '.xml',
            ReportFormat.HTML: '.html'
        }
        return extensions.get(self.format, '.txt')
    
    def get_mime_type(self):
        """Get MIME type based on format."""
        mime_types = {
            ReportFormat.PDF: 'application/pdf',
            ReportFormat.JSON: 'application/json',
            ReportFormat.CSV: 'text/csv',
            ReportFormat.XML: 'application/xml',
            ReportFormat.HTML: 'text/html'
        }
        return mime_types.get(self.format, 'text/plain')
    
    def to_dict(self, include_file_info=False):
        """Convert report to dictionary."""
        data = {
            'id': self.id,
            'user_id': self.user_id,
            'scan_id': self.scan_id,
            'name': self.name,
            'description': self.description,
            'format': self.format.value if self.format else None,
            'template': self.template,
            'status': self.status.value if self.status else None,
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'completed_at': self.completed_at.isoformat() if self.completed_at else None,
            'include_sections': self.get_include_sections(),
            'filters': self.get_filters(),
            'sorting': self.get_sorting(),
            'total_results': self.total_results,
            'high_severity_count': self.high_severity_count,
            'medium_severity_count': self.medium_severity_count,
            'low_severity_count': self.low_severity_count,
            'error_message': self.error_message,
            'file_extension': self.get_file_extension(),
            'mime_type': self.get_mime_type()
        }
        
        if include_file_info:
            data['file_path'] = self.file_path
            data['file_size'] = self.file_size
            data['file_hash'] = self.file_hash
            data['generation_log'] = self.generation_log
        
        return data
    
    @staticmethod
    def get_user_reports(user_id, format=None, status=None, limit=None, offset=None):
        """Get reports for a user with optional filtering."""
        query = Report.query.filter_by(user_id=user_id)
        
        if format:
            query = query.filter_by(format=format)
        
        if status:
            query = query.filter_by(status=status)
        
        query = query.order_by(Report.created_at.desc())
        
        if limit:
            query = query.limit(limit)
        if offset:
            query = query.offset(offset)
        
        return query.all()
    
    @staticmethod
    def get_scan_reports(scan_id):
        """Get all reports for a specific scan."""
        return Report.query.filter_by(scan_id=scan_id).order_by(Report.created_at.desc()).all()
    
    def __repr__(self):
        """String representation."""
        return f'<Report {self.name} ({self.format.value if self.format else "unknown"})>'