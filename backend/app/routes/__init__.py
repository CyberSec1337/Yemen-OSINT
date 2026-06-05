"""
Routes package for the OSINT Platform.
Contains all API route blueprints.
"""

from .auth import auth_bp
from .scan import scan_bp
from .results import results_bp
from .reports import reports_bp
from .settings import settings_bp

__all__ = ['auth_bp', 'scan_bp', 'results_bp', 'reports_bp', 'settings_bp']