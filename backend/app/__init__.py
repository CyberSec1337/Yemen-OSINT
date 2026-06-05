"""
Flask application factory.
Creates and configures the Flask app.
"""

from flask import Flask
from app.config import config
from app.extensions import init_extensions, db


def create_app(config_name='default'):
    """Create and configure Flask application."""
    
    app = Flask(__name__)
    
    # Load configuration
    app.config.from_object(config[config_name])
    
    # Initialize extensions
    init_extensions(app)
    
    # Register blueprints
    register_blueprints(app)
    
    # Register error handlers
    register_error_handlers(app)
    
    # Register CLI commands
    register_cli_commands(app)
    
    return app


def register_blueprints(app):
    """Register all application blueprints."""
    
    from app.routes.auth import auth_bp
    from app.routes.scan import scan_bp
    from app.routes.results import results_bp
    from app.routes.reports import reports_bp
    from app.routes.settings import settings_bp
    
    # Register blueprints with URL prefixes
    app.register_blueprint(auth_bp, url_prefix='/api/auth')
    app.register_blueprint(scan_bp, url_prefix='/api/scans')
    app.register_blueprint(results_bp, url_prefix='/api/results')
    app.register_blueprint(reports_bp, url_prefix='/api/reports')
    app.register_blueprint(settings_bp, url_prefix='/api/settings')


def register_error_handlers(app):
    """Register custom error handlers."""
    
    @app.errorhandler(400)
    def bad_request(error):
        return {'error': 'Bad request', 'message': str(error)}, 400
    
    @app.errorhandler(401)
    def unauthorized(error):
        return {'error': 'Unauthorized', 'message': 'Authentication required'}, 401
    
    @app.errorhandler(403)
    def forbidden(error):
        return {'error': 'Forbidden', 'message': 'Insufficient permissions'}, 403
    
    @app.errorhandler(404)
    def not_found(error):
        return {'error': 'Not found', 'message': 'Resource not found'}, 404
    
    @app.errorhandler(429)
    def ratelimit_handler(e):
        return {'error': 'Rate limit exceeded', 'message': str(e.description)}, 429
    
    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        return {'error': 'Internal server error', 'message': 'Something went wrong'}, 500


def register_cli_commands(app):
    """Register custom CLI commands."""
    
    @app.cli.command()
    def init_db():
        """Initialize the database."""
        db.create_all()
        print('Database initialized.')
    
    @app.cli.command()
    def create_admin():
        """Create an admin user."""
        from app.models.user import User
        import getpass
        
        username = input('Enter admin username: ')
        password = getpass.getpass('Enter admin password: ')
        
        user = User(username=username, is_admin=True)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        print(f'Admin user {username} created successfully.')
    
    @app.cli.command()
    def test_api():
        """Test API connections."""
        from app.services.apis.shodan_api import ShodanAPI
        from app.services.apis.virustotal_api import VirusTotalAPI
        from app.config import config
        
        app.config.from_object(config['default'])
        
        # Test Shodan
        if app.config['API_KEYS']['shodan']:
            shodan = ShodanAPI(app.config['API_KEYS']['shodan'])
            print(f"Shodan API key valid: {shodan.validate_api_key()}")
        
        # Test VirusTotal
        if app.config['API_KEYS']['virustotal']:
            vt = VirusTotalAPI(app.config['API_KEYS']['virustotal'])
            print(f"VirusTotal API key valid: {vt.validate_api_key()}")