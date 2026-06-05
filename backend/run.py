"""
Application entry point for the OSINT Platform.
"""

import os
from app import create_app
from app.config import config

# Determine configuration environment
env = os.environ.get('FLASK_ENV', 'development')

# Create Flask application
app = create_app(config_name=env)

if __name__ == '__main__':
    # Development server configuration
    debug_mode = env == 'development'
    
    print(f"Starting OSINT Platform in {env} mode...")
    print(f"Debug mode: {debug_mode}")
    print(f"Database: {app.config['SQLALCHEMY_DATABASE_URI']}")
    
    # Run development server
    app.run(
        host='0.0.0.0',
        port=5000,
        debug=debug_mode,
        use_reloader=debug_mode
    )