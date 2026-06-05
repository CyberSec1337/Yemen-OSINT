"""
Custom decorators for the OSINT Platform.
"""

import functools
import json
from datetime import datetime
from flask import request, jsonify, current_app
from flask_jwt_extended import verify_jwt_in_request, get_jwt_identity, get_jwt
from app.extensions import limiter
from app.models.user import User


def require_auth(f):
    """
    Decorator to require JWT authentication.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            
            # Verify user exists and is active
            user = User.query.get(current_user_id)
            if not user or not user.is_active:
                return jsonify({'error': 'User not found or inactive'}), 401
            
            # Add user to request context
            request.current_user = user
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({'error': 'Authentication required', 'message': str(e)}), 401
    
    return decorated_function


def require_admin(f):
    """
    Decorator to require admin privileges.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            verify_jwt_in_request()
            current_user_id = get_jwt_identity()
            
            user = User.query.get(current_user_id)
            if not user or not user.is_admin:
                return jsonify({'error': 'Admin privileges required'}), 403
            
            request.current_user = user
            return f(*args, **kwargs)
            
        except Exception as e:
            return jsonify({'error': 'Authentication required', 'message': str(e)}), 401
    
    return decorated_function


def rate_limit(limit: str, scope_func=None):
    """
    Custom rate limiting decorator.
    
    Args:
        limit: Rate limit string (e.g., "10 per minute")
        scope_func: Function to generate scope for rate limiting
    """
    def decorator(f):
        return limiter.limit(limit, key_func=scope_func)(f)
    return decorator


def handle_errors(f):
    """
    Decorator for standardized error handling.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        try:
            return f(*args, **kwargs)
        except ValueError as e:
            return jsonify({'error': 'Validation error', 'message': str(e)}), 400
        except KeyError as e:
            return jsonify({'error': 'Missing required field', 'message': f'Missing: {str(e)}'}), 400
        except PermissionError as e:
            return jsonify({'error': 'Permission denied', 'message': str(e)}), 403
        except TimeoutError as e:
            return jsonify({'error': 'Request timeout', 'message': str(e)}), 408
        except Exception as e:
            current_app.logger.error(f"Unexpected error in {f.__name__}: {str(e)}")
            return jsonify({'error': 'Internal server error', 'message': 'Something went wrong'}), 500
    
    return decorated_function


def validate_json(required_fields=None, optional_fields=None):
    """
    Decorator to validate JSON request data.
    
    Args:
        required_fields: List of required field names
        optional_fields: List of optional field names
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            if not request.is_json:
                return jsonify({'error': 'Content-Type must be application/json'}), 400
            
            data = request.get_json()
            if not data:
                return jsonify({'error': 'No JSON data provided'}), 400
            
            # Check required fields
            if required_fields:
                missing_fields = [field for field in required_fields if field not in data]
                if missing_fields:
                    return jsonify({
                        'error': 'Missing required fields',
                        'missing_fields': missing_fields
                    }), 400
            
            # Check for unexpected fields
            allowed_fields = (required_fields or []) + (optional_fields or [])
            if allowed_fields:
                unexpected_fields = [field for field in data if field not in allowed_fields]
                if unexpected_fields:
                    return jsonify({
                        'error': 'Unexpected fields',
                        'unexpected_fields': unexpected_fields
                    }), 400
            
            # Add validated data to request context
            request.validated_data = data
            return f(*args, **kwargs)
        
        return decorated_function
    return decorator


def log_api_call(f):
    """
    Decorator to log API calls.
    """
    @functools.wraps(f)
    def decorated_function(*args, **kwargs):
        start_time = datetime.utcnow()
        
        # Get user info if available
        user_id = None
        try:
            user_id = get_jwt_identity()
        except:
            pass
        
        # Log request
        current_app.logger.info(
            f"API Call: {request.method} {request.path} | "
            f"User: {user_id} | "
            f"IP: {request.remote_addr} | "
            f"Data: {json.dumps(request.get_json()) if request.is_json else 'N/A'}"
        )
        
        try:
            response = f(*args, **kwargs)
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            # Log response
            current_app.logger.info(
                f"API Response: {request.method} {request.path} | "
                f"Status: {response[1] if isinstance(response, tuple) else '200'} | "
                f"Duration: {duration:.3f}s"
            )
            
            return response
            
        except Exception as e:
            end_time = datetime.utcnow()
            duration = (end_time - start_time).total_seconds()
            
            # Log error
            current_app.logger.error(
                f"API Error: {request.method} {request.path} | "
                f"Error: {str(e)} | "
                f"Duration: {duration:.3f}s"
            )
            
            raise
    
    return decorated_function


def cache_response(timeout=300):
    """
    Decorator to cache responses (simple implementation).
    
    Args:
        timeout: Cache timeout in seconds
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            # Simple cache key based on URL and user
            cache_key = f"{request.path}_{request.query_string.decode()}"
            user_id = None
            
            try:
                user_id = get_jwt_identity()
                cache_key += f"_{user_id}"
            except:
                pass
            
            # This is a simple in-memory cache implementation
            # In production, use Redis or similar
            if not hasattr(current_app, '_response_cache'):
                current_app._response_cache = {}
            
            cache = current_app._response_cache
            now = datetime.utcnow().timestamp()
            
            # Check cache
            if cache_key in cache:
                cached_data, cached_time = cache[cache_key]
                if now - cached_time < timeout:
                    return cached_data
            
            # Execute function and cache result
            response = f(*args, **kwargs)
            cache[cache_key] = (response, now)
            
            return response
        
        return decorated_function
    return decorator


def validate_api_key_required(service_name):
    """
    Decorator to validate that user has API key for specific service.
    
    Args:
        service_name: Name of the service/API
    """
    def decorator(f):
        @functools.wraps(f)
        def decorated_function(*args, **kwargs):
            try:
                verify_jwt_in_request()
                current_user_id = get_jwt_identity()
                
                from app.models.api_key import APIKey
                api_key = APIKey.find_by_user_and_service(current_user_id, service_name)
                
                if not api_key:
                    return jsonify({
                        'error': 'API key required',
                        'message': f'API key for {service_name} is required to perform this action'
                    }), 400
                
                # Add API key to request context
                request.api_key = api_key
                return f(*args, **kwargs)
                
            except Exception as e:
                return jsonify({'error': 'Authentication required', 'message': str(e)}), 401
        
        return decorated_function
    return decorator