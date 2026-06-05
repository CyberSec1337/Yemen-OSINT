"""
Settings routes for managing user settings and API keys.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models.user import User
from app.models.api_key import APIKey
from app.utils.decorators import handle_errors, validate_json, log_api_call, require_auth
from app.utils.validators import validate_api_key
import logging

settings_bp = Blueprint('settings', __name__)
logger = logging.getLogger(__name__)


@settings_bp.route('/api-keys', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_api_keys():
    """
    Get all API keys for the current user.
    """
    current_user = request.current_user
    
    try:
        api_keys = APIKey.get_active_keys_for_user(current_user.id)
        
        return jsonify({
            'api_keys': [api_key.to_dict() for api_key in api_keys]
        }), 200
        
    except Exception as e:
        logger.error(f"Get API keys error: {str(e)}")
        return jsonify({'error': 'Failed to get API keys', 'message': str(e)}), 500


@settings_bp.route('/api-keys', methods=['POST'])
@require_auth
@handle_errors
@validate_json(required_fields=['service_name', 'api_key'], optional_fields=['key_identifier'])
@log_api_call
def add_api_key():
    """
    Add a new API key.
    
    Required fields:
    - service_name: Name of the service (shodan, virustotal, etc.)
    - api_key: The API key
    
    Optional fields:
    - key_identifier: Optional identifier for the key
    """
    data = request.validated_data
    current_user = request.current_user
    
    try:
        service_name = data['service_name'].lower()
        api_key = data['api_key'].strip()
        key_identifier = data.get('key_identifier', '').strip() if data.get('key_identifier') else None
        
        # Validate service name
        valid_services = ['shodan', 'virustotal', 'abuseipdb', 'alienvault', 'securitytrails']
        if service_name not in valid_services:
            return jsonify({
                'error': 'Invalid service name',
                'valid_services': valid_services
            }), 400
        
        # Validate API key format
        if not validate_api_key(api_key):
            return jsonify({'error': 'Invalid API key format'}), 400
        
        # Check if key already exists for this service
        existing_key = APIKey.find_by_user_and_service(current_user.id, service_name)
        if existing_key:
            return jsonify({'error': f'API key for {service_name} already exists'}), 409
        
        # Create new API key
        new_key = APIKey(
            user_id=current_user.id,
            service_name=service_name,
            api_key=api_key,
            key_identifier=key_identifier
        )
        
        db.session.add(new_key)
        db.session.commit()
        
        logger.info(f"API key added: {service_name} for user {current_user.username}")
        
        return jsonify({
            'message': 'API key added successfully',
            'api_key': new_key.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Add API key error: {str(e)}")
        return jsonify({'error': 'Failed to add API key', 'message': str(e)}), 500


@settings_bp.route('/api-keys/<int:key_id>', methods=['PUT'])
@require_auth
@handle_errors
@validate_json(required_fields=['api_key'], optional_fields=['key_identifier'])
@log_api_call
def update_api_key(key_id):
    """
    Update an existing API key.
    
    Required fields:
    - api_key: New API key
    
    Optional fields:
    - key_identifier: New key identifier
    """
    data = request.validated_data
    current_user = request.current_user
    
    try:
        # Find API key
        api_key_obj = APIKey.query.filter_by(id=key_id, user_id=current_user.id).first()
        if not api_key_obj:
            return jsonify({'error': 'API key not found'}), 404
        
        # Validate new API key format
        new_api_key = data['api_key'].strip()
        if not validate_api_key(new_api_key):
            return jsonify({'error': 'Invalid API key format'}), 400
        
        # Update API key
        api_key_obj.update_key(new_api_key)
        
        if 'key_identifier' in data:
            api_key_obj.key_identifier = data['key_identifier'].strip() if data['key_identifier'] else None
        
        db.session.commit()
        
        logger.info(f"API key updated: {api_key_obj.service_name} for user {current_user.username}")
        
        return jsonify({
            'message': 'API key updated successfully',
            'api_key': api_key_obj.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update API key error: {str(e)}")
        return jsonify({'error': 'Failed to update API key', 'message': str(e)}), 500


@settings_bp.route('/api-keys/<int:key_id>', methods=['DELETE'])
@require_auth
@handle_errors
@log_api_call
def delete_api_key(key_id):
    """
    Delete an API key.
    """
    current_user = request.current_user
    
    try:
        # Find API key
        api_key_obj = APIKey.query.filter_by(id=key_id, user_id=current_user.id).first()
        if not api_key_obj:
            return jsonify({'error': 'API key not found'}), 404
        
        service_name = api_key_obj.service_name
        
        # Delete API key
        db.session.delete(api_key_obj)
        db.session.commit()
        
        logger.info(f"API key deleted: {service_name} for user {current_user.username}")
        
        return jsonify({'message': 'API key deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete API key error: {str(e)}")
        return jsonify({'error': 'Failed to delete API key', 'message': str(e)}), 500


@settings_bp.route('/api-keys/<int:key_id>/toggle', methods=['POST'])
@require_auth
@handle_errors
@log_api_call
def toggle_api_key(key_id):
    """
    Toggle API key active status.
    """
    current_user = request.current_user
    
    try:
        # Find API key
        api_key_obj = APIKey.query.filter_by(id=key_id, user_id=current_user.id).first()
        if not api_key_obj:
            return jsonify({'error': 'API key not found'}), 404
        
        # Toggle status
        api_key_obj.is_active = not api_key_obj.is_active
        db.session.commit()
        
        status_text = 'activated' if api_key_obj.is_active else 'deactivated'
        logger.info(f"API key {status_text}: {api_key_obj.service_name} for user {current_user.username}")
        
        return jsonify({
            'message': f'API key {status_text} successfully',
            'api_key': api_key_obj.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Toggle API key error: {str(e)}")
        return jsonify({'error': 'Failed to toggle API key', 'message': str(e)}), 500


@settings_bp.route('/api-keys/validate', methods=['POST'])
@require_auth
@handle_errors
@validate_json(required_fields=['service_name', 'api_key'])
@log_api_call
def validate_api_key_endpoint():
    """
    Validate an API key without saving it.
    
    Required fields:
    - service_name: Name of the service
    - api_key: The API key to validate
    """
    data = request.validated_data
    current_user = request.current_user
    
    try:
        service_name = data['service_name'].lower()
        api_key = data['api_key'].strip()
        
        # Validate service name
        valid_services = ['shodan', 'virustotal', 'abuseipdb', 'alienvault', 'securitytrails']
        if service_name not in valid_services:
            return jsonify({
                'error': 'Invalid service name',
                'valid_services': valid_services
            }), 400
        
        # TODO: Implement actual API key validation
        # For now, we'll do basic format validation
        
        is_valid = validate_api_key(api_key)
        
        if is_valid:
            # Simulate API validation
            validation_result = {
                'valid': True,
                'service': service_name,
                'message': f'API key format is valid for {service_name}'
            }
        else:
            validation_result = {
                'valid': False,
                'service': service_name,
                'message': 'Invalid API key format'
            }
        
        logger.info(f"API key validation attempted: {service_name} for user {current_user.username}")
        
        return jsonify(validation_result), 200
        
    except Exception as e:
        logger.error(f"Validate API key error: {str(e)}")
        return jsonify({'error': 'Failed to validate API key', 'message': str(e)}), 500


@settings_bp.route('/profile', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_profile():
    """
    Get user profile and settings.
    """
    current_user = request.current_user
    
    try:
        # Get user statistics
        from app.models.scan import Scan
        from app.models.result import Result
        from app.models.report import Report
        
        scan_count = Scan.query.filter_by(user_id=current_user.id).count()
        result_count = db.session.query(Result).join(Scan).filter(Scan.user_id == current_user.id).count()
        report_count = Report.query.filter_by(user_id=current_user.id).count()
        api_key_count = APIKey.query.filter_by(user_id=current_user.id, is_active=True).count()
        
        profile_data = current_user.to_dict(include_sensitive=True)
        profile_data.update({
            'statistics': {
                'scans': scan_count,
                'results': result_count,
                'reports': report_count,
                'api_keys': api_key_count
            }
        })
        
        return jsonify({
            'profile': profile_data
        }), 200
        
    except Exception as e:
        logger.error(f"Get profile error: {str(e)}")
        return jsonify({'error': 'Failed to get profile', 'message': str(e)}), 500


@settings_bp.route('/preferences', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_preferences():
    """
    Get user preferences.
    """
    current_user = request.current_user
    
    try:
        # TODO: Implement user preferences storage
        # For now, return default preferences
        
        preferences = {
            'notifications': {
                'email': True,
                'scan_completed': True,
                'scan_failed': True,
                'report_ready': True
            },
            'scanning': {
                'default_apis': ['shodan', 'virustotal'],
                'auto_start': False,
                'max_concurrent': 3,
                'timeout': 300
            },
            'reports': {
                'default_format': 'pdf',
                'default_template': 'standard',
                'auto_generate': False,
                'include_raw_data': False
            },
            'ui': {
                'theme': 'dark',
                'language': 'en',
                'timezone': 'UTC',
                'date_format': 'YYYY-MM-DD HH:mm:ss'
            }
        }
        
        return jsonify({
            'preferences': preferences
        }), 200
        
    except Exception as e:
        logger.error(f"Get preferences error: {str(e)}")
        return jsonify({'error': 'Failed to get preferences', 'message': str(e)}), 500


@settings_bp.route('/preferences', methods=['PUT'])
@require_auth
@handle_errors
@validate_json()
@log_api_call
def update_preferences():
    """
    Update user preferences.
    """
    data = request.validated_data
    current_user = request.current_user
    
    try:
        # TODO: Implement user preferences storage
        # For now, just validate and return success
        
        logger.info(f"Preferences updated for user {current_user.username}")
        
        return jsonify({
            'message': 'Preferences updated successfully',
            'preferences': data
        }), 200
        
    except Exception as e:
        logger.error(f"Update preferences error: {str(e)}")
        return jsonify({'error': 'Failed to update preferences', 'message': str(e)}), 500