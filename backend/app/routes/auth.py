"""
Authentication routes for user management.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import create_access_token, create_refresh_token, jwt_required, get_jwt_identity, get_jwt
from werkzeug.security import check_password_hash
from app.extensions import db, limiter
from app.models.user import User
from app.utils.decorators import handle_errors, validate_json, log_api_call, rate_limit
from app.utils.validators import validate_email, validate_username
import logging

auth_bp = Blueprint('auth', __name__)
logger = logging.getLogger(__name__)


@auth_bp.route('/register', methods=['POST'])
@handle_errors
@validate_json(required_fields=['username', 'password'], optional_fields=['email'])
@rate_limit('5 per minute')
@log_api_call
def register():
    """
    Register a new user.
    
    Required fields:
    - username: Unique username (3-30 characters)
    - password: Password (minimum 8 characters)
    
    Optional fields:
    - email: Email address
    """
    data = request.validated_data
    
    username = data['username'].strip()
    password = data['password']
    email = data.get('email', '').strip() if data.get('email') else None
    
    # Validate input
    if not validate_username(username):
        return jsonify({'error': 'Invalid username format'}), 400
    
    if len(password) < 8:
        return jsonify({'error': 'Password must be at least 8 characters long'}), 400
    
    if email and not validate_email(email):
        return jsonify({'error': 'Invalid email format'}), 400
    
    # Check if username already exists
    if User.find_by_username(username):
        return jsonify({'error': 'Username already exists'}), 409
    
    # Check if email already exists
    if email and User.find_by_email(email):
        return jsonify({'error': 'Email already exists'}), 409
    
    try:
        # Create new user
        user = User(username=username, email=email)
        user.set_password(password)
        
        db.session.add(user)
        db.session.commit()
        
        logger.info(f"New user registered: {username}")
        
        # Create tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        return jsonify({
            'message': 'User registered successfully',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Registration error: {str(e)}")
        return jsonify({'error': 'Registration failed', 'message': str(e)}), 500


@auth_bp.route('/login', methods=['POST'])
@handle_errors
@validate_json(required_fields=['username', 'password'])
@rate_limit('10 per minute')
@log_api_call
def login():
    """
    Authenticate user and return tokens.
    
    Required fields:
    - username: Username or email
    - password: Password
    """
    data = request.validated_data
    
    username_or_email = data['username'].strip()
    password = data['password']
    
    # Find user by username or email
    user = User.find_by_username_or_email(username_or_email)
    
    if not user or not user.check_password(password):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    if not user.is_active:
        return jsonify({'error': 'Account is disabled'}), 401
    
    try:
        # Update last login
        user.update_last_login()
        
        # Create tokens
        access_token = create_access_token(identity=user.id)
        refresh_token = create_refresh_token(identity=user.id)
        
        logger.info(f"User logged in: {user.username}")
        
        return jsonify({
            'message': 'Login successful',
            'user': user.to_dict(),
            'access_token': access_token,
            'refresh_token': refresh_token
        }), 200
        
    except Exception as e:
        logger.error(f"Login error: {str(e)}")
        return jsonify({'error': 'Login failed', 'message': str(e)}), 500


@auth_bp.route('/refresh', methods=['POST'])
@jwt_required(refresh=True)
@handle_errors
@log_api_call
def refresh():
    """
    Refresh access token using refresh token.
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user or not user.is_active:
            return jsonify({'error': 'User not found or inactive'}), 401
        
        # Create new access token
        new_access_token = create_access_token(identity=current_user_id)
        
        return jsonify({
            'access_token': new_access_token
        }), 200
        
    except Exception as e:
        logger.error(f"Token refresh error: {str(e)}")
        return jsonify({'error': 'Token refresh failed', 'message': str(e)}), 500


@auth_bp.route('/logout', methods=['POST'])
@jwt_required()
@handle_errors
@log_api_call
def logout():
    """
    Logout user (client-side token removal).
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if user:
            logger.info(f"User logged out: {user.username}")
        
        # In a production environment, you might want to blacklist the token
        # For now, we rely on client-side token removal
        
        return jsonify({'message': 'Logout successful'}), 200
        
    except Exception as e:
        logger.error(f"Logout error: {str(e)}")
        return jsonify({'error': 'Logout failed', 'message': str(e)}), 500


@auth_bp.route('/me', methods=['GET'])
@jwt_required()
@handle_errors
@log_api_call
def get_current_user():
    """
    Get current user information.
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        return jsonify({
            'user': user.to_dict(include_sensitive=True)
        }), 200
        
    except Exception as e:
        logger.error(f"Get current user error: {str(e)}")
        return jsonify({'error': 'Failed to get user information', 'message': str(e)}), 500


@auth_bp.route('/change-password', methods=['POST'])
@jwt_required()
@handle_errors
@validate_json(required_fields=['current_password', 'new_password'])
@rate_limit('5 per minute')
@log_api_call
def change_password():
    """
    Change user password.
    
    Required fields:
    - current_password: Current password
    - new_password: New password (minimum 8 characters)
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.validated_data
        current_password = data['current_password']
        new_password = data['new_password']
        
        # Verify current password
        if not user.check_password(current_password):
            return jsonify({'error': 'Current password is incorrect'}), 401
        
        # Validate new password
        if len(new_password) < 8:
            return jsonify({'error': 'New password must be at least 8 characters long'}), 400
        
        # Update password
        user.set_password(new_password)
        db.session.commit()
        
        logger.info(f"Password changed for user: {user.username}")
        
        return jsonify({'message': 'Password changed successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Change password error: {str(e)}")
        return jsonify({'error': 'Failed to change password', 'message': str(e)}), 500


@auth_bp.route('/update-profile', methods=['PUT'])
@jwt_required()
@handle_errors
@validate_json(optional_fields=['email'])
@log_api_call
def update_profile():
    """
    Update user profile.
    
    Optional fields:
    - email: New email address
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.validated_data
        
        # Update email if provided
        if 'email' in data:
            email = data['email'].strip() if data['email'] else None
            
            if email and not validate_email(email):
                return jsonify({'error': 'Invalid email format'}), 400
            
            if email and email != user.email:
                # Check if email already exists
                existing_user = User.find_by_email(email)
                if existing_user and existing_user.id != user.id:
                    return jsonify({'error': 'Email already exists'}), 409
                
                user.email = email
        
        db.session.commit()
        
        logger.info(f"Profile updated for user: {user.username}")
        
        return jsonify({
            'message': 'Profile updated successfully',
            'user': user.to_dict()
        }), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Update profile error: {str(e)}")
        return jsonify({'error': 'Failed to update profile', 'message': str(e)}), 500


@auth_bp.route('/delete-account', methods=['DELETE'])
@jwt_required()
@handle_errors
@validate_json(required_fields=['password'])
@rate_limit('5 per minute')
@log_api_call
def delete_account():
    """
    Delete user account.
    
    Required fields:
    - password: Current password for confirmation
    """
    try:
        current_user_id = get_jwt_identity()
        user = User.query.get(current_user_id)
        
        if not user:
            return jsonify({'error': 'User not found'}), 404
        
        data = request.validated_data
        password = data['password']
        
        # Verify password
        if not user.check_password(password):
            return jsonify({'error': 'Password is incorrect'}), 401
        
        # Delete user (cascade will delete related records)
        db.session.delete(user)
        db.session.commit()
        
        logger.info(f"Account deleted: {user.username}")
        
        return jsonify({'message': 'Account deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete account error: {str(e)}")
        return jsonify({'error': 'Failed to delete account', 'message': str(e)}), 500


# Error handlers for authentication blueprint
@auth_bp.errorhandler(422)
def handle_unprocessable_entity(e):
    """Handle unprocessable entity errors."""
    return jsonify({'error': 'Validation failed', 'message': str(e)}), 422


@auth_bp.errorhandler(401)
def handle_unauthorized(e):
    """Handle unauthorized errors."""
    return jsonify({'error': 'Unauthorized', 'message': 'Authentication required'}), 401


@auth_bp.errorhandler(403)
def handle_forbidden(e):
    """Handle forbidden errors."""
    return jsonify({'error': 'Forbidden', 'message': 'Insufficient permissions'}), 403


@auth_bp.errorhandler(429)
def handle_rate_limit(e):
    """Handle rate limit errors."""
    return jsonify({'error': 'Rate limit exceeded', 'message': str(e.description)}), 429