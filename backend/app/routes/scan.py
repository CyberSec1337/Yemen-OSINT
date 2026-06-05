"""
Scan routes for managing OSINT scans.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models.user import User
from app.models.scan import Scan, ScanStatus, ScanType, TargetType
from app.models.result import Result
from app.services.osint_engine import OSINTEngine
from app.utils.decorators import handle_errors, validate_json, log_api_call, require_auth
from app.utils.validators import validate_target, validate_scan_name, validate_bulk_targets
import logging

# Global OSINT engine instance
osint_engine = OSINTEngine()

scan_bp = Blueprint('scan', __name__)
logger = logging.getLogger(__name__)


@scan_bp.route('/', methods=['POST'])
@require_auth
@handle_errors
@validate_json(required_fields=['name', 'target', 'target_type', 'selected_apis'], 
               optional_fields=['description', 'scan_type', 'scan_options'])
@log_api_call
def create_scan():
    """
    Create a new OSINT scan.
    
    Required fields:
    - name: Scan name
    - target: Target string or list of targets
    - target_type: Type of target (ip, domain, url, email, username, bitcoin, hash)
    - selected_apis: List of API names to use
    
    Optional fields:
    - description: Scan description
    - scan_type: Type of scan (single, bulk, scheduled)
    - scan_options: Additional scan options
    """
    data = request.validated_data
    current_user = request.current_user
    
    try:
        # Validate scan name
        if not validate_scan_name(data['name']):
            return jsonify({'error': 'Invalid scan name'}), 400
        
        # Validate target type
        try:
            target_type = TargetType(data['target_type'].lower())
        except ValueError:
            return jsonify({'error': f'Invalid target type. Must be one of: {[t.value for t in TargetType]}'}), 400
        
        # Validate scan type
        scan_type_str = data.get('scan_type', 'single').lower()
        try:
            scan_type = ScanType(scan_type_str)
        except ValueError:
            return jsonify({'error': f'Invalid scan type. Must be one of: {[t.value for t in ScanType]}'}), 400
        
        # Validate targets
        targets = data['target']
        if isinstance(targets, str):
            targets = [targets.strip()]
        elif isinstance(targets, list):
            targets = [t.strip() for t in targets if t.strip()]
        else:
            return jsonify({'error': 'Target must be a string or list of strings'}), 400
        
        if not targets:
            return jsonify({'error': 'At least one target is required'}), 400
        
        # Validate each target
        if scan_type == ScanType.BULK:
            is_valid, invalid_targets = validate_bulk_targets(targets, target_type.value)
            if not is_valid:
                if len(invalid_targets) > 10:
                    return jsonify({'error': f'Too many invalid targets ({len(invalid_targets)})'}), 400
                return jsonify({'error': 'Invalid targets', 'invalid_targets': invalid_targets}), 400
        else:
            # Single target validation
            if len(targets) > 1:
                return jsonify({'error': 'Single scan can only have one target'}), 400
            
            if not validate_target(targets[0], target_type.value):
                return jsonify({'error': f'Invalid {target_type.value} target'}), 400
        
        # Validate selected APIs
        selected_apis = data['selected_apis']
        if not isinstance(selected_apis, list) or not selected_apis:
            return jsonify({'error': 'At least one API must be selected'}), 400
        
        # Validate API names
        valid_apis = ['shodan', 'virustotal', 'abuseipdb', 'alienvault', 'securitytrails']
        invalid_apis = [api for api in selected_apis if api.lower() not in valid_apis]
        if invalid_apis:
            return jsonify({'error': 'Invalid APIs selected', 'invalid_apis': invalid_apis}), 400
        
        # Create scan
        scan = Scan(
            user_id=current_user.id,
            name=data['name'].strip(),
            target=targets,
            target_type=target_type,
            selected_apis=selected_apis,
            scan_type=scan_type,
            description=data.get('description', '').strip() if data.get('description') else None
        )
        
        # Set scan options if provided
        if 'scan_options' in data:
            scan.update_scan_options(data['scan_options'])
        
        db.session.add(scan)
        db.session.commit()
        
        logger.info(f"Scan created: {scan.name} by user {current_user.username}")
        
        return jsonify({
            'message': 'Scan created successfully',
            'scan': scan.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create scan error: {str(e)}")
        return jsonify({'error': 'Failed to create scan', 'message': str(e)}), 500


@scan_bp.route('/', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def list_scans():
    """
    List user's scans with optional filtering.
    
    Query parameters:
    - status: Filter by status
    - scan_type: Filter by scan type
    - target_type: Filter by target type
    - page: Page number (default: 1)
    - per_page: Items per page (default: 20, max: 100)
    """
    current_user = request.current_user
    
    try:
        # Get query parameters
        status = request.args.get('status')
        scan_type = request.args.get('scan_type')
        target_type = request.args.get('target_type')
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        
        # Build query
        query = Scan.query.filter_by(user_id=current_user.id)
        
        # Apply filters
        if status:
            try:
                status_enum = ScanStatus(status.lower())
                query = query.filter_by(status=status_enum)
            except ValueError:
                return jsonify({'error': f'Invalid status. Must be one of: {[s.value for s in ScanStatus]}'}), 400
        
        if scan_type:
            try:
                scan_type_enum = ScanType(scan_type.lower())
                query = query.filter_by(scan_type=scan_type_enum)
            except ValueError:
                return jsonify({'error': f'Invalid scan type. Must be one of: {[t.value for t in ScanType]}'}), 400
        
        if target_type:
            try:
                target_type_enum = TargetType(target_type.lower())
                query = query.filter_by(target_type=target_type_enum)
            except ValueError:
                return jsonify({'error': f'Invalid target type. Must be one of: {[t.value for t in TargetType]}'}), 400
        
        # Order by creation date (newest first)
        query = query.order_by(Scan.created_at.desc())
        
        # Paginate
        total = query.count()
        scans = query.offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'scans': [scan.to_dict() for scan in scans],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        }), 200
        
    except Exception as e:
        logger.error(f"List scans error: {str(e)}")
        return jsonify({'error': 'Failed to list scans', 'message': str(e)}), 500


@scan_bp.route('/<int:scan_id>', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_scan(scan_id):
    """
    Get scan details by ID.
    """
    current_user = request.current_user
    
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        return jsonify({
            'scan': scan.to_dict(include_results=False)
        }), 200
        
    except Exception as e:
        logger.error(f"Get scan error: {str(e)}")
        return jsonify({'error': 'Failed to get scan', 'message': str(e)}), 500


@scan_bp.route('/<int:scan_id>', methods=['DELETE'])
@require_auth
@handle_errors
@log_api_call
def delete_scan(scan_id):
    """
    Delete a scan by ID.
    """
    current_user = request.current_user
    
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Check if scan is running
        if scan.status == ScanStatus.RUNNING:
            return jsonify({'error': 'Cannot delete a running scan'}), 400
        
        # Delete scan (cascade will delete related results and reports)
        db.session.delete(scan)
        db.session.commit()
        
        logger.info(f"Scan deleted: {scan.name} by user {current_user.username}")
        
        return jsonify({'message': 'Scan deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete scan error: {str(e)}")
        return jsonify({'error': 'Failed to delete scan', 'message': str(e)}), 500


@scan_bp.route('/<int:scan_id>/start', methods=['POST'])
@require_auth
@handle_errors
@log_api_call
def start_scan(scan_id):
    """
    Start a scan.
    """
    current_user = request.current_user
    
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Check if scan can be started
        if scan.status != ScanStatus.PENDING:
            return jsonify({'error': f'Cannot start scan with status: {scan.status.value}'}), 400
        
        # Check if user has API keys for selected services
        from app.models.api_key import APIKey
        missing_keys = []
        
        for api_name in scan.get_selected_apis():
            api_key = APIKey.find_by_user_and_service(current_user.id, api_name)
            if not api_key:
                missing_keys.append(api_name)
        
        if missing_keys:
            return jsonify({
                'error': 'Missing API keys',
                'missing_keys': missing_keys
            }), 400
        
        # Start the scan using OSINT engine
        def progress_callback(scan_id, progress, current_step):
            """Progress callback for scan updates."""
            try:
                # Update scan progress in database
                scan = Scan.query.get(scan_id)
                if scan:
                    scan.update_progress(progress, current_step)
                    db.session.commit()
            except Exception as e:
                logger.error(f"Progress callback error: {str(e)}")
        
        # Start the scan
        if osint_engine.start_scan(scan.id, progress_callback):
            logger.info(f"Scan started: {scan.name} by user {current_user.username}")
            
            return jsonify({
                'message': 'Scan started successfully',
                'scan': scan.to_dict()
            }), 200
        else:
            return jsonify({'error': 'Failed to start scan'}), 500
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Start scan error: {str(e)}")
        return jsonify({'error': 'Failed to start scan', 'message': str(e)}), 500


@scan_bp.route('/<int:scan_id>/cancel', methods=['POST'])
@require_auth
@handle_errors
@log_api_call
def cancel_scan(scan_id):
    """
    Cancel a running scan.
    """
    current_user = request.current_user
    
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Check if scan can be cancelled
        if scan.status not in [ScanStatus.RUNNING, ScanStatus.PENDING]:
            return jsonify({'error': f'Cannot cancel scan with status: {scan.status.value}'}), 400
        
        # Cancel the scan using OSINT engine
        if osint_engine.cancel_scan(scan.id):
            logger.info(f"Scan cancelled: {scan.name} by user {current_user.username}")
            
            return jsonify({
                'message': 'Scan cancelled successfully',
                'scan': scan.to_dict()
            }), 200
        else:
            return jsonify({'error': 'Failed to cancel scan'}), 500
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Cancel scan error: {str(e)}")
        return jsonify({'error': 'Failed to cancel scan', 'message': str(e)}), 500


@scan_bp.route('/<int:scan_id>/pause', methods=['POST'])
@require_auth
@handle_errors
@log_api_call
def pause_scan(scan_id):
    """
    Pause a running scan.
    """
    current_user = request.current_user
    
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Check if scan can be paused
        if scan.status != ScanStatus.RUNNING:
            return jsonify({'error': f'Cannot pause scan with status: {scan.status.value}'}), 400
        
        # Pause the scan using OSINT engine
        if osint_engine.pause_scan(scan.id):
            logger.info(f"Scan paused: {scan.name} by user {current_user.username}")
            
            return jsonify({
                'message': 'Scan paused successfully',
                'scan': scan.to_dict()
            }), 200
        else:
            return jsonify({'error': 'Failed to pause scan'}), 500
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Pause scan error: {str(e)}")
        return jsonify({'error': 'Failed to pause scan', 'message': str(e)}), 500


@scan_bp.route('/<int:scan_id>/resume', methods=['POST'])
@require_auth
@handle_errors
@log_api_call
def resume_scan(scan_id):
    """
    Resume a paused scan.
    """
    current_user = request.current_user
    
    try:
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Check if scan can be resumed
        if scan.status != ScanStatus.PAUSED:
            return jsonify({'error': f'Cannot resume scan with status: {scan.status.value}'}), 400
        
        # Resume the scan using OSINT engine
        if osint_engine.resume_scan(scan.id):
            logger.info(f"Scan resumed: {scan.name} by user {current_user.username}")
            
            return jsonify({
                'message': 'Scan resumed successfully',
                'scan': scan.to_dict()
            }), 200
        else:
            return jsonify({'error': 'Failed to resume scan'}), 500
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Resume scan error: {str(e)}")
        return jsonify({'error': 'Failed to resume scan', 'message': str(e)}), 500


@scan_bp.route('/<int:scan_id>/status', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_scan_status(scan_id):
    """
    Get real-time scan status from OSINT engine.
    """
    current_user = request.current_user
    
    try:
        # Verify scan ownership
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Get status from OSINT engine
        engine_status = osint_engine.get_scan_status(scan_id)
        
        if engine_status:
            return jsonify({
                'status': engine_status
            }), 200
        else:
            # Fallback to database status
            return jsonify({
                'status': {
                    'scan_id': scan.id,
                    'status': scan.status.value,
                    'progress': scan.progress,
                    'current_step': scan.current_step,
                    'started_at': scan.started_at.isoformat() if scan.started_at else None,
                    'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                    'total_results': scan.total_results,
                    'completed_apis': scan.completed_apis,
                    'total_apis': scan.total_apis,
                    'is_active': False
                }
            }), 200
        
    except Exception as e:
        logger.error(f"Get scan status error: {str(e)}")
        return jsonify({'error': 'Failed to get scan status', 'message': str(e)}), 500


@scan_bp.route('/engine/status', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_engine_status():
    """
    Get OSINT engine status and statistics.
    """
    current_user = request.current_user
    
    try:
        # Get engine statistics
        engine_stats = osint_engine.get_engine_statistics()
        
        # Get user's active scans
        user_scans = Scan.query.filter_by(user_id=current_user.id).all()
        user_active_scans = [scan.id for scan in user_scans if scan.id in engine_stats['active_scan_ids']]
        
        return jsonify({
            'engine_statistics': engine_stats,
            'user_active_scans': user_active_scans,
            'user_total_scans': len(user_scans)
        }), 200
        
    except Exception as e:
        logger.error(f"Get engine status error: {str(e)}")
        return jsonify({'error': 'Failed to get engine status', 'message': str(e)}), 500


@scan_bp.route('/test-apis', methods=['POST'])
@require_auth
@handle_errors
@validate_json(optional_fields=['apis'])
@log_api_call
def test_user_apis():
    """
    Test user's API connections.
    
    Optional fields:
    - apis: List of specific APIs to test (tests all if not provided)
    """
    current_user = request.current_user
    data = request.validated_data
    
    try:
        from app.services.api_manager import APIManager
        
        # Initialize API manager for user
        api_manager = APIManager(current_user.id)
        
        # Get APIs to test
        apis_to_test = data.get('apis')
        if not apis_to_test:
            apis_to_test = api_manager.get_available_services()
        
        # Test API connections
        test_results = {}
        for api_name in apis_to_test:
            if api_name in api_manager.services:
                test_results[api_name] = {
                    'available': True,
                    'connection_test': api_manager.test_service_connection(api_name),
                    'validation': api_manager.validate_service(api_name)
                }
            else:
                test_results[api_name] = {
                    'available': False,
                    'connection_test': False,
                    'validation': False,
                    'reason': 'API key not configured'
                }
        
        return jsonify({
            'test_results': test_results,
            'total_apis': len(apis_to_test),
            'working_apis': len([api for api, result in test_results.items() if result.get('connection_test', False)])
        }), 200
        
    except Exception as e:
        logger.error(f"Test APIs error: {str(e)}")
        return jsonify({'error': 'Failed to test APIs', 'message': str(e)}), 500


@scan_bp.route('/threat-analysis/<int:scan_id>', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_threat_analysis(scan_id):
    """
    Get detailed threat analysis for a completed scan.
    """
    current_user = request.current_user
    
    try:
        # Verify scan ownership
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != ScanStatus.COMPLETED:
            return jsonify({'error': 'Scan must be completed to get threat analysis'}), 400
        
        # Get scan results
        results = Result.query.filter_by(scan_id=scan_id).all()
        
        if not results:
            return jsonify({'error': 'No results found for scan'}), 404
        
        # Calculate threat analysis
        threat_analysis = osint_engine.threat_scorer.calculate_threat_score(results)
        
        # Get summary report
        summary_report = osint_engine.data_processor.create_summary_report(results)
        
        return jsonify({
            'scan_info': scan.to_dict(),
            'threat_analysis': threat_analysis,
            'summary_report': summary_report
        }), 200
        
    except Exception as e:
        logger.error(f"Get threat analysis error: {str(e)}")
        return jsonify({'error': 'Failed to get threat analysis', 'message': str(e)}), 500


@scan_bp.route('/correlations/<int:scan_id>', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_scan_correlations(scan_id):
    """
    Get correlations between results in a scan.
    """
    current_user = request.current_user
    
    try:
        # Verify scan ownership
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        if scan.status != ScanStatus.COMPLETED:
            return jsonify({'error': 'Scan must be completed to get correlations'}), 400
        
        # Get scan results
        results = Result.query.filter_by(scan_id=scan_id).all()
        
        if not results:
            return jsonify({'error': 'No results found for scan'}), 404
        
        # Find correlations
        correlations = osint_engine.data_processor.correlate_results(results)
        
        # Format correlations for response
        formatted_correlations = []
        for result1, result2, correlation_type in correlations:
            formatted_correlations.append({
                'correlation_type': correlation_type,
                'result1': {
                    'id': result1.id,
                    'source': result1.source,
                    'target': result1.target,
                    'severity': result1.severity.value
                },
                'result2': {
                    'id': result2.id,
                    'source': result2.source,
                    'target': result2.target,
                    'severity': result2.severity.value
                }
            })
        
        return jsonify({
            'scan_id': scan_id,
            'total_correlations': len(correlations),
            'correlations': formatted_correlations
        }), 200
        
    except Exception as e:
        logger.error(f"Get correlations error: {str(e)}")
        return jsonify({'error': 'Failed to get correlations', 'message': str(e)}), 500


@scan_bp.route('/stats', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_scan_stats():
    """
    Get scan statistics for the current user.
    """
    current_user = request.current_user
    
    try:
        # Get scan counts by status
        status_counts = {}
        for status in ScanStatus:
            count = Scan.query.filter_by(user_id=current_user.id, status=status).count()
            status_counts[status.value] = count
        
        # Get scan counts by type
        type_counts = {}
        for scan_type in ScanType:
            count = Scan.query.filter_by(user_id=current_user.id, scan_type=scan_type).count()
            type_counts[scan_type.value] = count
        
        # Get total results
        total_results = db.session.query(Result).join(Scan).filter(Scan.user_id == current_user.id).count()
        
        # Get recent scans
        recent_scans = Scan.query.filter_by(user_id=current_user.id).order_by(Scan.created_at.desc()).limit(5).all()
        
        return jsonify({
            'status_counts': status_counts,
            'type_counts': type_counts,
            'total_scans': sum(status_counts.values()),
            'total_results': total_results,
            'recent_scans': [scan.to_dict() for scan in recent_scans]
        }), 200
        
    except Exception as e:
        logger.error(f"Get scan stats error: {str(e)}")
        return jsonify({'error': 'Failed to get scan statistics', 'message': str(e)}), 500