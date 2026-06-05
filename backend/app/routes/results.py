"""
Results routes for managing scan results.
"""

from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.result import Result, Severity, ResultStatus
from app.utils.decorators import handle_errors, log_api_call, require_auth
import logging

results_bp = Blueprint('results', __name__)
logger = logging.getLogger(__name__)


@results_bp.route('/scan/<int:scan_id>', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_scan_results(scan_id):
    """
    Get results for a specific scan.
    
    Query parameters:
    - severity: Filter by severity
    - source: Filter by source/API
    - page: Page number (default: 1)
    - per_page: Items per page (default: 20, max: 100)
    """
    current_user = request.current_user
    
    try:
        # Verify scan ownership
        scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Get query parameters
        severity = request.args.get('severity')
        source = request.args.get('source')
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        
        # Build query
        query = Result.query.filter_by(scan_id=scan_id)
        
        # Apply filters
        if severity:
            try:
                severity_enum = Severity(severity.lower())
                query = query.filter_by(severity=severity_enum)
            except ValueError:
                return jsonify({'error': f'Invalid severity. Must be one of: {[s.value for s in Severity]}'}), 400
        
        if source:
            query = query.filter_by(source=source.lower())
        
        # Order by timestamp (newest first)
        query = query.order_by(Result.timestamp.desc())
        
        # Paginate
        total = query.count()
        results = query.offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'scan': scan.to_dict(),
            'results': [result.to_dict() for result in results],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Get scan results error: {str(e)}")
        return jsonify({'error': 'Failed to get scan results', 'message': str(e)}), 500


@results_bp.route('/<int:result_id>', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_result(result_id):
    """
    Get a specific result by ID.
    """
    current_user = request.current_user
    
    try:
        # Get result with scan ownership check
        result = db.session.query(Result).join(Scan).filter(
            Result.id == result_id,
            Scan.user_id == current_user.id
        ).first()
        
        if not result:
            return jsonify({'error': 'Result not found'}), 404
        
        return jsonify({
            'result': result.to_dict(include_raw=True)
        }), 200
        
    except Exception as e:
        logger.error(f"Get result error: {str(e)}")
        return jsonify({'error': 'Failed to get result', 'message': str(e)}), 500


@results_bp.route('/search', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def search_results():
    """
    Search results across all user's scans.
    
    Query parameters:
    - q: Search query
    - severity: Filter by severity
    - source: Filter by source
    - target_type: Filter by target type
    - date_from: Start date (ISO format)
    - date_to: End date (ISO format)
    - page: Page number (default: 1)
    - per_page: Items per page (default: 20, max: 100)
    """
    current_user = request.current_user
    
    try:
        # Get query parameters
        query_text = request.args.get('q', '').strip()
        severity = request.args.get('severity')
        source = request.args.get('source')
        target_type = request.args.get('target_type')
        date_from = request.args.get('date_from')
        date_to = request.args.get('date_to')
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        
        # Build query
        query = db.session.query(Result).join(Scan).filter(Scan.user_id == current_user.id)
        
        # Apply text search
        if query_text:
            query = query.filter(
                (Result.target.contains(query_text)) |
                (Result.summary.contains(query_text))
            )
        
        # Apply filters
        if severity:
            try:
                severity_enum = Severity(severity.lower())
                query = query.filter_by(severity=severity_enum)
            except ValueError:
                return jsonify({'error': f'Invalid severity. Must be one of: {[s.value for s in Severity]}'}), 400
        
        if source:
            query = query.filter_by(source=source.lower())
        
        if target_type:
            query = query.filter(Scan.target_type == target_type.lower())
        
        # Apply date filters
        if date_from:
            try:
                from datetime import datetime
                date_from_dt = datetime.fromisoformat(date_from.replace('Z', '+00:00'))
                query = query.filter(Result.timestamp >= date_from_dt)
            except ValueError:
                return jsonify({'error': 'Invalid date_from format'}), 400
        
        if date_to:
            try:
                from datetime import datetime
                date_to_dt = datetime.fromisoformat(date_to.replace('Z', '+00:00'))
                query = query.filter(Result.timestamp <= date_to_dt)
            except ValueError:
                return jsonify({'error': 'Invalid date_to format'}), 400
        
        # Order by timestamp (newest first)
        query = query.order_by(Result.timestamp.desc())
        
        # Paginate
        total = query.count()
        results = query.offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'results': [result.to_dict() for result in results],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            },
            'filters': {
                'query': query_text,
                'severity': severity,
                'source': source,
                'target_type': target_type,
                'date_from': date_from,
                'date_to': date_to
            }
        }), 200
        
    except Exception as e:
        logger.error(f"Search results error: {str(e)}")
        return jsonify({'error': 'Failed to search results', 'message': str(e)}), 500


@results_bp.route('/export', methods=['POST'])
@require_auth
@handle_errors
@log_api_call
def export_results():
    """
    Export results in various formats.
    
    Required fields:
    - format: Export format (json, csv, xml)
    
    Optional fields:
    - scan_id: Specific scan ID to export
    - filters: Export filters (same as search)
    """
    current_user = request.current_user
    
    try:
        data = request.get_json()
        
        if not data or 'format' not in data:
            return jsonify({'error': 'Export format is required'}), 400
        
        export_format = data['format'].lower()
        if export_format not in ['json', 'csv', 'xml']:
            return jsonify({'error': 'Invalid export format. Must be one of: json, csv, xml'}), 400
        
        # Get filters
        scan_id = data.get('scan_id')
        filters = data.get('filters', {})
        
        # Build query
        query = db.session.query(Result).join(Scan).filter(Scan.user_id == current_user.id)
        
        # Apply scan filter
        if scan_id:
            scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            query = query.filter(Result.scan_id == scan_id)
        
        # Apply other filters (similar to search endpoint)
        if filters.get('severity'):
            try:
                severity_enum = Severity(filters['severity'].lower())
                query = query.filter_by(severity=severity_enum)
            except ValueError:
                return jsonify({'error': 'Invalid severity filter'}), 400
        
        if filters.get('source'):
            query = query.filter_by(source=filters['source'].lower())
        
        # Get all results (no pagination for export)
        results = query.order_by(Result.timestamp.desc()).all()
        
        # TODO: Implement actual export functionality
        # For now, return a placeholder response
        
        logger.info(f"Results exported: {len(results)} results in {export_format} format by user {current_user.username}")
        
        return jsonify({
            'message': f'Export prepared successfully',
            'format': export_format,
            'total_results': len(results),
            'download_url': f'/api/results/download/{export_format}'  # Placeholder
        }), 200
        
    except Exception as e:
        logger.error(f"Export results error: {str(e)}")
        return jsonify({'error': 'Failed to export results', 'message': str(e)}), 500


@results_bp.route('/stats', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_result_stats():
    """
    Get result statistics for the current user.
    """
    current_user = request.current_user
    
    try:
        # Get result counts by severity
        severity_counts = {}
        for severity in Severity:
            count = db.session.query(Result).join(Scan).filter(
                Scan.user_id == current_user.id,
                Result.severity == severity
            ).count()
            severity_counts[severity.value] = count
        
        # Get result counts by source
        source_counts = db.session.query(
            Result.source,
            db.func.count(Result.id).label('count')
        ).join(Scan).filter(
            Scan.user_id == current_user.id
        ).group_by(Result.source).all()
        
        source_counts_dict = {source: count for source, count in source_counts}
        
        # Get recent results
        recent_results = db.session.query(Result).join(Scan).filter(
            Scan.user_id == current_user.id
        ).order_by(Result.timestamp.desc()).limit(10).all()
        
        # Get top targets
        top_targets = db.session.query(
            Result.target,
            db.func.count(Result.id).label('count')
        ).join(Scan).filter(
            Scan.user_id == current_user.id
        ).group_by(Result.target).order_by(db.desc('count')).limit(10).all()
        
        return jsonify({
            'severity_counts': severity_counts,
            'source_counts': source_counts_dict,
            'total_results': sum(severity_counts.values()),
            'recent_results': [result.to_dict() for result in recent_results],
            'top_targets': [{'target': target, 'count': count} for target, count in top_targets]
        }), 200
        
    except Exception as e:
        logger.error(f"Get result stats error: {str(e)}")
        return jsonify({'error': 'Failed to get result statistics', 'message': str(e)}), 500