"""
Reports routes for managing generated reports.
"""

from flask import Blueprint, request, jsonify, send_file
from flask_jwt_extended import jwt_required, get_jwt_identity
from app.extensions import db
from app.models.user import User
from app.models.scan import Scan
from app.models.report import Report, ReportFormat, ReportStatus
from app.utils.decorators import handle_errors, validate_json, log_api_call, require_auth
import logging

reports_bp = Blueprint('reports', __name__)
logger = logging.getLogger(__name__)


@reports_bp.route('/', methods=['POST'])
@require_auth
@handle_errors
@validate_json(required_fields=['scan_id', 'name', 'format'], 
               optional_fields=['description', 'template', 'include_sections', 'filters', 'sorting'])
@log_api_call
def create_report():
    """
    Create a new report.
    
    Required fields:
    - scan_id: ID of the scan to report on
    - name: Report name
    - format: Report format (pdf, json, csv, xml, html)
    
    Optional fields:
    - description: Report description
    - template: Report template (default: standard)
    - include_sections: List of sections to include
    - filters: Report filters
    - sorting: Result sorting preferences
    """
    data = request.validated_data
    current_user = request.current_user
    
    try:
        # Validate scan ownership
        scan = Scan.query.filter_by(id=data['scan_id'], user_id=current_user.id).first()
        if not scan:
            return jsonify({'error': 'Scan not found'}), 404
        
        # Validate format
        try:
            report_format = ReportFormat(data['format'].lower())
        except ValueError:
            return jsonify({'error': f'Invalid format. Must be one of: {[f.value for f in ReportFormat]}'}), 400
        
        # Create report
        report = Report(
            user_id=current_user.id,
            scan_id=data['scan_id'],
            name=data['name'].strip(),
            format=report_format,
            description=data.get('description', '').strip() if data.get('description') else None,
            template=data.get('template', 'standard')
        )
        
        # Set optional fields
        if 'include_sections' in data:
            report.set_include_sections(data['include_sections'])
        
        if 'filters' in data:
            report.set_filters(data['filters'])
        
        if 'sorting' in data:
            report.set_sorting(data['sorting'])
        
        # Calculate statistics
        report.calculate_statistics()
        
        db.session.add(report)
        db.session.commit()
        
        logger.info(f"Report created: {report.name} by user {current_user.username}")
        
        # TODO: Queue report generation
        # For now, we'll simulate the report generation
        
        return jsonify({
            'message': 'Report created successfully',
            'report': report.to_dict()
        }), 201
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Create report error: {str(e)}")
        return jsonify({'error': 'Failed to create report', 'message': str(e)}), 500


@reports_bp.route('/', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def list_reports():
    """
    List user's reports with optional filtering.
    
    Query parameters:
    - format: Filter by format
    - status: Filter by status
    - scan_id: Filter by scan ID
    - page: Page number (default: 1)
    - per_page: Items per page (default: 20, max: 100)
    """
    current_user = request.current_user
    
    try:
        # Get query parameters
        format_filter = request.args.get('format')
        status_filter = request.args.get('status')
        scan_id = request.args.get('scan_id')
        page = int(request.args.get('page', 1))
        per_page = min(int(request.args.get('per_page', 20)), 100)
        
        # Build query
        query = Report.query.filter_by(user_id=current_user.id)
        
        # Apply filters
        if format_filter:
            try:
                format_enum = ReportFormat(format_filter.lower())
                query = query.filter_by(format=format_enum)
            except ValueError:
                return jsonify({'error': f'Invalid format. Must be one of: {[f.value for f in ReportFormat]}'}), 400
        
        if status_filter:
            try:
                status_enum = ReportStatus(status_filter.lower())
                query = query.filter_by(status=status_enum)
            except ValueError:
                return jsonify({'error': f'Invalid status. Must be one of: {[s.value for s in ReportStatus]}'}), 400
        
        if scan_id:
            # Verify scan ownership
            scan = Scan.query.filter_by(id=scan_id, user_id=current_user.id).first()
            if not scan:
                return jsonify({'error': 'Scan not found'}), 404
            query = query.filter_by(scan_id=scan_id)
        
        # Order by creation date (newest first)
        query = query.order_by(Report.created_at.desc())
        
        # Paginate
        total = query.count()
        reports = query.offset((page - 1) * per_page).limit(per_page).all()
        
        return jsonify({
            'reports': [report.to_dict() for report in reports],
            'pagination': {
                'page': page,
                'per_page': per_page,
                'total': total,
                'pages': (total + per_page - 1) // per_page
            }
        }), 200
        
    except Exception as e:
        logger.error(f"List reports error: {str(e)}")
        return jsonify({'error': 'Failed to list reports', 'message': str(e)}), 500


@reports_bp.route('/<int:report_id>', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_report(report_id):
    """
    Get report details by ID.
    """
    current_user = request.current_user
    
    try:
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
        
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        return jsonify({
            'report': report.to_dict(include_file_info=True)
        }), 200
        
    except Exception as e:
        logger.error(f"Get report error: {str(e)}")
        return jsonify({'error': 'Failed to get report', 'message': str(e)}), 500


@reports_bp.route('/<int:report_id>/download', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def download_report(report_id):
    """
    Download a generated report file.
    """
    current_user = request.current_user
    
    try:
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
        
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        if report.status != ReportStatus.COMPLETED:
            return jsonify({'error': 'Report is not ready for download'}), 400
        
        if not report.file_path:
            return jsonify({'error': 'Report file not found'}), 404
        
        # TODO: Implement actual file download
        # For now, return a placeholder response
        
        logger.info(f"Report downloaded: {report.name} by user {current_user.username}")
        
        return jsonify({
            'message': 'Report download started',
            'download_url': report.file_path,
            'filename': f"{report.name}{report.get_file_extension()}",
            'mime_type': report.get_mime_type(),
            'file_size': report.file_size
        }), 200
        
    except Exception as e:
        logger.error(f"Download report error: {str(e)}")
        return jsonify({'error': 'Failed to download report', 'message': str(e)}), 500


@reports_bp.route('/<int:report_id>', methods=['DELETE'])
@require_auth
@handle_errors
@log_api_call
def delete_report(report_id):
    """
    Delete a report by ID.
    """
    current_user = request.current_user
    
    try:
        report = Report.query.filter_by(id=report_id, user_id=current_user.id).first()
        
        if not report:
            return jsonify({'error': 'Report not found'}), 404
        
        # TODO: Delete actual file from filesystem
        
        # Delete report from database
        db.session.delete(report)
        db.session.commit()
        
        logger.info(f"Report deleted: {report.name} by user {current_user.username}")
        
        return jsonify({'message': 'Report deleted successfully'}), 200
        
    except Exception as e:
        db.session.rollback()
        logger.error(f"Delete report error: {str(e)}")
        return jsonify({'error': 'Failed to delete report', 'message': str(e)}), 500


@reports_bp.route('/templates', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_report_templates():
    """
    Get available report templates.
    """
    try:
        # TODO: Implement actual template discovery
        # For now, return placeholder templates
        
        templates = [
            {
                'id': 'standard',
                'name': 'Standard Report',
                'description': 'Comprehensive OSINT report with all sections',
                'sections': ['summary', 'findings', 'indicators', 'timeline', 'recommendations']
            },
            {
                'id': 'executive',
                'name': 'Executive Summary',
                'description': 'High-level summary for executives',
                'sections': ['summary', 'key_findings', 'risk_assessment', 'recommendations']
            },
            {
                'id': 'technical',
                'name': 'Technical Analysis',
                'description': 'Detailed technical analysis',
                'sections': ['findings', 'indicators', 'technical_details', 'raw_data']
            },
            {
                'id': 'compliance',
                'name': 'Compliance Report',
                'description': 'Compliance-focused report',
                'sections': ['summary', 'compliance_status', 'findings', 'remediation']
            }
        ]
        
        return jsonify({
            'templates': templates
        }), 200
        
    except Exception as e:
        logger.error(f"Get report templates error: {str(e)}")
        return jsonify({'error': 'Failed to get report templates', 'message': str(e)}), 500


@reports_bp.route('/stats', methods=['GET'])
@require_auth
@handle_errors
@log_api_call
def get_report_stats():
    """
    Get report statistics for the current user.
    """
    current_user = request.current_user
    
    try:
        # Get report counts by format
        format_counts = {}
        for format_type in ReportFormat:
            count = Report.query.filter_by(user_id=current_user.id, format=format_type).count()
            format_counts[format_type.value] = count
        
        # Get report counts by status
        status_counts = {}
        for status in ReportStatus:
            count = Report.query.filter_by(user_id=current_user.id, status=status).count()
            status_counts[status.value] = count
        
        # Get recent reports
        recent_reports = Report.query.filter_by(user_id=current_user.id).order_by(Report.created_at.desc()).limit(5).all()
        
        # Get total file size
        total_size = db.session.query(db.func.sum(Report.file_size)).filter(
            Report.user_id == current_user.id,
            Report.file_size.isnot(None)
        ).scalar() or 0
        
        return jsonify({
            'format_counts': format_counts,
            'status_counts': status_counts,
            'total_reports': sum(format_counts.values()),
            'total_file_size': total_size,
            'recent_reports': [report.to_dict() for report in recent_reports]
        }), 200
        
    except Exception as e:
        logger.error(f"Get report stats error: {str(e)}")
        return jsonify({'error': 'Failed to get report statistics', 'message': str(e)}), 500