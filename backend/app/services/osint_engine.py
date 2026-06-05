"""
OSINT Engine - Main orchestrator for OSINT scans.
Coordinates API calls, processes results, and manages scan lifecycle.
"""

import time
import threading
from datetime import datetime
from typing import Dict, List, Any, Optional, Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
import logging

from app.extensions import db
from app.models.scan import Scan, ScanStatus, ScanType
from app.models.result import Result
from app.models.api_key import APIKey
from .api_manager import APIManager
from .data_processor import DataProcessor
from .threat_scorer import ThreatScorer


class OSINTEngine:
    """
    Main OSINT engine that orchestrates scans and coordinates API calls.
    Handles scan execution, progress tracking, and result processing.
    """
    
    def __init__(self):
        """Initialize OSINT engine."""
        self.logger = logging.getLogger(self.__class__.__name__)
        self.active_scans = {}  # scan_id -> thread
        self.scan_callbacks = {}  # scan_id -> callback functions
        self.max_concurrent_scans = 5
        
        # Initialize processors
        self.data_processor = DataProcessor()
        self.threat_scorer = ThreatScorer()
        
        # Thread pool for scan execution
        self.executor = ThreadPoolExecutor(max_workers=self.max_concurrent_scans)
        
        self.logger.info("OSINT Engine initialized")
    
    def start_scan(self, scan_id: int, progress_callback: Optional[Callable] = None) -> bool:
        """
        Start a new scan.
        
        Args:
            scan_id: ID of the scan to start
            progress_callback: Optional callback for progress updates
            
        Returns:
            True if scan started successfully, False otherwise
        """
        try:
            # Check if scan is already running
            if scan_id in self.active_scans:
                self.logger.warning(f"Scan {scan_id} is already running")
                return False
            
            # Get scan from database
            scan = Scan.query.get(scan_id)
            if not scan:
                self.logger.error(f"Scan {scan_id} not found")
                return False
            
            if scan.status != ScanStatus.PENDING:
                self.logger.error(f"Scan {scan_id} is not in pending status")
                return False
            
            # Store callback if provided
            if progress_callback:
                self.scan_callbacks[scan_id] = progress_callback
            
            # Submit scan for execution
            future = self.executor.submit(self._execute_scan, scan_id)
            self.active_scans[scan_id] = future
            
            self.logger.info(f"Scan {scan_id} started")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to start scan {scan_id}: {str(e)}")
            return False
    
    def cancel_scan(self, scan_id: int) -> bool:
        """
        Cancel a running scan.
        
        Args:
            scan_id: ID of the scan to cancel
            
        Returns:
            True if scan cancelled successfully, False otherwise
        """
        try:
            if scan_id not in self.active_scans:
                self.logger.warning(f"Scan {scan_id} is not running")
                return False
            
            # Get scan and update status
            scan = Scan.query.get(scan_id)
            if scan:
                scan.cancel_scan()
            
            # Cancel the future
            future = self.active_scans[scan_id]
            future.cancel()
            
            # Clean up
            del self.active_scans[scan_id]
            if scan_id in self.scan_callbacks:
                del self.scan_callbacks[scan_id]
            
            self.logger.info(f"Scan {scan_id} cancelled")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to cancel scan {scan_id}: {str(e)}")
            return False
    
    def pause_scan(self, scan_id: int) -> bool:
        """
        Pause a running scan.
        
        Args:
            scan_id: ID of the scan to pause
            
        Returns:
            True if scan paused successfully, False otherwise
        """
        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                return False
            
            if scan.status != ScanStatus.RUNNING:
                return False
            
            scan.pause_scan()
            self.logger.info(f"Scan {scan_id} paused")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to pause scan {scan_id}: {str(e)}")
            return False
    
    def resume_scan(self, scan_id: int) -> bool:
        """
        Resume a paused scan.
        
        Args:
            scan_id: ID of the scan to resume
            
        Returns:
            True if scan resumed successfully, False otherwise
        """
        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                return False
            
            if scan.status != ScanStatus.PAUSED:
                return False
            
            scan.resume_scan()
            self.logger.info(f"Scan {scan_id} resumed")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to resume scan {scan_id}: {str(e)}")
            return False
    
    def get_scan_status(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Get current status of a scan.
        
        Args:
            scan_id: ID of the scan
            
        Returns:
            Scan status information or None if not found
        """
        try:
            scan = Scan.query.get(scan_id)
            if not scan:
                return None
            
            return {
                'scan_id': scan.id,
                'status': scan.status.value,
                'progress': scan.progress,
                'current_step': scan.current_step,
                'started_at': scan.started_at.isoformat() if scan.started_at else None,
                'completed_at': scan.completed_at.isoformat() if scan.completed_at else None,
                'total_results': scan.total_results,
                'completed_apis': scan.completed_apis,
                'total_apis': scan.total_apis,
                'is_active': scan_id in self.active_scans
            }
            
        except Exception as e:
            self.logger.error(f"Failed to get scan status {scan_id}: {str(e)}")
            return None
    
    def _execute_scan(self, scan_id: int):
        """
        Execute a scan (runs in separate thread).
        
        Args:
            scan_id: ID of the scan to execute
        """
        try:
            # Get scan from database
            scan = Scan.query.get(scan_id)
            if not scan:
                self.logger.error(f"Scan {scan_id} not found for execution")
                return
            
            # Mark scan as started
            scan.start_scan()
            self._update_progress(scan_id, 0, "Initializing scan")
            
            # Initialize API manager
            api_manager = APIManager(scan.user_id)
            
            # Get scan targets and APIs
            targets = scan.get_targets()
            selected_apis = scan.get_selected_apis()
            
            # Validate API keys
            available_apis = api_manager.get_available_services()
            missing_apis = [api for api in selected_apis if api not in available_apis]
            
            if missing_apis:
                scan.fail_scan(f"Missing API keys for: {', '.join(missing_apis)}")
                self._cleanup_scan(scan_id)
                return
            
            # Execute scan for each target
            all_results = []
            total_targets = len(targets)
            
            for i, target in enumerate(targets):
                try:
                    # Check if scan was cancelled
                    if scan.status == ScanStatus.CANCELLED:
                        break
                    
                    # Update progress
                    target_progress = int((i / total_targets) * 80)  # 80% for API calls
                    self._update_progress(scan_id, target_progress, f"Scanning {target}")
                    
                    # Execute APIs for this target
                    target_results = self._scan_target(api_manager, target, selected_apis, scan_id)
                    all_results.extend(target_results)
                    
                except Exception as e:
                    self.logger.error(f"Error scanning target {target}: {str(e)}")
                    continue
            
            # Check if scan was cancelled
            if scan.status == ScanStatus.CANCELLED:
                self._cleanup_scan(scan_id)
                return
            
            # Process and correlate results
            self._update_progress(scan_id, 85, "Processing results")
            
            # Deduplicate results
            deduplicated_results = self.data_processor.deduplicate_results(all_results)
            
            # Enrich results
            enriched_results = []
            for result in deduplicated_results:
                enriched_result = self.data_processor.enrich_result(result)
                enriched_results.append(enriched_result)
            
            # Find correlations
            correlations = self.data_processor.correlate_results(enriched_results)
            
            # Calculate threat score
            self._update_progress(scan_id, 90, "Calculating threat scores")
            threat_analysis = self.threat_scorer.calculate_threat_score(enriched_results)
            
            # Save results to database
            self._update_progress(scan_id, 95, "Saving results")
            self._save_results(scan_id, enriched_results)
            
            # Update scan with summary
            self._update_scan_summary(scan, enriched_results, threat_analysis)
            
            # Complete scan
            scan.complete_scan()
            self._update_progress(scan_id, 100, "Scan completed")
            
            self.logger.info(f"Scan {scan_id} completed successfully with {len(enriched_results)} results")
            
        except Exception as e:
            self.logger.error(f"Scan {scan_id} failed: {str(e)}")
            try:
                scan = Scan.query.get(scan_id)
                if scan:
                    scan.fail_scan(str(e))
            except:
                pass
        finally:
            self._cleanup_scan(scan_id)
    
    def _scan_target(self, api_manager: APIManager, target: str, apis: List[str], scan_id: int) -> List[Result]:
        """
        Scan a single target with multiple APIs.
        
        Args:
            api_manager: API manager instance
            target: Target to scan
            apis: List of APIs to use
            scan_id: Scan ID
            
        Returns:
            List of results
        """
        results = []
        
        # Determine optimal query types for each API
        query_types = {}
        for api in apis:
            query_types[api] = api_manager.get_optimal_query_type(api, target)
        
        # Execute parallel queries
        api_responses = api_manager.execute_parallel_queries(target, apis, query_types)
        
        # Process responses
        for api_name, response in api_responses.items():
            try:
                if response:
                    # Create result from API response
                    result = self._create_result_from_response(
                        scan_id, api_name, target, response
                    )
                    if result:
                        results.append(result)
                else:
                    # Create error result
                    result = Result(
                        scan_id=scan_id,
                        source=api_name,
                        target=target,
                        status=ResultStatus.ERROR
                    )
                    result.error_message = "No response from API"
                    results.append(result)
                    
            except Exception as e:
                self.logger.error(f"Error processing response from {api_name}: {str(e)}")
                continue
        
        return results
    
    def _create_result_from_response(self, scan_id: int, api_name: str, target: str, response: Dict[str, Any]) -> Optional[Result]:
        """
        Create a Result object from API response.
        
        Args:
            scan_id: Scan ID
            api_name: API name
            target: Target
            response: API response
            
        Returns:
            Result object or None if failed
        """
        try:
            # Normalize response
            normalized = self.data_processor.normalize_api_response(api_name, response, target)
            
            # Create result
            result = Result(
                scan_id=scan_id,
                source=normalized['source'],
                target=target,
                status=ResultStatus[normalized['status'].upper()],
                severity=Severity[normalized['severity'].upper()]
            )
            
            # Set data
            result.summary = normalized['data']['summary']
            result.set_details(normalized['data']['details'])
            result.set_indicators(normalized['data']['indicators'])
            result.set_metadata(normalized['data']['metadata'])
            
            if 'error' in normalized and normalized['error']:
                result.error_message = normalized['error']
            
            return result
            
        except Exception as e:
            self.logger.error(f"Error creating result from {api_name} response: {str(e)}")
            return None
    
    def _save_results(self, scan_id: int, results: List[Result]):
        """
        Save results to database.
        
        Args:
            scan_id: Scan ID
            results: List of results to save
        """
        try:
            for result in results:
                db.session.add(result)
            
            db.session.commit()
            self.logger.info(f"Saved {len(results)} results for scan {scan_id}")
            
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to save results for scan {scan_id}: {str(e)}")
    
    def _update_scan_summary(self, scan: Scan, results: List[Result], threat_analysis: Dict[str, Any]):
        """
        Update scan with summary information.
        
        Args:
            scan: Scan object
            results: List of results
            threat_analysis: Threat analysis results
        """
        try:
            # Count results by severity
            severity_counts = {}
            for result in results:
                severity = result.severity.value
                severity_counts[severity] = severity_counts.get(severity, 0) + 1
            
            # Update scan with summary
            scan.total_results = len(results)
            scan.high_severity_count = severity_counts.get('high', 0) + severity_counts.get('critical', 0)
            scan.medium_severity_count = severity_counts.get('medium', 0)
            scan.low_severity_count = severity_counts.get('low', 0)
            
            # Store threat analysis in scan options
            scan_options = scan.get_scan_options()
            scan_options['threat_analysis'] = threat_analysis
            scan.update_scan_options(scan_options)
            
            db.session.commit()
            
        except Exception as e:
            db.session.rollback()
            self.logger.error(f"Failed to update scan summary: {str(e)}")
    
    def _update_progress(self, scan_id: int, progress: int, current_step: str):
        """
        Update scan progress.
        
        Args:
            scan_id: Scan ID
            progress: Progress percentage (0-100)
            current_step: Description of current step
        """
        try:
            scan = Scan.query.get(scan_id)
            if scan:
                scan.update_progress(progress, current_step)
            
            # Call progress callback if available
            if scan_id in self.scan_callbacks:
                callback = self.scan_callbacks[scan_id]
                try:
                    callback(scan_id, progress, current_step)
                except Exception as e:
                    self.logger.error(f"Progress callback error: {str(e)}")
            
        except Exception as e:
            self.logger.error(f"Failed to update progress for scan {scan_id}: {str(e)}")
    
    def _cleanup_scan(self, scan_id: int):
        """
        Clean up scan resources.
        
        Args:
            scan_id: Scan ID to clean up
        """
        try:
            if scan_id in self.active_scans:
                del self.active_scans[scan_id]
            
            if scan_id in self.scan_callbacks:
                del self.scan_callbacks[scan_id]
            
        except Exception as e:
            self.logger.error(f"Error cleaning up scan {scan_id}: {str(e)}")
    
    def get_active_scans(self) -> List[int]:
        """
        Get list of currently active scan IDs.
        
        Returns:
            List of active scan IDs
        """
        return list(self.active_scans.keys())
    
    def get_engine_statistics(self) -> Dict[str, Any]:
        """
        Get engine statistics.
        
        Returns:
            Engine statistics
        """
        return {
            'active_scans': len(self.active_scans),
            'max_concurrent_scans': self.max_concurrent_scans,
            'thread_pool_workers': self.executor._max_workers,
            'active_scan_ids': list(self.active_scans.keys()),
            'registered_callbacks': len(self.scan_callbacks)
        }
    
    def shutdown(self):
        """Shutdown the OSINT engine."""
        try:
            # Cancel all active scans
            for scan_id in list(self.active_scans.keys()):
                self.cancel_scan(scan_id)
            
            # Shutdown thread pool
            self.executor.shutdown(wait=True)
            
            self.logger.info("OSINT Engine shutdown complete")
            
        except Exception as e:
            self.logger.error(f"Error during engine shutdown: {str(e)}")
    
    def __del__(self):
        """Cleanup when engine is destroyed."""
        self.shutdown()