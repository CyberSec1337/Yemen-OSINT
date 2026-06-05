"""
Threat Scorer for calculating threat levels and risk assessment.
Implements various scoring algorithms and risk models.
"""

import math
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Set
import logging

from app.models.result import Result, Severity


class ThreatScorer:
    """
    Calculates threat scores and risk assessments based on OSINT data.
    Implements multiple scoring models and risk factors.
    """
    
    def __init__(self):
        """Initialize threat scorer."""
        self.logger = logging.getLogger(self.__class__.__name__)
        
        # Scoring weights
        self.severity_weights = {
            'critical': 10.0,
            'high': 7.5,
            'medium': 5.0,
            'low': 2.5,
            'info': 1.0
        }
        
        # Source reliability scores
        self.source_reliability = {
            'virustotal': 9.0,
            'shodan': 8.0,
            'abuseipdb': 8.5,
            'alienvault': 7.5,
            'securitytrails': 7.0
        }
        
        # Indicator type weights
        self.indicator_weights = {
            'malicious_detection': 10.0,
            'vulnerability': 9.0,
            'abuse_reports': 8.0,
            'threat_score': 7.5,
            'malicious_activity': 8.5,
            'port': 4.0,
            'service': 3.0,
            'subdomain': 2.5,
            'domain': 2.0,
            'ip_address': 3.5,
            'url': 4.5,
            'hash': 6.0,
            'email': 2.0,
            'nameserver': 1.5,
            'registrar': 1.0,
            'antivirus_detection': 9.5
        }
        
        # Risk factors
        self.risk_factors = {
            'multiple_sources': 1.5,
            'high_severity_count': 2.0,
            'recent_activity': 1.3,
            'correlation_strength': 1.8,
            'indicator_diversity': 1.4,
            'confidence_level': 1.2
        }
    
    def calculate_threat_score(self, results: List[Result]) -> Dict[str, Any]:
        """
        Calculate comprehensive threat score from multiple results.
        
        Args:
            results: List of results to score
            
        Returns:
            Threat score analysis
        """
        if not results:
            return self._create_empty_score()
        
        # Base score calculation
        base_score = self._calculate_base_score(results)
        
        # Apply risk factors
        risk_adjusted_score = self._apply_risk_factors(base_score, results)
        
        # Normalize to 0-100 scale
        normalized_score = self._normalize_score(risk_adjusted_score)
        
        # Determine threat level
        threat_level = self._determine_threat_level(normalized_score)
        
        # Calculate component scores
        component_scores = self._calculate_component_scores(results)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(threat_level, results)
        
        return {
            'overall_score': normalized_score,
            'threat_level': threat_level,
            'base_score': base_score,
            'risk_adjusted_score': risk_adjusted_score,
            'component_scores': component_scores,
            'risk_factors': self._analyze_risk_factors(results),
            'recommendations': recommendations,
            'analysis_metadata': {
                'results_count': len(results),
                'sources_count': len(set(r.source for r in results)),
                'indicators_count': sum(len(r.get_indicators()) for r in results),
                'calculation_time': datetime.utcnow().isoformat()
            }
        }
    
    def _calculate_base_score(self, results: List[Result]) -> float:
        """Calculate base threat score from results."""
        total_score = 0.0
        total_weight = 0.0
        
        for result in results:
            # Get result severity weight
            severity_weight = self.severity_weights.get(result.severity.value, 1.0)
            
            # Get source reliability weight
            source_weight = self.source_reliability.get(result.source, 5.0)
            
            # Calculate indicator score
            indicator_score = self._calculate_indicator_score(result)
            
            # Combined weight
            combined_weight = severity_weight * source_weight * 0.1
            
            # Add to total
            total_score += indicator_score * combined_weight
            total_weight += combined_weight
        
        return total_score / total_weight if total_weight > 0 else 0.0
    
    def _calculate_indicator_score(self, result: Result) -> float:
        """Calculate score based on indicators in a result."""
        indicators = result.get_indicators()
        
        if not indicators:
            return 1.0
        
        total_indicator_score = 0.0
        
        for indicator in indicators:
            indicator_type = indicator.get('type', 'unknown')
            indicator_weight = self.indicator_weights.get(indicator_type, 1.0)
            
            # Apply severity modifier
            severity_modifier = 1.0
            indicator_severity = indicator.get('severity', 'info')
            if indicator_severity == 'critical':
                severity_modifier = 2.0
            elif indicator_severity == 'high':
                severity_modifier = 1.5
            elif indicator_severity == 'medium':
                severity_modifier = 1.2
            
            total_indicator_score += indicator_weight * severity_modifier
        
        # Average the indicator scores
        return total_indicator_score / len(indicators)
    
    def _apply_risk_factors(self, base_score: float, results: List[Result]) -> float:
        """Apply risk factors to base score."""
        adjusted_score = base_score
        
        # Multiple sources factor
        sources = set(r.source for r in results)
        if len(sources) > 1:
            adjusted_score *= self.risk_factors['multiple_sources']
        
        # High severity count factor
        high_severity_count = sum(1 for r in results if r.severity in [Severity.HIGH, Severity.CRITICAL])
        if high_severity_count > 0:
            adjusted_score *= (1.0 + (high_severity_count * 0.2))
        
        # Recent activity factor
        if self._has_recent_activity(results):
            adjusted_score *= self.risk_factors['recent_activity']
        
        # Indicator diversity factor
        all_indicators = []
        for result in results:
            all_indicators.extend(result.get_indicators())
        
        unique_types = set(ind.get('type', 'unknown') for ind in all_indicators)
        if len(unique_types) > 3:
            adjusted_score *= self.risk_factors['indicator_diversity']
        
        # Confidence level factor
        avg_confidence = sum(r.confidence for r in results) / len(results) if results else 50
        if avg_confidence > 75:
            adjusted_score *= self.risk_factors['confidence_level']
        
        return adjusted_score
    
    def _normalize_score(self, score: float) -> float:
        """Normalize score to 0-100 scale."""
        # Using logarithmic scaling for better distribution
        if score <= 0:
            return 0.0
        
        # Cap at 100 for very high scores
        normalized = min(100.0, math.log10(score + 1) * 20)
        
        return round(normalized, 2)
    
    def _determine_threat_level(self, score: float) -> str:
        """Determine threat level based on score."""
        if score >= 80:
            return 'CRITICAL'
        elif score >= 60:
            return 'HIGH'
        elif score >= 40:
            return 'MEDIUM'
        elif score >= 20:
            return 'LOW'
        else:
            return 'MINIMAL'
    
    def _calculate_component_scores(self, results: List[Result]) -> Dict[str, float]:
        """Calculate component scores for different aspects."""
        components = {
            'malware_detection': 0.0,
            'network_threats': 0.0,
            'reputation_risk': 0.0,
            'vulnerability_exposure': 0.0,
            'suspicious_activity': 0.0
        }
        
        for result in results:
            indicators = result.get_indicators()
            
            for indicator in indicators:
                indicator_type = indicator.get('type', 'unknown')
                indicator_severity = indicator.get('severity', 'info')
                severity_weight = self.severity_weights.get(indicator_severity, 1.0)
                
                # Categorize indicators
                if indicator_type in ['malicious_detection', 'antivirus_detection', 'hash']:
                    components['malware_detection'] += 10 * severity_weight
                elif indicator_type in ['ip_address', 'port', 'service', 'abuse_reports']:
                    components['network_threats'] += 8 * severity_weight
                elif indicator_type in ['domain', 'subdomain', 'url', 'email']:
                    components['reputation_risk'] += 6 * severity_weight
                elif indicator_type in ['vulnerability']:
                    components['vulnerability_exposure'] += 12 * severity_weight
                elif indicator_type in ['malicious_activity', 'threat_score']:
                    components['suspicious_activity'] += 9 * severity_weight
        
        # Normalize components to 0-100
        for component in components:
            components[component] = min(100.0, components[component])
        
        return components
    
    def _analyze_risk_factors(self, results: List[Result]) -> Dict[str, Any]:
        """Analyze specific risk factors."""
        factors = {
            'multiple_sources': {
                'present': len(set(r.source for r in results)) > 1,
                'impact': 'High',
                'description': 'Multiple sources confirm the threat'
            },
            'high_severity_findings': {
                'present': any(r.severity in [Severity.HIGH, Severity.CRITICAL] for r in results),
                'impact': 'Critical',
                'description': 'High severity indicators detected'
            },
            'recent_activity': {
                'present': self._has_recent_activity(results),
                'impact': 'Medium',
                'description': 'Recent malicious activity detected'
            },
            'diverse_indicators': {
                'present': len(set(ind.get('type', 'unknown') for r in results for ind in r.get_indicators())) > 5,
                'impact': 'Medium',
                'description': 'Multiple types of indicators present'
            },
            'high_confidence': {
                'present': any(r.confidence > 80 for r in results),
                'impact': 'High',
                'description': 'High confidence in findings'
            }
        }
        
        return factors
    
    def _has_recent_activity(self, results: List[Result]) -> bool:
        """Check if there's recent activity in results."""
        cutoff_date = datetime.utcnow() - timedelta(days=30)
        
        for result in results:
            if result.timestamp and result.timestamp > cutoff_date:
                return True
            
            # Check metadata for recent activity
            metadata = result.get_metadata()
            if metadata.get('last_reported_at'):
                try:
                    last_reported = datetime.fromisoformat(metadata['last_reported_at'].replace('Z', '+00:00'))
                    if last_reported > cutoff_date:
                        return True
                except:
                    pass
        
        return False
    
    def _generate_recommendations(self, threat_level: str, results: List[Result]) -> List[str]:
        """Generate security recommendations based on threat level and results."""
        recommendations = []
        
        # Base recommendations by threat level
        if threat_level == 'CRITICAL':
            recommendations.extend([
                'IMMEDIATE ACTION REQUIRED: Block all associated IPs and domains',
                'Conduct full security audit of affected systems',
                'Review all logs for suspicious activity',
                'Consider disconnecting affected systems from network'
            ])
        elif threat_level == 'HIGH':
            recommendations.extend([
                'Block identified malicious IPs and domains',
                'Monitor network traffic for suspicious patterns',
                'Update security signatures and rules',
                'Review access logs for unauthorized access'
            ])
        elif threat_level == 'MEDIUM':
            recommendations.extend([
                'Add IPs/domains to security watchlist',
                'Increase monitoring and logging',
                'Review security configurations',
                'Educate users about potential threats'
            ])
        elif threat_level == 'LOW':
            recommendations.extend([
                'Monitor for future activity',
                'Document findings for future reference',
                'Consider periodic security reviews'
            ])
        
        # Specific recommendations based on indicators
        all_indicators = []
        for result in results:
            all_indicators.extend(result.get_indicators())
        
        indicator_types = set(ind.get('type', 'unknown') for ind in all_indicators)
        
        if 'malicious_detection' in indicator_types:
            recommendations.append('Run antivirus scans on all systems')
        
        if 'vulnerability' in indicator_types:
            recommendations.append('Apply security patches and updates')
        
        if 'abuse_reports' in indicator_types:
            recommendations.append('Review abuse reports for additional context')
        
        if 'port' in indicator_types:
            recommendations.append('Review firewall rules and port configurations')
        
        return list(set(recommendations))  # Remove duplicates
    
    def _create_empty_score(self) -> Dict[str, Any]:
        """Create empty score for no results."""
        return {
            'overall_score': 0.0,
            'threat_level': 'MINIMAL',
            'base_score': 0.0,
            'risk_adjusted_score': 0.0,
            'component_scores': {
                'malware_detection': 0.0,
                'network_threats': 0.0,
                'reputation_risk': 0.0,
                'vulnerability_exposure': 0.0,
                'suspicious_activity': 0.0
            },
            'risk_factors': {},
            'recommendations': ['No threats detected'],
            'analysis_metadata': {
                'results_count': 0,
                'sources_count': 0,
                'indicators_count': 0,
                'calculation_time': datetime.utcnow().isoformat()
            }
        }
    
    def calculate_trend_score(self, historical_results: List[List[Result]]) -> Dict[str, Any]:
        """
        Calculate threat trend over time.
        
        Args:
            historical_results: List of result sets ordered by time
            
        Returns:
            Trend analysis
        """
        if len(historical_results) < 2:
            return {'trend': 'insufficient_data', 'direction': 'unknown'}
        
        scores = []
        for results in historical_results:
            score_analysis = self.calculate_threat_score(results)
            scores.append(score_analysis['overall_score'])
        
        # Calculate trend
        if len(scores) >= 3:
            recent_avg = sum(scores[-3:]) / 3
            earlier_avg = sum(scores[:-3]) / len(scores[:-3]) if len(scores) > 3 else scores[0]
        else:
            recent_avg = scores[-1]
            earlier_avg = scores[0]
        
        trend_direction = 'stable'
        trend_percentage = 0.0
        
        if earlier_avg > 0:
            change = ((recent_avg - earlier_avg) / earlier_avg) * 100
            trend_percentage = round(change, 2)
            
            if change > 10:
                trend_direction = 'increasing'
            elif change < -10:
                trend_direction = 'decreasing'
        
        return {
            'trend': trend_direction,
            'direction': trend_direction,
            'percentage_change': trend_percentage,
            'current_score': scores[-1],
            'previous_score': scores[-2] if len(scores) > 1 else 0,
            'scores_over_time': scores,
            'analysis_period': f"{len(scores)} time periods"
        }