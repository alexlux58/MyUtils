"""
JSONL Handler
Handles output to JSONL format for toolchain integration.
"""

import json
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from datetime import datetime


class JSONLHandler:
    """Handles output to JSONL format for toolchain integration."""

    def __init__(self):
        """Initialize the JSONL handler."""
        self.logger = logging.getLogger(__name__)

    async def save_results(self, results: List[Dict[str, Any]], output_path: str) -> bool:
        """Save results to JSONL format."""
        try:
            output_dir = Path(output_path)
            output_dir.mkdir(parents=True, exist_ok=True)
            
            # Generate filename with timestamp
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"reconnaissance_results_{timestamp}.jsonl"
            filepath = output_dir / filename
            
            # Write results to JSONL file
            with open(filepath, 'w', encoding='utf-8') as f:
                for result in results:
                    # Flatten the result for better toolchain integration
                    flattened_result = self._flatten_result(result)
                    f.write(json.dumps(flattened_result, default=str) + '\n')
            
            self.logger.info(f"Results saved to JSONL: {filepath}")
            
            # Also create a summary file
            await self._create_summary_file(results, output_dir, timestamp)
            
            return True

        except Exception as e:
            self.logger.error(f"Error saving to JSONL: {e}")
            return False

    def _flatten_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        """Flatten result structure for better toolchain integration."""
        flattened = {
            'metadata': {
                'inventory_id': result.get('inventory_id', ''),
                'input_value': result.get('input_value', ''),
                'input_type': result.get('input_type', ''),
                'sensitivity_level': result.get('sensitivity_level', ''),
                'authorized_scan': result.get('authorized_scan', False),
                'timestamp': result.get('timestamp', ''),
                'collection_type': 'combined'
            }
        }
        
        # Attack surface analysis
        attack_surface = result.get('attack_surface', {})
        if attack_surface:
            flattened['attack_surface'] = {
                'score': attack_surface.get('attack_surface_score', 0),
                'risk_level': attack_surface.get('risk_level', 'unknown'),
                'initial_access_vectors': attack_surface.get('initial_access_vectors', []),
                'password_spray_candidates': attack_surface.get('password_spray_candidates', []),
                'phishing_risk_level': attack_surface.get('phishing_risk_level', 'unknown'),
                'mitre_attack_mapping': attack_surface.get('mitre_attack_mapping', []),
                'priority_actions': attack_surface.get('priority_actions', [])
            }
        
        # Correlated data
        correlated_data = result.get('correlated_data', {})
        if correlated_data:
            flattened['intelligence'] = self._extract_intelligence_data(correlated_data)
        
        # Defensive recommendations
        defensive_recommendations = result.get('defensive_recommendations', [])
        if defensive_recommendations:
            flattened['defensive_recommendations'] = defensive_recommendations
        
        # Error handling
        if 'error' in result:
            flattened['error'] = result['error']
        
        return flattened

    def _extract_intelligence_data(self, correlated_data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract and structure intelligence data."""
        intelligence = {}
        
        # Domain intelligence
        domain_intel = correlated_data.get('domain_intelligence', {})
        if domain_intel:
            intelligence['domain'] = {
                'dns_records': domain_intel.get('dns_records', {}),
                'whois_info': domain_intel.get('whois_info', {}),
                'security_headers': domain_intel.get('security_headers', {}),
                'vulnerabilities': domain_intel.get('vulnerabilities', {}),
                'subdomains': domain_intel.get('subdomains', []),
                'technology_stack': domain_intel.get('technology_stack', {}),
                'certificate_analysis': domain_intel.get('certificate_analysis', {})
            }
        
        # IP intelligence
        ip_intel = correlated_data.get('ip_intelligence', {})
        if ip_intel:
            intelligence['ip'] = {
                'geolocation': ip_intel.get('geolocation', {}),
                'asn_info': ip_intel.get('asn_info', {}),
                'reputation_scores': ip_intel.get('reputation_scores', {}),
                'passive_dns': ip_intel.get('passive_dns', {}),
                'port_correlations': ip_intel.get('port_correlations', {}),
                'threat_intelligence': ip_intel.get('threat_intelligence', {})
            }
        
        # Digital footprint
        footprint_intel = correlated_data.get('digital_footprint', {})
        if footprint_intel:
            intelligence['digital_footprint'] = {
                'breach_analysis': footprint_intel.get('breach_analysis', {}),
                'social_media': footprint_intel.get('platforms', {}),
                'repositories': footprint_intel.get('repositories', []),
                'professional_networks': footprint_intel.get('professional_networks', {}),
                'threat_profile': footprint_intel.get('threat_profile', {})
            }
        
        # Pattern analysis
        pattern_analysis = correlated_data.get('pattern_analysis', {})
        if pattern_analysis:
            intelligence['patterns'] = pattern_analysis
        
        # Threat indicators
        threat_indicators = correlated_data.get('threat_indicators', [])
        if threat_indicators:
            intelligence['threat_indicators'] = threat_indicators
        
        # Intelligence summary
        intelligence_summary = correlated_data.get('intelligence_summary', {})
        if intelligence_summary:
            intelligence['summary'] = intelligence_summary
        
        return intelligence

    async def _create_summary_file(self, results: List[Dict[str, Any]], output_dir: Path, timestamp: str) -> None:
        """Create a summary file with aggregated statistics."""
        try:
            summary = {
                'metadata': {
                    'generated_at': datetime.utcnow().isoformat(),
                    'total_targets': len(results),
                    'successful_scans': len([r for r in results if 'error' not in r]),
                    'failed_scans': len([r for r in results if 'error' in r])
                },
                'statistics': self._calculate_statistics(results),
                'risk_distribution': self._calculate_risk_distribution(results),
                'top_findings': self._extract_top_findings(results)
            }
            
            summary_file = output_dir / f"reconnaissance_summary_{timestamp}.json"
            with open(summary_file, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, default=str)
            
            self.logger.info(f"Summary file created: {summary_file}")
            
        except Exception as e:
            self.logger.error(f"Error creating summary file: {e}")

    def _calculate_statistics(self, results: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate statistics from results."""
        stats = {
            'total_vulnerabilities': 0,
            'critical_vulnerabilities': 0,
            'high_vulnerabilities': 0,
            'medium_vulnerabilities': 0,
            'low_vulnerabilities': 0,
            'total_breaches': 0,
            'domains_with_subdomains': 0,
            'ips_with_reputation_issues': 0,
            'social_media_accounts': 0,
            'code_repositories': 0
        }
        
        for result in results:
            if 'error' in result:
                continue
            
            # Vulnerability statistics
            correlated_data = result.get('correlated_data', {})
            domain_intel = correlated_data.get('domain_intelligence', {})
            vulnerabilities = domain_intel.get('vulnerabilities', {})
            
            stats['total_vulnerabilities'] += vulnerabilities.get('vulnerability_count', 0)
            stats['critical_vulnerabilities'] += vulnerabilities.get('critical_count', 0)
            stats['high_vulnerabilities'] += vulnerabilities.get('high_count', 0)
            stats['medium_vulnerabilities'] += vulnerabilities.get('medium_count', 0)
            stats['low_vulnerabilities'] += vulnerabilities.get('low_count', 0)
            
            # Subdomain statistics
            subdomains = domain_intel.get('subdomains', [])
            if subdomains:
                stats['domains_with_subdomains'] += 1
            
            # Breach statistics
            footprint_intel = correlated_data.get('digital_footprint', {})
            breach_analysis = footprint_intel.get('breach_analysis', {})
            stats['total_breaches'] += breach_analysis.get('breach_count', 0)
            
            # Social media statistics
            platforms = footprint_intel.get('platforms', {})
            active_platforms = len([p for p in platforms.values() if p.get('exists')])
            stats['social_media_accounts'] += active_platforms
            
            # Repository statistics
            repositories = footprint_intel.get('repositories', [])
            stats['code_repositories'] += len(repositories)
            
            # IP reputation statistics
            ip_intel = correlated_data.get('ip_intelligence', {})
            reputation_scores = ip_intel.get('reputation_scores', {})
            if reputation_scores:
                malicious_count = sum(
                    score.get('malicious_count', 0) 
                    for score in reputation_scores.values()
                )
                if malicious_count > 0:
                    stats['ips_with_reputation_issues'] += 1
        
        return stats

    def _calculate_risk_distribution(self, results: List[Dict[str, Any]]) -> Dict[str, int]:
        """Calculate risk level distribution."""
        risk_distribution = {
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'unknown': 0
        }
        
        for result in results:
            if 'error' in result:
                risk_distribution['unknown'] += 1
                continue
            
            attack_surface = result.get('attack_surface', {})
            risk_level = attack_surface.get('risk_level', 'unknown')
            risk_distribution[risk_level] = risk_distribution.get(risk_level, 0) + 1
        
        return risk_distribution

    def _extract_top_findings(self, results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Extract top findings across all results."""
        findings = []
        
        for result in results:
            if 'error' in result:
                continue
            
            # High-risk findings
            attack_surface = result.get('attack_surface', {})
            if attack_surface.get('risk_level') in ['critical', 'high']:
                findings.append({
                    'target': result.get('input_value', ''),
                    'finding': f"High risk level: {attack_surface.get('risk_level')}",
                    'severity': attack_surface.get('risk_level'),
                    'attack_surface_score': attack_surface.get('attack_surface_score', 0)
                })
            
            # Critical vulnerabilities
            correlated_data = result.get('correlated_data', {})
            domain_intel = correlated_data.get('domain_intelligence', {})
            vulnerabilities = domain_intel.get('vulnerabilities', {})
            
            if vulnerabilities.get('critical_count', 0) > 0:
                findings.append({
                    'target': result.get('input_value', ''),
                    'finding': f"Critical vulnerabilities: {vulnerabilities['critical_count']}",
                    'severity': 'critical',
                    'attack_surface_score': attack_surface.get('attack_surface_score', 0)
                })
            
            # Multiple breaches
            footprint_intel = correlated_data.get('digital_footprint', {})
            breach_analysis = footprint_intel.get('breach_analysis', {})
            
            if breach_analysis.get('breach_count', 0) > 3:
                findings.append({
                    'target': result.get('input_value', ''),
                    'finding': f"Multiple data breaches: {breach_analysis['breach_count']}",
                    'severity': 'high',
                    'attack_surface_score': attack_surface.get('attack_surface_score', 0)
                })
        
        # Sort by severity and attack surface score
        severity_order = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1}
        findings.sort(
            key=lambda x: (severity_order.get(x.get('severity', 'unknown'), 0), x.get('attack_surface_score', 0)),
            reverse=True
        )
        
        return findings[:10]  # Return top 10 findings
