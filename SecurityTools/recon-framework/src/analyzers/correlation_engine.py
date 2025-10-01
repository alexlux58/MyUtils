"""
Correlation Engine
Correlates data from multiple sources to identify patterns and relationships.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime
import re


class CorrelationEngine:
    """Correlates data from multiple intelligence sources."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the correlation engine."""
        self.config = config
        self.logger = logging.getLogger(__name__)

    def correlate_findings(
        self, 
        base_data: Dict[str, Any], 
        enhanced_data: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Correlate findings from base and enhanced data collection."""
        self.logger.info("Correlating findings from multiple data sources")
        
        correlated_data = {
            'correlation_metadata': {
                'correlation_timestamp': datetime.utcnow().isoformat(),
                'base_data_sources': len(base_data),
                'enhanced_data_sources': len(enhanced_data),
                'correlation_confidence': 0.0
            },
            'correlated_findings': {},
            'pattern_analysis': {},
            'relationship_mapping': {},
            'threat_indicators': [],
            'intelligence_summary': {}
        }

        try:
            # Merge base and enhanced data
            merged_data = self._merge_data_sources(base_data, enhanced_data)
            correlated_data['correlated_findings'] = merged_data
            
            # Perform pattern analysis
            correlated_data['pattern_analysis'] = self._analyze_patterns(merged_data)
            
            # Map relationships
            correlated_data['relationship_mapping'] = self._map_relationships(merged_data)
            
            # Identify threat indicators
            correlated_data['threat_indicators'] = self._identify_threat_indicators(merged_data)
            
            # Generate intelligence summary
            correlated_data['intelligence_summary'] = self._generate_intelligence_summary(
                merged_data, correlated_data['pattern_analysis']
            )
            
            # Calculate correlation confidence
            correlated_data['correlation_metadata']['correlation_confidence'] = self._calculate_correlation_confidence(
                merged_data, correlated_data['pattern_analysis']
            )

        except Exception as e:
            self.logger.error(f"Data correlation error: {e}")
            correlated_data['error'] = str(e)

        return correlated_data

    def _merge_data_sources(self, base_data: Dict[str, Any], enhanced_data: Dict[str, Any]) -> Dict[str, Any]:
        """Merge data from base and enhanced collection."""
        merged_data = {}
        
        # Merge domain intelligence
        domain_data = {}
        if 'domain_intelligence' in base_data:
            domain_data.update(base_data['domain_intelligence'])
        if 'domain_intelligence' in enhanced_data:
            domain_data.update(enhanced_data['domain_intelligence'])
        if domain_data:
            merged_data['domain_intelligence'] = domain_data
        
        # Merge IP intelligence
        ip_data = {}
        if 'ip_intelligence' in base_data:
            ip_data.update(base_data['ip_intelligence'])
        if 'ip_intelligence' in enhanced_data:
            ip_data.update(enhanced_data['ip_intelligence'])
        if ip_data:
            merged_data['ip_intelligence'] = ip_data
        
        # Merge digital footprint
        footprint_data = {}
        if 'digital_footprint' in base_data:
            footprint_data.update(base_data['digital_footprint'])
        if 'digital_footprint' in enhanced_data:
            footprint_data.update(enhanced_data['digital_footprint'])
        if footprint_data:
            merged_data['digital_footprint'] = footprint_data
        
        # Add metadata
        merged_data['merge_metadata'] = {
            'base_collection_timestamp': base_data.get('collection_timestamp'),
            'enhanced_collection_timestamp': enhanced_data.get('collection_timestamp'),
            'data_freshness': self._calculate_data_freshness(base_data, enhanced_data)
        }
        
        return merged_data

    def _analyze_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze patterns across data sources."""
        patterns = {
            'temporal_patterns': {},
            'geographic_patterns': {},
            'technical_patterns': {},
            'behavioral_patterns': {},
            'security_patterns': {}
        }
        
        # Temporal patterns
        patterns['temporal_patterns'] = self._analyze_temporal_patterns(data)
        
        # Geographic patterns
        patterns['geographic_patterns'] = self._analyze_geographic_patterns(data)
        
        # Technical patterns
        patterns['technical_patterns'] = self._analyze_technical_patterns(data)
        
        # Behavioral patterns
        patterns['behavioral_patterns'] = self._analyze_behavioral_patterns(data)
        
        # Security patterns
        patterns['security_patterns'] = self._analyze_security_patterns(data)
        
        return patterns

    def _map_relationships(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map relationships between different data points."""
        relationships = {
            'domain_ip_relationships': {},
            'social_technical_correlations': {},
            'breach_vulnerability_links': {},
            'network_infrastructure_mapping': {}
        }
        
        # Domain-IP relationships
        relationships['domain_ip_relationships'] = self._map_domain_ip_relationships(data)
        
        # Social-technical correlations
        relationships['social_technical_correlations'] = self._map_social_technical_correlations(data)
        
        # Breach-vulnerability links
        relationships['breach_vulnerability_links'] = self._map_breach_vulnerability_links(data)
        
        # Network infrastructure mapping
        relationships['network_infrastructure_mapping'] = self._map_network_infrastructure(data)
        
        return relationships

    def _identify_threat_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify threat indicators from correlated data."""
        threat_indicators = []
        
        # High-risk indicators
        threat_indicators.extend(self._identify_high_risk_indicators(data))
        
        # Medium-risk indicators
        threat_indicators.extend(self._identify_medium_risk_indicators(data))
        
        # Low-risk indicators
        threat_indicators.extend(self._identify_low_risk_indicators(data))
        
        return threat_indicators

    def _generate_intelligence_summary(self, data: Dict[str, Any], patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Generate comprehensive intelligence summary."""
        summary = {
            'executive_summary': '',
            'key_findings': [],
            'risk_assessment': {},
            'recommendations': [],
            'intelligence_gaps': []
        }
        
        # Generate executive summary
        summary['executive_summary'] = self._generate_executive_summary(data, patterns)
        
        # Extract key findings
        summary['key_findings'] = self._extract_key_findings(data, patterns)
        
        # Risk assessment
        summary['risk_assessment'] = self._assess_overall_risk(data, patterns)
        
        # Recommendations
        summary['recommendations'] = self._generate_recommendations(data, patterns)
        
        # Intelligence gaps
        summary['intelligence_gaps'] = self._identify_intelligence_gaps(data)
        
        return summary

    def _calculate_data_freshness(self, base_data: Dict[str, Any], enhanced_data: Dict[str, Any]) -> str:
        """Calculate data freshness score."""
        base_timestamp = base_data.get('collection_timestamp')
        enhanced_timestamp = enhanced_data.get('collection_timestamp')
        
        if not base_timestamp and not enhanced_timestamp:
            return 'unknown'
        
        # Simple freshness calculation based on timestamps
        if enhanced_timestamp:
            return 'fresh'
        elif base_timestamp:
            return 'moderate'
        else:
            return 'stale'

    def _analyze_temporal_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze temporal patterns in the data."""
        temporal_patterns = {
            'activity_timeline': [],
            'peak_activity_periods': [],
            'temporal_correlations': []
        }
        
        # Analyze domain creation and expiration dates
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            whois_info = domain_data.get('whois_info', {})
            
            creation_date = whois_info.get('creation_date')
            expiration_date = whois_info.get('expiration_date')
            
            if creation_date:
                temporal_patterns['activity_timeline'].append({
                    'event': 'domain_created',
                    'timestamp': creation_date,
                    'type': 'domain_lifecycle'
                })
            
            if expiration_date:
                temporal_patterns['activity_timeline'].append({
                    'event': 'domain_expires',
                    'timestamp': expiration_date,
                    'type': 'domain_lifecycle'
                })
        
        # Analyze breach timeline
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            breach_analysis = footprint_data.get('breach_analysis', {})
            breach_timeline = breach_analysis.get('breach_timeline', [])
            
            for breach in breach_timeline:
                temporal_patterns['activity_timeline'].append({
                    'event': 'data_breach',
                    'timestamp': breach.get('breach_date'),
                    'type': 'security_incident',
                    'severity': 'high'
                })
        
        return temporal_patterns

    def _analyze_geographic_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze geographic patterns in the data."""
        geographic_patterns = {
            'primary_locations': [],
            'geographic_risks': [],
            'location_correlations': []
        }
        
        # Analyze IP geolocation
        if 'ip_intelligence' in data:
            ip_data = data['ip_intelligence']
            geolocation = ip_data.get('geolocation', {})
            
            if geolocation:
                location = {
                    'country': geolocation.get('country', 'Unknown'),
                    'region': geolocation.get('region', 'Unknown'),
                    'city': geolocation.get('city', 'Unknown'),
                    'coordinates': {
                        'latitude': geolocation.get('latitude', 0),
                        'longitude': geolocation.get('longitude', 0)
                    }
                }
                geographic_patterns['primary_locations'].append(location)
                
                # Assess geographic risks
                country_code = geolocation.get('country_code', '').lower()
                if country_code in ['cn', 'ru', 'kp', 'ir']:
                    geographic_patterns['geographic_risks'].append({
                        'location': location,
                        'risk_level': 'high',
                        'risk_factors': ['State-sponsored activity', 'Data sovereignty concerns']
                    })
        
        return geographic_patterns

    def _analyze_technical_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze technical patterns in the data."""
        technical_patterns = {
            'technology_stack': {},
            'security_configurations': {},
            'vulnerability_patterns': {},
            'infrastructure_patterns': {}
        }
        
        # Analyze technology stack
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            tech_stack = domain_data.get('technology_stack', {})
            if tech_stack:
                technical_patterns['technology_stack'] = tech_stack
        
        # Analyze security configurations
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            security_headers = domain_data.get('security_headers', {})
            if security_headers:
                technical_patterns['security_configurations'] = {
                    'present_headers': security_headers.get('present_headers', []),
                    'missing_headers': security_headers.get('missing_headers', []),
                    'security_score': security_headers.get('security_score', 0)
                }
        
        # Analyze vulnerability patterns
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            vulnerabilities = domain_data.get('vulnerabilities', {})
            if vulnerabilities:
                technical_patterns['vulnerability_patterns'] = {
                    'total_vulnerabilities': vulnerabilities.get('vulnerability_count', 0),
                    'severity_distribution': {
                        'critical': vulnerabilities.get('critical_count', 0),
                        'high': vulnerabilities.get('high_count', 0),
                        'medium': vulnerabilities.get('medium_count', 0),
                        'low': vulnerabilities.get('low_count', 0)
                    }
                }
        
        return technical_patterns

    def _analyze_behavioral_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze behavioral patterns in the data."""
        behavioral_patterns = {
            'social_media_activity': {},
            'professional_behavior': {},
            'communication_patterns': {},
            'digital_footprint_analysis': {}
        }
        
        # Analyze social media activity
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            platforms = footprint_data.get('platforms', {})
            
            active_platforms = [p for p in platforms.values() if p.get('exists')]
            behavioral_patterns['social_media_activity'] = {
                'platform_count': len(active_platforms),
                'platforms': [p['platform'] for p in active_platforms],
                'activity_level': 'high' if len(active_platforms) > 3 else 'medium' if len(active_platforms) > 1 else 'low'
            }
        
        # Analyze professional behavior
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            professional_data = footprint_data.get('professional_networks', {})
            
            behavioral_patterns['professional_behavior'] = {
                'linkedin_presence': professional_data.get('linkedin_analysis', {}).get('profile_exists', False),
                'professional_indicators': professional_data.get('professional_indicators', [])
            }
        
        return behavioral_patterns

    def _analyze_security_patterns(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze security patterns in the data."""
        security_patterns = {
            'breach_patterns': {},
            'vulnerability_patterns': {},
            'security_control_gaps': {},
            'threat_landscape': {}
        }
        
        # Analyze breach patterns
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            breach_analysis = footprint_data.get('breach_analysis', {})
            
            security_patterns['breach_patterns'] = {
                'breach_count': breach_analysis.get('breach_count', 0),
                'exposed_data_types': breach_analysis.get('exposed_data', []),
                'risk_level': breach_analysis.get('risk_assessment', {}).get('risk_level', 'unknown')
            }
        
        # Analyze vulnerability patterns
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            vulnerabilities = domain_data.get('vulnerabilities', {})
            
            security_patterns['vulnerability_patterns'] = {
                'total_vulnerabilities': vulnerabilities.get('vulnerability_count', 0),
                'critical_vulnerabilities': vulnerabilities.get('critical_count', 0),
                'vulnerability_types': [v.get('type') for v in vulnerabilities.get('vulnerabilities', [])]
            }
        
        return security_patterns

    def _map_domain_ip_relationships(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map relationships between domains and IP addresses."""
        relationships = {
            'domain_ip_mappings': [],
            'infrastructure_analysis': {},
            'hosting_relationships': {}
        }
        
        # Extract domain-IP mappings
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            dns_records = domain_data.get('dns_records', {})
            
            a_records = dns_records.get('A', [])
            aaaa_records = dns_records.get('AAAA', [])
            
            relationships['domain_ip_mappings'] = {
                'ipv4_addresses': a_records,
                'ipv6_addresses': aaaa_records
            }
        
        return relationships

    def _map_social_technical_correlations(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map correlations between social and technical data."""
        correlations = {
            'social_technical_links': [],
            'credential_reuse_indicators': [],
            'attack_surface_correlations': {}
        }
        
        # Check for email addresses in technical data
        if 'digital_footprint' in data and 'domain_intelligence' in data:
            footprint_data = data['digital_footprint']
            domain_data = data['domain_intelligence']
            
            if footprint_data.get('identifier_type') == 'email':
                email = footprint_data.get('identifier', '')
                domain = email.split('@')[1] if '@' in email else ''
                
                if domain:
                    correlations['social_technical_links'].append({
                        'type': 'email_domain_correlation',
                        'email': email,
                        'domain': domain,
                        'correlation_strength': 'high'
                    })
        
        return correlations

    def _map_breach_vulnerability_links(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map links between breach data and vulnerabilities."""
        links = {
            'breach_vulnerability_correlations': [],
            'credential_exposure_risks': [],
            'attack_chain_indicators': []
        }
        
        # Check for breach data and vulnerabilities
        if 'digital_footprint' in data and 'domain_intelligence' in data:
            footprint_data = data['digital_footprint']
            domain_data = data['domain_intelligence']
            
            breach_count = footprint_data.get('breach_analysis', {}).get('breach_count', 0)
            vuln_count = domain_data.get('vulnerabilities', {}).get('vulnerability_count', 0)
            
            if breach_count > 0 and vuln_count > 0:
                links['breach_vulnerability_correlations'].append({
                    'type': 'breach_vulnerability_correlation',
                    'breach_count': breach_count,
                    'vulnerability_count': vuln_count,
                    'risk_multiplier': 'high',
                    'description': 'Both breach data and vulnerabilities present - high risk combination'
                })
        
        return links

    def _map_network_infrastructure(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Map network infrastructure relationships."""
        infrastructure = {
            'network_mapping': {},
            'hosting_analysis': {},
            'infrastructure_risks': []
        }
        
        # Analyze IP infrastructure
        if 'ip_intelligence' in data:
            ip_data = data['ip_intelligence']
            asn_info = ip_data.get('asn_info', {})
            isp_info = ip_data.get('isp_info', {})
            
            infrastructure['network_mapping'] = {
                'asn': asn_info.get('asn', 'Unknown'),
                'asn_name': asn_info.get('asn_name', 'Unknown'),
                'isp': isp_info.get('isp', 'Unknown'),
                'isp_type': isp_info.get('isp_type', 'Unknown')
            }
        
        return infrastructure

    def _identify_high_risk_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify high-risk threat indicators."""
        indicators = []
        
        # Critical vulnerabilities
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            vulnerabilities = domain_data.get('vulnerabilities', {})
            if vulnerabilities.get('critical_count', 0) > 0:
                indicators.append({
                    'indicator': 'Critical vulnerabilities present',
                    'risk_level': 'high',
                    'description': f"{vulnerabilities['critical_count']} critical vulnerabilities detected",
                    'mitigation': 'Immediate patching required'
                })
        
        # Multiple data breaches
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            breach_analysis = footprint_data.get('breach_analysis', {})
            if breach_analysis.get('breach_count', 0) > 5:
                indicators.append({
                    'indicator': 'Multiple data breaches',
                    'risk_level': 'high',
                    'description': f"Account found in {breach_analysis['breach_count']} data breaches",
                    'mitigation': 'Implement strong authentication and monitoring'
                })
        
        return indicators

    def _identify_medium_risk_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify medium-risk threat indicators."""
        indicators = []
        
        # Missing security headers
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            security_headers = domain_data.get('security_headers', {})
            missing_headers = security_headers.get('missing_headers', [])
            if len(missing_headers) > 3:
                indicators.append({
                    'indicator': 'Multiple missing security headers',
                    'risk_level': 'medium',
                    'description': f"{len(missing_headers)} security headers missing",
                    'mitigation': 'Implement missing security headers'
                })
        
        return indicators

    def _identify_low_risk_indicators(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify low-risk threat indicators."""
        indicators = []
        
        # Limited social media presence
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            platforms = footprint_data.get('platforms', {})
            active_platforms = len([p for p in platforms.values() if p.get('exists')])
            if active_platforms == 0:
                indicators.append({
                    'indicator': 'No social media presence',
                    'risk_level': 'low',
                    'description': 'Limited digital footprint',
                    'mitigation': 'Monitor for new account creation'
                })
        
        return indicators

    def _generate_executive_summary(self, data: Dict[str, Any], patterns: Dict[str, Any]) -> str:
        """Generate executive summary of findings."""
        summary_parts = []
        
        # Overall risk assessment
        threat_indicators = self._identify_threat_indicators(data)
        high_risk_count = len([i for i in threat_indicators if i.get('risk_level') == 'high'])
        
        if high_risk_count > 0:
            summary_parts.append(f"High-risk indicators detected: {high_risk_count} critical findings require immediate attention.")
        else:
            summary_parts.append("No critical security issues detected in current assessment.")
        
        # Key findings
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            vulnerabilities = domain_data.get('vulnerabilities', {})
            vuln_count = vulnerabilities.get('vulnerability_count', 0)
            if vuln_count > 0:
                summary_parts.append(f"Vulnerability assessment identified {vuln_count} security issues.")
        
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            breach_analysis = footprint_data.get('breach_analysis', {})
            breach_count = breach_analysis.get('breach_count', 0)
            if breach_count > 0:
                summary_parts.append(f"Digital footprint analysis revealed exposure in {breach_count} data breaches.")
        
        return " ".join(summary_parts) if summary_parts else "Assessment completed with no significant findings."

    def _extract_key_findings(self, data: Dict[str, Any], patterns: Dict[str, Any]) -> List[str]:
        """Extract key findings from the data."""
        findings = []
        
        # Domain findings
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            
            # Security headers
            security_headers = domain_data.get('security_headers', {})
            missing_headers = security_headers.get('missing_headers', [])
            if missing_headers:
                findings.append(f"Missing security headers: {', '.join([h['header'] for h in missing_headers])}")
            
            # Vulnerabilities
            vulnerabilities = domain_data.get('vulnerabilities', {})
            vuln_count = vulnerabilities.get('vulnerability_count', 0)
            if vuln_count > 0:
                findings.append(f"Security vulnerabilities detected: {vuln_count} total issues")
        
        # IP findings
        if 'ip_intelligence' in data:
            ip_data = data['ip_intelligence']
            geolocation = ip_data.get('geolocation', {})
            if geolocation:
                country = geolocation.get('country', 'Unknown')
                findings.append(f"Primary location: {country}")
        
        # Digital footprint findings
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            breach_analysis = footprint_data.get('breach_analysis', {})
            breach_count = breach_analysis.get('breach_count', 0)
            if breach_count > 0:
                findings.append(f"Data breach exposure: {breach_count} breaches affecting this identifier")
        
        return findings

    def _assess_overall_risk(self, data: Dict[str, Any], patterns: Dict[str, Any]) -> Dict[str, Any]:
        """Assess overall risk level."""
        threat_indicators = self._identify_threat_indicators(data)
        
        high_risk_count = len([i for i in threat_indicators if i.get('risk_level') == 'high'])
        medium_risk_count = len([i for i in threat_indicators if i.get('risk_level') == 'medium'])
        low_risk_count = len([i for i in threat_indicators if i.get('risk_level') == 'low'])
        
        if high_risk_count > 0:
            risk_level = 'high'
        elif medium_risk_count > 2:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'overall_risk': risk_level,
            'risk_factors': {
                'high_risk_indicators': high_risk_count,
                'medium_risk_indicators': medium_risk_count,
                'low_risk_indicators': low_risk_count
            },
            'confidence': 0.8  # Would be calculated based on data quality
        }

    def _generate_recommendations(self, data: Dict[str, Any], patterns: Dict[str, Any]) -> List[str]:
        """Generate recommendations based on findings."""
        recommendations = []
        
        # Security recommendations
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            security_headers = domain_data.get('security_headers', {})
            missing_headers = security_headers.get('missing_headers', [])
            if missing_headers:
                recommendations.append("Implement missing security headers to improve web security posture")
            
            vulnerabilities = domain_data.get('vulnerabilities', {})
            if vulnerabilities.get('vulnerability_count', 0) > 0:
                recommendations.append("Address identified vulnerabilities through patching and security updates")
        
        # Digital footprint recommendations
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            breach_analysis = footprint_data.get('breach_analysis', {})
            if breach_analysis.get('breach_count', 0) > 0:
                recommendations.append("Implement strong authentication and monitor for credential reuse")
        
        return recommendations

    def _identify_intelligence_gaps(self, data: Dict[str, Any]) -> List[str]:
        """Identify gaps in intelligence collection."""
        gaps = []
        
        # Check for missing data sources
        if 'domain_intelligence' not in data:
            gaps.append("Domain intelligence data not available")
        
        if 'ip_intelligence' not in data:
            gaps.append("IP intelligence data not available")
        
        if 'digital_footprint' not in data:
            gaps.append("Digital footprint data not available")
        
        return gaps

    def _calculate_correlation_confidence(self, data: Dict[str, Any], patterns: Dict[str, Any]) -> float:
        """Calculate confidence in correlation analysis."""
        # Simple confidence calculation based on data completeness
        data_sources = len([k for k in data.keys() if k != 'merge_metadata'])
        max_sources = 3  # domain, ip, digital_footprint
        
        base_confidence = data_sources / max_sources
        
        # Adjust based on pattern quality
        pattern_quality = len([k for k in patterns.keys() if patterns[k]])
        pattern_confidence = pattern_quality / len(patterns)
        
        return (base_confidence + pattern_confidence) / 2
