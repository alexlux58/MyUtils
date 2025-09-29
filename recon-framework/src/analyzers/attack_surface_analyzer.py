"""
Attack Surface Analyzer
Analyzes collected data to identify attack vectors and calculate risk scores.
"""

import logging
from typing import Dict, List, Any, Optional
from datetime import datetime


class AttackSurfaceAnalyzer:
    """Analyzes attack surface and generates risk assessments."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the attack surface analyzer."""
        self.config = config
        self.logger = logging.getLogger(__name__)

    def analyze(self, correlated_data: Dict[str, Any], sensitivity_level: str) -> Dict[str, Any]:
        """Analyze attack surface and generate comprehensive risk assessment."""
        self.logger.info("Analyzing attack surface and generating risk assessment")
        
        analysis = {
            'attack_surface_score': 0,
            'risk_level': 'unknown',
            'attack_vectors': [],
            'initial_access_vectors': [],
            'password_spray_candidates': [],
            'phishing_risk_level': 'low',
            'defensive_recommendations': [],
            'mitre_attack_mapping': [],
            'priority_actions': [],
            'analysis_timestamp': datetime.utcnow().isoformat()
        }

        try:
            # Calculate attack surface score
            analysis['attack_surface_score'] = self._calculate_attack_surface_score(
                correlated_data, sensitivity_level
            )
            
            # Determine risk level
            analysis['risk_level'] = self._determine_risk_level(analysis['attack_surface_score'])
            
            # Identify attack vectors
            analysis['attack_vectors'] = self._identify_attack_vectors(correlated_data)
            
            # Identify initial access vectors
            analysis['initial_access_vectors'] = self._identify_initial_access_vectors(
                correlated_data, analysis['attack_vectors']
            )
            
            # Generate password spray candidates
            analysis['password_spray_candidates'] = self._generate_password_spray_candidates(
                correlated_data
            )
            
            # Assess phishing risk
            analysis['phishing_risk_level'] = self._assess_phishing_risk(correlated_data)
            
            # Generate defensive recommendations
            analysis['defensive_recommendations'] = self._generate_defensive_recommendations(
                correlated_data, analysis['attack_vectors']
            )
            
            # Map to MITRE ATT&CK
            analysis['mitre_attack_mapping'] = self._map_to_mitre_attack(
                analysis['attack_vectors']
            )
            
            # Generate priority actions
            analysis['priority_actions'] = self._generate_priority_actions(
                analysis['attack_vectors'], analysis['risk_level']
            )

        except Exception as e:
            self.logger.error(f"Attack surface analysis error: {e}")
            analysis['error'] = str(e)

        return analysis

    def _calculate_attack_surface_score(self, data: Dict[str, Any], sensitivity_level: str) -> int:
        """Calculate attack surface score (1-10)."""
        score = 0
        
        # Base score from sensitivity level
        sensitivity_scores = {'public': 1, 'low': 2, 'med': 4, 'high': 6}
        score += sensitivity_scores.get(sensitivity_level, 2)
        
        # Domain-specific factors
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            
            # Subdomain count (more subdomains = larger attack surface)
            subdomains = domain_data.get('subdomains', [])
            score += min(len(subdomains) * 0.5, 2)
            
            # Security headers (missing headers = higher risk)
            security_headers = domain_data.get('security_headers', {})
            missing_headers = security_headers.get('missing_headers', [])
            score += min(len(missing_headers) * 0.3, 1.5)
            
            # Vulnerabilities
            vulnerabilities = domain_data.get('vulnerabilities', {})
            vuln_count = vulnerabilities.get('vulnerability_count', 0)
            score += min(vuln_count * 0.5, 2)
        
        # IP-specific factors
        if 'ip_intelligence' in data:
            ip_data = data['ip_intelligence']
            
            # Reputation score
            reputation = ip_data.get('reputation_scores', {})
            if reputation:
                malicious_count = sum(
                    score.get('malicious_count', 0) 
                    for score in reputation.values()
                )
                score += min(malicious_count * 0.3, 1.5)
        
        # Digital footprint factors
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            
            # Breach data
            breach_analysis = footprint_data.get('breach_analysis', {})
            breach_count = breach_analysis.get('breach_count', 0)
            score += min(breach_count * 0.2, 1)
            
            # Social media presence (more platforms = more attack surface)
            platforms = footprint_data.get('platforms', {})
            active_platforms = len([p for p in platforms.values() if p.get('exists')])
            score += min(active_platforms * 0.1, 0.5)
        
        # Cap at 10
        return min(int(score), 10)

    def _determine_risk_level(self, attack_surface_score: int) -> str:
        """Determine risk level based on attack surface score."""
        if attack_surface_score >= 8:
            return 'critical'
        elif attack_surface_score >= 6:
            return 'high'
        elif attack_surface_score >= 4:
            return 'medium'
        else:
            return 'low'

    def _identify_attack_vectors(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Identify potential attack vectors from collected data."""
        attack_vectors = []
        
        # Web application attack vectors
        if 'domain_intelligence' in data:
            domain_data = data['domain_intelligence']
            
            # Missing security headers
            security_headers = domain_data.get('security_headers', {})
            missing_headers = security_headers.get('missing_headers', [])
            for header in missing_headers:
                attack_vectors.append({
                    'vector_type': 'web_security',
                    'name': f"Missing {header['header']}",
                    'severity': 'medium',
                    'description': f"Missing {header['description']} header",
                    'mitigation': f"Implement {header['header']} header"
                })
            
            # Vulnerabilities
            vulnerabilities = domain_data.get('vulnerabilities', {})
            vuln_list = vulnerabilities.get('vulnerabilities', [])
            for vuln in vuln_list:
                attack_vectors.append({
                    'vector_type': 'vulnerability',
                    'name': vuln.get('type', 'Unknown Vulnerability'),
                    'severity': vuln.get('severity', 'unknown'),
                    'description': vuln.get('description', ''),
                    'mitigation': 'Apply security patches and updates'
                })
        
        # Network attack vectors
        if 'ip_intelligence' in data:
            ip_data = data['ip_intelligence']
            
            # Open ports (if detected)
            port_analysis = ip_data.get('port_correlations', {})
            common_services = port_analysis.get('common_services', [])
            for service in common_services:
                if service.get('likelihood') == 'high':
                    attack_vectors.append({
                        'vector_type': 'network_service',
                        'name': f"Exposed {service['service']}",
                        'severity': 'medium',
                        'description': f"Port {service['port']} ({service['service']}) likely exposed",
                        'mitigation': 'Review port exposure and implement access controls'
                    })
        
        # Social engineering attack vectors
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            
            # Breach data
            breach_analysis = footprint_data.get('breach_analysis', {})
            if breach_analysis.get('breach_count', 0) > 0:
                attack_vectors.append({
                    'vector_type': 'social_engineering',
                    'name': 'Credential Reuse',
                    'severity': 'high',
                    'description': 'Account found in data breaches - potential credential reuse',
                    'mitigation': 'Implement password policies and MFA'
                })
            
            # Social media presence
            platforms = footprint_data.get('platforms', {})
            active_platforms = [p for p in platforms.values() if p.get('exists')]
            if len(active_platforms) > 3:
                attack_vectors.append({
                    'vector_type': 'social_engineering',
                    'name': 'Social Media Reconnaissance',
                    'severity': 'medium',
                    'description': 'Extensive social media presence for reconnaissance',
                    'mitigation': 'Review privacy settings and limit public information'
                })
        
        return attack_vectors

    def _identify_initial_access_vectors(self, data: Dict[str, Any], attack_vectors: List[Dict]) -> List[str]:
        """Identify initial access vectors for red team operations."""
        initial_access = []
        
        # Web-based initial access
        web_vectors = [v for v in attack_vectors if v['vector_type'] == 'web_security']
        if web_vectors:
            initial_access.append('Web Application Exploitation')
        
        # Vulnerability-based initial access
        vuln_vectors = [v for v in attack_vectors if v['vector_type'] == 'vulnerability']
        if vuln_vectors:
            initial_access.append('Vulnerability Exploitation')
        
        # Social engineering initial access
        se_vectors = [v for v in attack_vectors if v['vector_type'] == 'social_engineering']
        if se_vectors:
            initial_access.append('Social Engineering')
        
        # Network-based initial access
        network_vectors = [v for v in attack_vectors if v['vector_type'] == 'network_service']
        if network_vectors:
            initial_access.append('Network Service Exploitation')
        
        # Email-based initial access
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            if footprint_data.get('identifier_type') == 'email':
                initial_access.append('Email-based Attacks')
        
        return initial_access

    def _generate_password_spray_candidates(self, data: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Generate password spray candidates from breach data."""
        candidates = []
        
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            breach_analysis = footprint_data.get('breach_analysis', {})
            
            if breach_analysis.get('breach_count', 0) > 0:
                # Extract common passwords from breach data
                breach_timeline = breach_analysis.get('breach_timeline', [])
                for breach in breach_timeline:
                    if 'password' in breach.get('data_classes', []):
                        candidates.append({
                            'source': breach.get('breach_name', 'Unknown'),
                            'breach_date': breach.get('breach_date', 'Unknown'),
                            'password_patterns': ['common_passwords', 'company_name_variations'],
                            'target_accounts': ['email_accounts', 'social_media_accounts']
                        })
        
        return candidates

    def _assess_phishing_risk(self, data: Dict[str, Any]) -> str:
        """Assess phishing risk level."""
        risk_factors = 0
        
        # Email address availability
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            if footprint_data.get('identifier_type') == 'email':
                risk_factors += 1
        
        # Social media presence
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            platforms = footprint_data.get('platforms', {})
            active_platforms = len([p for p in platforms.values() if p.get('exists')])
            if active_platforms > 2:
                risk_factors += 1
        
        # Professional information exposure
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            professional_data = footprint_data.get('professional_networks', {})
            if professional_data.get('linkedin_analysis', {}).get('profile_exists'):
                risk_factors += 1
        
        # Breach data
        if 'digital_footprint' in data:
            footprint_data = data['digital_footprint']
            breach_analysis = footprint_data.get('breach_analysis', {})
            if breach_analysis.get('breach_count', 0) > 0:
                risk_factors += 1
        
        if risk_factors >= 3:
            return 'high'
        elif risk_factors >= 2:
            return 'medium'
        else:
            return 'low'

    def _generate_defensive_recommendations(self, data: Dict[str, Any], attack_vectors: List[Dict]) -> List[Dict[str, Any]]:
        """Generate defensive recommendations based on findings."""
        recommendations = []
        
        # Immediate actions (24-48 hours)
        immediate_actions = []
        
        # High severity vulnerabilities
        high_severity = [v for v in attack_vectors if v.get('severity') == 'high']
        if high_severity:
            immediate_actions.append({
                'action': 'Address high-severity vulnerabilities',
                'timeline': '24-48 hours',
                'priority': 'critical',
                'description': f'Fix {len(high_severity)} high-severity issues'
            })
        
        # Missing security headers
        missing_headers = [v for v in attack_vectors if 'Missing' in v.get('name', '')]
        if missing_headers:
            immediate_actions.append({
                'action': 'Implement missing security headers',
                'timeline': '24-48 hours',
                'priority': 'high',
                'description': f'Add {len(missing_headers)} missing security headers'
            })
        
        if immediate_actions:
            recommendations.append({
                'category': 'Immediate Actions (24-48 hours)',
                'actions': immediate_actions
            })
        
        # Medium-term improvements (1-4 weeks)
        medium_term_actions = []
        
        # Security header implementation
        if missing_headers:
            medium_term_actions.append({
                'action': 'Comprehensive security header implementation',
                'timeline': '1-4 weeks',
                'priority': 'high',
                'description': 'Implement all recommended security headers'
            })
        
        # Vulnerability management
        if attack_vectors:
            medium_term_actions.append({
                'action': 'Vulnerability management program',
                'timeline': '1-4 weeks',
                'priority': 'medium',
                'description': 'Establish regular vulnerability scanning and patching'
            })
        
        if medium_term_actions:
            recommendations.append({
                'category': 'Medium-term Improvements (1-4 weeks)',
                'actions': medium_term_actions
            })
        
        # Strategic changes (1-6 months)
        strategic_actions = []
        
        # Security architecture review
        strategic_actions.append({
            'action': 'Security architecture review',
            'timeline': '1-6 months',
            'priority': 'medium',
            'description': 'Review and improve overall security architecture'
        })
        
        # Monitoring and detection
        strategic_actions.append({
            'action': 'Enhanced monitoring and detection',
            'timeline': '1-6 months',
            'priority': 'medium',
            'description': 'Implement comprehensive security monitoring'
        })
        
        if strategic_actions:
            recommendations.append({
                'category': 'Strategic Changes (1-6 months)',
                'actions': strategic_actions
            })
        
        return recommendations

    def _map_to_mitre_attack(self, attack_vectors: List[Dict]) -> List[Dict[str, Any]]:
        """Map attack vectors to MITRE ATT&CK framework."""
        mitre_mapping = []
        
        for vector in attack_vectors:
            vector_type = vector.get('vector_type', '')
            name = vector.get('name', '')
            
            # Map based on vector type and name
            if vector_type == 'web_security':
                if 'XSS' in name:
                    mitre_mapping.append({
                        'attack_vector': name,
                        'mitre_technique': 'T1059.007',
                        'technique_name': 'Client-Side Code Injection',
                        'tactic': 'Initial Access'
                    })
                elif 'SQL' in name:
                    mitre_mapping.append({
                        'attack_vector': name,
                        'mitre_technique': 'T1190',
                        'technique_name': 'Exploit Public-Facing Application',
                        'tactic': 'Initial Access'
                    })
                else:
                    mitre_mapping.append({
                        'attack_vector': name,
                        'mitre_technique': 'T1190',
                        'technique_name': 'Exploit Public-Facing Application',
                        'tactic': 'Initial Access'
                    })
            
            elif vector_type == 'social_engineering':
                mitre_mapping.append({
                    'attack_vector': name,
                    'mitre_technique': 'T1566',
                    'technique_name': 'Phishing',
                    'tactic': 'Initial Access'
                })
            
            elif vector_type == 'network_service':
                mitre_mapping.append({
                    'attack_vector': name,
                    'mitre_technique': 'T1190',
                    'technique_name': 'Exploit Public-Facing Application',
                    'tactic': 'Initial Access'
                })
        
        return mitre_mapping

    def _generate_priority_actions(self, attack_vectors: List[Dict], risk_level: str) -> List[Dict[str, Any]]:
        """Generate priority actions based on risk level and attack vectors."""
        priority_actions = []
        
        # Critical risk level actions
        if risk_level == 'critical':
            priority_actions.extend([
                {
                    'action': 'Immediate security incident response',
                    'priority': 1,
                    'timeline': 'Immediate',
                    'description': 'Initiate incident response procedures'
                },
                {
                    'action': 'Emergency patching and remediation',
                    'priority': 2,
                    'timeline': '24 hours',
                    'description': 'Address all critical vulnerabilities immediately'
                }
            ])
        
        # High risk level actions
        elif risk_level == 'high':
            priority_actions.extend([
                {
                    'action': 'Urgent vulnerability remediation',
                    'priority': 1,
                    'timeline': '48 hours',
                    'description': 'Fix high-severity vulnerabilities'
                },
                {
                    'action': 'Security controls implementation',
                    'priority': 2,
                    'timeline': '1 week',
                    'description': 'Implement missing security controls'
                }
            ])
        
        # Medium risk level actions
        elif risk_level == 'medium':
            priority_actions.extend([
                {
                    'action': 'Vulnerability management',
                    'priority': 1,
                    'timeline': '1 week',
                    'description': 'Establish vulnerability management process'
                },
                {
                    'action': 'Security hardening',
                    'priority': 2,
                    'timeline': '2 weeks',
                    'description': 'Implement security hardening measures'
                }
            ])
        
        # Low risk level actions
        else:
            priority_actions.extend([
                {
                    'action': 'Security baseline establishment',
                    'priority': 1,
                    'timeline': '1 month',
                    'description': 'Establish security baseline and monitoring'
                },
                {
                    'action': 'Regular security assessments',
                    'priority': 2,
                    'timeline': 'Ongoing',
                    'description': 'Implement regular security assessments'
                }
            ])
        
        return priority_actions
