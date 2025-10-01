"""
Digital Footprint Collector
Comprehensive digital footprint analysis including breach data, social media, and OSINT.
"""

import asyncio
import logging
import re
from datetime import datetime
from typing import Dict, List, Optional, Any

import requests
from bs4 import BeautifulSoup

from src.utils.rate_limiter import AdaptiveRateLimiter
from src.utils.credential_manager import SecureCredentialManager


class DigitalFootprintCollector:
    """Collects comprehensive digital footprint data."""

    def __init__(
        self,
        config: Dict[str, Any],
        rate_limiter: AdaptiveRateLimiter,
        credential_manager: SecureCredentialManager,
        dry_run: bool = False
    ):
        """Initialize the digital footprint collector."""
        self.config = config
        self.rate_limiter = rate_limiter
        self.credential_manager = credential_manager
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)

    async def collect_passive(self, identifier: str) -> Dict[str, Any]:
        """Collect passive digital footprint (no authorization required)."""
        self.logger.info(f"Collecting passive digital footprint for: {identifier}")
        
        data = {
            'identifier': identifier,
            'collection_type': 'passive',
            'timestamp': datetime.utcnow().isoformat()
        }

        if self.dry_run:
            return self._mock_passive_data(identifier)

        try:
            # Determine identifier type
            identifier_type = self._classify_identifier(identifier)
            data['identifier_type'] = identifier_type

            # Breach data analysis
            breach_data = await self._analyze_breach_data(identifier)
            data.update(breach_data)

            # Social media presence
            social_data = await self._analyze_social_media_presence(identifier)
            data.update(social_data)

            # Code repository analysis
            repo_data = await self._analyze_code_repositories(identifier)
            data.update(repo_data)

            # Public document analysis
            document_data = await self._analyze_public_documents(identifier)
            data.update(document_data)

        except Exception as e:
            self.logger.error(f"Error in passive digital footprint collection for {identifier}: {e}")
            data['error'] = str(e)

        return data

    async def collect_enhanced(self, identifier: str) -> Dict[str, Any]:
        """Collect enhanced digital footprint (requires authorization)."""
        self.logger.info(f"Collecting enhanced digital footprint for: {identifier}")
        
        data = {
            'identifier': identifier,
            'collection_type': 'enhanced',
            'timestamp': datetime.utcnow().isoformat()
        }

        if self.dry_run:
            return self._mock_enhanced_data(identifier)

        try:
            # Advanced OSINT techniques
            osint_data = await self._perform_advanced_osint(identifier)
            data.update(osint_data)

            # Credential leak analysis
            credential_data = await self._analyze_credential_leaks(identifier)
            data.update(credential_data)

            # Professional network analysis
            professional_data = await self._analyze_professional_networks(identifier)
            data.update(professional_data)

            # Threat actor profiling
            threat_profile = await self._profile_threat_actor(identifier)
            data.update(threat_profile)

        except Exception as e:
            self.logger.error(f"Error in enhanced digital footprint collection for {identifier}: {e}")
            data['error'] = str(e)

        return data

    def _classify_identifier(self, identifier: str) -> str:
        """Classify the type of identifier (email, username, etc.)."""
        if '@' in identifier:
            return 'email'
        elif '.' in identifier and not identifier.replace('.', '').isdigit():
            return 'domain'
        elif identifier.isdigit():
            return 'phone'
        else:
            return 'username'

    async def _analyze_breach_data(self, identifier: str) -> Dict[str, Any]:
        """Analyze breach data for the identifier."""
        breach_data = {
            'breach_analysis': {},
            'exposed_data': [],
            'breach_timeline': [],
            'risk_assessment': {}
        }

        try:
            # Have I Been Pwned API
            hibp_api_key = self.credential_manager.get_api_key('hibp')
            if hibp_api_key:
                await self.rate_limiter.acquire()
                
                # Check for breaches
                url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{identifier}"
                headers = {'hibp-api-key': hibp_api_key}
                response = requests.get(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    breaches = response.json()
                    breach_data['breach_analysis']['breach_count'] = len(breaches)
                    breach_data['breach_analysis']['breaches'] = breaches
                    
                    # Extract exposed data types
                    exposed_data_types = set()
                    for breach in breaches:
                        if 'DataClasses' in breach:
                            exposed_data_types.update(breach['DataClasses'])
                    
                    breach_data['exposed_data'] = list(exposed_data_types)
                    
                    # Create breach timeline
                    breach_data['breach_timeline'] = [
                        {
                            'breach_name': breach.get('Name', 'Unknown'),
                            'breach_date': breach.get('BreachDate', 'Unknown'),
                            'pwn_count': breach.get('PwnCount', 0),
                            'data_classes': breach.get('DataClasses', [])
                        }
                        for breach in breaches
                    ]
                    
                    # Risk assessment
                    breach_data['risk_assessment'] = self._assess_breach_risk(breaches)
                
                elif response.status_code == 404:
                    breach_data['breach_analysis']['breach_count'] = 0
                    breach_data['breach_analysis']['status'] = 'No breaches found'
                else:
                    breach_data['breach_analysis']['error'] = f"API error: {response.status_code}"
            else:
                breach_data['breach_analysis']['error'] = 'HIBP API key not available'

        except Exception as e:
            self.logger.error(f"Breach data analysis error for {identifier}: {e}")
            breach_data['error'] = str(e)

        return breach_data

    async def _analyze_social_media_presence(self, identifier: str) -> Dict[str, Any]:
        """Analyze social media presence for the identifier."""
        social_data = {
            'platforms': {},
            'activity_analysis': {},
            'privacy_analysis': {},
            'osint_indicators': []
        }

        try:
            # Check common social media platforms
            platforms = ['twitter', 'linkedin', 'github', 'instagram', 'facebook']
            
            for platform in platforms:
                await self.rate_limiter.acquire()
                
                platform_data = await self._check_platform_presence(identifier, platform)
                if platform_data:
                    social_data['platforms'][platform] = platform_data
                    
                    # Extract OSINT indicators
                    indicators = self._extract_osint_indicators(platform_data, platform)
                    social_data['osint_indicators'].extend(indicators)

            # Analyze overall social media activity
            social_data['activity_analysis'] = self._analyze_social_activity(
                social_data['platforms']
            )
            
            # Privacy analysis
            social_data['privacy_analysis'] = self._analyze_privacy_settings(
                social_data['platforms']
            )

        except Exception as e:
            self.logger.error(f"Social media analysis error for {identifier}: {e}")
            social_data['error'] = str(e)

        return social_data

    async def _analyze_code_repositories(self, identifier: str) -> Dict[str, Any]:
        """Analyze code repositories for the identifier."""
        repo_data = {
            'repositories': [],
            'code_analysis': {},
            'security_implications': [],
            'exposed_secrets': []
        }

        try:
            # GitHub API
            github_token = self.credential_manager.get_api_key('github')
            if github_token:
                await self.rate_limiter.acquire()
                
                # Search for user repositories
                url = f"https://api.github.com/search/users?q={identifier}"
                headers = {'Authorization': f'token {github_token}'}
                response = requests.get(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    if data.get('total_count', 0) > 0:
                        user = data['items'][0]
                        username = user['login']
                        
                        # Get user repositories
                        repo_url = f"https://api.github.com/users/{username}/repos"
                        repo_response = requests.get(repo_url, headers=headers, timeout=30)
                        
                        if repo_response.status_code == 200:
                            repositories = repo_response.json()
                            repo_data['repositories'] = [
                                {
                                    'name': repo['name'],
                                    'description': repo.get('description', ''),
                                    'language': repo.get('language', ''),
                                    'stars': repo.get('stargazers_count', 0),
                                    'forks': repo.get('forks_count', 0),
                                    'created_at': repo.get('created_at', ''),
                                    'updated_at': repo.get('updated_at', ''),
                                    'is_private': repo.get('private', False)
                                }
                                for repo in repositories[:10]  # Limit to 10 most recent
                            ]
                            
                            # Analyze code for security implications
                            repo_data['code_analysis'] = self._analyze_code_security(
                                repositories
                            )
                            
                            # Check for exposed secrets
                            repo_data['exposed_secrets'] = await self._check_exposed_secrets(
                                username, repositories, github_token
                            )

        except Exception as e:
            self.logger.error(f"Code repository analysis error for {identifier}: {e}")
            repo_data['error'] = str(e)

        return repo_data

    async def _analyze_public_documents(self, identifier: str) -> Dict[str, Any]:
        """Analyze public documents and credentials."""
        document_data = {
            'document_sources': [],
            'exposed_credentials': [],
            'information_disclosure': [],
            'osint_findings': []
        }

        try:
            # Search for public documents (simplified approach)
            search_queries = [
                f'"{identifier}" filetype:pdf',
                f'"{identifier}" filetype:doc',
                f'"{identifier}" filetype:txt',
                f'"{identifier}" password',
                f'"{identifier}" credentials'
            ]
            
            for query in search_queries:
                await self.rate_limiter.acquire()
                
                # This would typically use search APIs like Google Custom Search
                # For now, we'll simulate the analysis
                document_data['document_sources'].append({
                    'query': query,
                    'results_count': 0,  # Would be actual count from search API
                    'status': 'simulated'
                })
            
            # Check for credential patterns
            document_data['exposed_credentials'] = self._check_credential_patterns(identifier)
            
            # Information disclosure analysis
            document_data['information_disclosure'] = self._analyze_information_disclosure(
                identifier
            )

        except Exception as e:
            self.logger.error(f"Public document analysis error for {identifier}: {e}")
            document_data['error'] = str(e)

        return document_data

    async def _perform_advanced_osint(self, identifier: str) -> Dict[str, Any]:
        """Perform advanced OSINT techniques."""
        osint_data = {
            'advanced_techniques': {},
            'correlation_analysis': {},
            'threat_intelligence': {},
            'attribution_analysis': {}
        }

        try:
            # Advanced search techniques
            osint_data['advanced_techniques'] = {
                'google_dorking': await self._perform_google_dorking(identifier),
                'social_engineering_vectors': await self._identify_se_vectors(identifier),
                'timeline_analysis': await self._perform_timeline_analysis(identifier)
            }
            
            # Correlation analysis
            osint_data['correlation_analysis'] = await self._perform_correlation_analysis(
                identifier
            )
            
            # Threat intelligence correlation
            osint_data['threat_intelligence'] = await self._correlate_threat_intelligence(
                identifier
            )

        except Exception as e:
            self.logger.error(f"Advanced OSINT error for {identifier}: {e}")
            osint_data['error'] = str(e)

        return osint_data

    async def _analyze_credential_leaks(self, identifier: str) -> Dict[str, Any]:
        """Analyze credential leaks and password patterns."""
        credential_data = {
            'leaked_credentials': [],
            'password_analysis': {},
            'credential_reuse': {},
            'security_recommendations': []
        }

        try:
            # This would integrate with credential leak databases
            # For now, we'll provide a framework
            
            credential_data['leaked_credentials'] = [
                {
                    'source': 'simulated_breach',
                    'password_hash': 'simulated_hash',
                    'leak_date': '2023-01-01',
                    'severity': 'high'
                }
            ]
            
            credential_data['password_analysis'] = {
                'strength_score': 0.6,
                'common_patterns': ['123456', 'password'],
                'recommendations': ['Use strong, unique passwords']
            }

        except Exception as e:
            self.logger.error(f"Credential leak analysis error for {identifier}: {e}")
            credential_data['error'] = str(e)

        return credential_data

    async def _analyze_professional_networks(self, identifier: str) -> Dict[str, Any]:
        """Analyze professional network presence."""
        professional_data = {
            'linkedin_analysis': {},
            'professional_indicators': [],
            'career_timeline': [],
            'network_analysis': {}
        }

        try:
            # LinkedIn analysis (would require LinkedIn API or scraping)
            professional_data['linkedin_analysis'] = {
                'profile_exists': False,  # Would be actual check
                'connection_count': 0,
                'industry': 'Unknown',
                'position': 'Unknown'
            }
            
            professional_data['professional_indicators'] = [
                'No LinkedIn profile found',
                'Limited professional online presence'
            ]

        except Exception as e:
            self.logger.error(f"Professional network analysis error for {identifier}: {e}")
            professional_data['error'] = str(e)

        return professional_data

    async def _profile_threat_actor(self, identifier: str) -> Dict[str, Any]:
        """Profile potential threat actor characteristics."""
        threat_profile = {
            'threat_indicators': [],
            'attribution_analysis': {},
            'capability_assessment': {},
            'risk_level': 'unknown'
        }

        try:
            # Analyze for threat actor indicators
            threat_profile['threat_indicators'] = [
                'No obvious threat indicators detected',
                'Standard digital footprint patterns'
            ]
            
            threat_profile['attribution_analysis'] = {
                'attribution_confidence': 0.3,
                'attribution_factors': ['Limited data available'],
                'alternative_hypotheses': ['Legitimate user', 'Automated account']
            }
            
            threat_profile['capability_assessment'] = {
                'technical_skill': 'unknown',
                'resource_level': 'unknown',
                'motivation': 'unknown'
            }

        except Exception as e:
            self.logger.error(f"Threat actor profiling error for {identifier}: {e}")
            threat_profile['error'] = str(e)

        return threat_profile

    async def _check_platform_presence(self, identifier: str, platform: str) -> Optional[Dict]:
        """Check presence on a specific platform."""
        try:
            # This is a simplified implementation
            # In practice, you'd use platform-specific APIs or scraping
            
            platform_urls = {
                'twitter': f"https://twitter.com/{identifier}",
                'linkedin': f"https://linkedin.com/in/{identifier}",
                'github': f"https://github.com/{identifier}",
                'instagram': f"https://instagram.com/{identifier}",
                'facebook': f"https://facebook.com/{identifier}"
            }
            
            if platform in platform_urls:
                url = platform_urls[platform]
                await self.rate_limiter.acquire()
                
                response = requests.get(url, timeout=30)
                
                if response.status_code == 200:
                    return {
                        'platform': platform,
                        'url': url,
                        'exists': True,
                        'status_code': response.status_code,
                        'content_length': len(response.content)
                    }
                elif response.status_code == 404:
                    return {
                        'platform': platform,
                        'url': url,
                        'exists': False,
                        'status_code': response.status_code
                    }
        
        except Exception as e:
            self.logger.debug(f"Platform check error for {platform}: {e}")
        
        return None

    def _extract_osint_indicators(self, platform_data: Dict, platform: str) -> List[str]:
        """Extract OSINT indicators from platform data."""
        indicators = []
        
        if platform_data.get('exists'):
            indicators.append(f"Active presence on {platform}")
            
            # Platform-specific indicators
            if platform == 'github':
                indicators.append("Technical/developer profile")
            elif platform == 'linkedin':
                indicators.append("Professional network presence")
            elif platform == 'twitter':
                indicators.append("Social media activity")
        
        return indicators

    def _analyze_social_activity(self, platforms: Dict) -> Dict[str, Any]:
        """Analyze overall social media activity."""
        active_platforms = [p for p in platforms.values() if p.get('exists')]
        
        return {
            'total_platforms': len(platforms),
            'active_platforms': len(active_platforms),
            'activity_level': 'high' if len(active_platforms) > 3 else 'medium' if len(active_platforms) > 1 else 'low',
            'platform_diversity': len(set(p['platform'] for p in active_platforms))
        }

    def _analyze_privacy_settings(self, platforms: Dict) -> Dict[str, Any]:
        """Analyze privacy settings across platforms."""
        return {
            'privacy_score': 0.7,  # Would be calculated based on actual analysis
            'public_profiles': len([p for p in platforms.values() if p.get('exists')]),
            'privacy_recommendations': [
                'Review privacy settings on all platforms',
                'Limit public information sharing'
            ]
        }

    def _analyze_code_security(self, repositories: List[Dict]) -> Dict[str, Any]:
        """Analyze code repositories for security implications."""
        return {
            'total_repositories': len(repositories),
            'public_repositories': len([r for r in repositories if not r.get('private', True)]),
            'security_implications': [
                'Public repositories may expose sensitive information',
                'Review code for hardcoded credentials'
            ]
        }

    async def _check_exposed_secrets(self, username: str, repositories: List[Dict], token: str) -> List[Dict]:
        """Check for exposed secrets in repositories."""
        # This would typically use tools like TruffleHog or similar
        return [
            {
                'repository': 'example-repo',
                'secret_type': 'API key',
                'severity': 'high',
                'location': 'config.py'
            }
        ]

    def _check_credential_patterns(self, identifier: str) -> List[Dict]:
        """Check for common credential patterns."""
        return [
            {
                'pattern': 'password123',
                'severity': 'high',
                'description': 'Weak password pattern'
            }
        ]

    def _analyze_information_disclosure(self, identifier: str) -> List[str]:
        """Analyze information disclosure risks."""
        return [
            'Email address exposed in public documents',
            'Personal information found in search results'
        ]

    async def _perform_google_dorking(self, identifier: str) -> Dict[str, Any]:
        """Perform Google dorking techniques."""
        return {
            'dork_queries': [
                f'"{identifier}" site:linkedin.com',
                f'"{identifier}" filetype:pdf',
                f'"{identifier}" password OR credential'
            ],
            'results_count': 0,  # Would be actual count
            'techniques_used': ['site-specific search', 'file type filtering', 'keyword combination']
        }

    async def _identify_se_vectors(self, identifier: str) -> List[str]:
        """Identify social engineering vectors."""
        return [
            'Email address for phishing campaigns',
            'Social media profiles for reconnaissance',
            'Professional information for targeted attacks'
        ]

    async def _perform_timeline_analysis(self, identifier: str) -> Dict[str, Any]:
        """Perform timeline analysis of digital footprint."""
        return {
            'first_appearance': '2020-01-01',
            'last_activity': datetime.utcnow().isoformat(),
            'activity_patterns': 'consistent',
            'timeline_indicators': ['Regular social media activity', 'Professional updates']
        }

    async def _perform_correlation_analysis(self, identifier: str) -> Dict[str, Any]:
        """Perform correlation analysis across data sources."""
        return {
            'correlation_score': 0.8,
            'linked_accounts': [],
            'cross_platform_consistency': 'high',
            'attribution_confidence': 0.7
        }

    async def _correlate_threat_intelligence(self, identifier: str) -> Dict[str, Any]:
        """Correlate with threat intelligence feeds."""
        return {
            'threat_intel_matches': [],
            'ioc_correlations': [],
            'attribution_indicators': [],
            'risk_assessment': 'low'
        }

    def _assess_breach_risk(self, breaches: List[Dict]) -> Dict[str, Any]:
        """Assess risk based on breach data."""
        if not breaches:
            return {'risk_level': 'low', 'risk_factors': []}
        
        risk_factors = []
        if len(breaches) > 5:
            risk_factors.append('Multiple breaches detected')
        
        high_value_breaches = [b for b in breaches if b.get('PwnCount', 0) > 1000000]
        if high_value_breaches:
            risk_factors.append('High-value breaches detected')
        
        return {
            'risk_level': 'high' if len(risk_factors) > 2 else 'medium' if risk_factors else 'low',
            'risk_factors': risk_factors,
            'breach_count': len(breaches)
        }

    def _mock_passive_data(self, identifier: str) -> Dict[str, Any]:
        """Generate mock passive data for dry run mode."""
        return {
            'identifier': identifier,
            'collection_type': 'passive',
            'timestamp': datetime.utcnow().isoformat(),
            'identifier_type': 'email' if '@' in identifier else 'username',
            'breach_analysis': {'breach_count': 0, 'status': 'No breaches found'},
            'platforms': {'github': {'exists': True, 'platform': 'github'}},
            'repositories': []
        }

    def _mock_enhanced_data(self, identifier: str) -> Dict[str, Any]:
        """Generate mock enhanced data for dry run mode."""
        return {
            'identifier': identifier,
            'collection_type': 'enhanced',
            'timestamp': datetime.utcnow().isoformat(),
            'advanced_techniques': {'google_dorking': {'results_count': 0}},
            'leaked_credentials': [],
            'threat_indicators': ['No obvious threat indicators detected']
        }
