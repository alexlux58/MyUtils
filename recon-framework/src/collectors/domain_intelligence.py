"""
Domain Intelligence Collector
Comprehensive domain reconnaissance with WHOIS, DNS, and certificate analysis.
"""

import asyncio
import logging
import socket
import ssl
from datetime import datetime
from typing import Dict, List, Optional, Any
from urllib.parse import urlparse

import dns.resolver
import requests
from bs4 import BeautifulSoup

from src.utils.rate_limiter import AdaptiveRateLimiter
from src.utils.credential_manager import SecureCredentialManager


class DomainIntelligenceCollector:
    """Collects comprehensive domain intelligence data."""

    def __init__(
        self,
        config: Dict[str, Any],
        rate_limiter: AdaptiveRateLimiter,
        credential_manager: SecureCredentialManager,
        dry_run: bool = False
    ):
        """Initialize the domain intelligence collector."""
        self.config = config
        self.rate_limiter = rate_limiter
        self.credential_manager = credential_manager
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)

    async def collect_passive(self, domain: str) -> Dict[str, Any]:
        """Collect passive domain intelligence (no authorization required)."""
        self.logger.info(f"Collecting passive domain intelligence for: {domain}")
        
        data = {
            'domain': domain,
            'collection_type': 'passive',
            'timestamp': datetime.utcnow().isoformat()
        }

        if self.dry_run:
            return self._mock_passive_data(domain)

        try:
            # DNS enumeration
            dns_data = await self._collect_dns_data(domain)
            data.update(dns_data)

            # WHOIS information
            whois_data = await self._collect_whois_data(domain)
            data.update(whois_data)

            # Certificate transparency logs
            ct_data = await self._collect_certificate_transparency(domain)
            data.update(ct_data)

            # HTTP metadata
            http_data = await self._collect_http_metadata(domain)
            data.update(http_data)

            # Security headers analysis
            security_headers = await self._analyze_security_headers(domain)
            data['security_headers'] = security_headers

        except Exception as e:
            self.logger.error(f"Error in passive collection for {domain}: {e}")
            data['error'] = str(e)

        return data

    async def collect_enhanced(self, domain: str) -> Dict[str, Any]:
        """Collect enhanced domain intelligence (requires authorization)."""
        self.logger.info(f"Collecting enhanced domain intelligence for: {domain}")
        
        data = {
            'domain': domain,
            'collection_type': 'enhanced',
            'timestamp': datetime.utcnow().isoformat()
        }

        if self.dry_run:
            return self._mock_enhanced_data(domain)

        try:
            # Subdomain enumeration
            subdomains = await self._enumerate_subdomains(domain)
            data['subdomains'] = subdomains

            # Historical data from archive.org
            historical_data = await self._collect_historical_data(domain)
            data['historical_data'] = historical_data

            # Technology stack detection
            tech_stack = await self._detect_technology_stack(domain)
            data['technology_stack'] = tech_stack

            # Vulnerability scanning (if authorized)
            vulnerabilities = await self._scan_vulnerabilities(domain)
            data['vulnerabilities'] = vulnerabilities

        except Exception as e:
            self.logger.error(f"Error in enhanced collection for {domain}: {e}")
            data['error'] = str(e)

        return data

    async def _collect_dns_data(self, domain: str) -> Dict[str, Any]:
        """Collect comprehensive DNS data."""
        dns_data = {
            'dns_records': {},
            'dns_servers': [],
            'dns_analysis': {}
        }

        try:
            # Common DNS record types
            record_types = ['A', 'AAAA', 'MX', 'TXT', 'NS', 'CNAME', 'SRV', 'PTR']
            
            for record_type in record_types:
                try:
                    records = dns.resolver.resolve(domain, record_type)
                    dns_data['dns_records'][record_type] = [
                        str(record) for record in records
                    ]
                except Exception as e:
                    self.logger.debug(f"No {record_type} records for {domain}: {e}")

            # DNS servers
            try:
                ns_records = dns.resolver.resolve(domain, 'NS')
                dns_data['dns_servers'] = [str(record) for record in ns_records]
            except Exception as e:
                self.logger.debug(f"Could not resolve NS records for {domain}: {e}")

            # DNS analysis
            dns_data['dns_analysis'] = self._analyze_dns_records(dns_data['dns_records'])

        except Exception as e:
            self.logger.error(f"DNS collection error for {domain}: {e}")
            dns_data['error'] = str(e)

        return dns_data

    async def _collect_whois_data(self, domain: str) -> Dict[str, Any]:
        """Collect WHOIS information with privacy detection."""
        whois_data = {
            'whois_info': {},
            'privacy_detection': {},
            'registrar_analysis': {}
        }

        try:
            # Basic WHOIS lookup
            import whois
            w = whois.whois(domain)
            
            whois_data['whois_info'] = {
                'registrar': str(w.registrar) if w.registrar else None,
                'creation_date': w.creation_date.isoformat() if w.creation_date else None,
                'expiration_date': w.expiration_date.isoformat() if w.expiration_date else None,
                'name_servers': w.name_servers if w.name_servers else [],
                'status': w.status if w.status else [],
                'emails': w.emails if w.emails else []
            }

            # Privacy detection
            whois_data['privacy_detection'] = self._detect_privacy_protection(w)

            # Registrar reputation analysis
            if w.registrar:
                whois_data['registrar_analysis'] = self._analyze_registrar_reputation(
                    str(w.registrar)
                )

        except Exception as e:
            self.logger.error(f"WHOIS collection error for {domain}: {e}")
            whois_data['error'] = str(e)

        return whois_data

    async def _collect_certificate_transparency(self, domain: str) -> Dict[str, Any]:
        """Collect certificate transparency log data."""
        ct_data = {
            'certificates': [],
            'subdomains_from_ct': [],
            'certificate_analysis': {}
        }

        try:
            # Use crt.sh API for certificate transparency
            await self.rate_limiter.acquire()
            
            url = f"https://crt.sh/?q={domain}&output=json"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                certificates = response.json()
                ct_data['certificates'] = certificates[:50]  # Limit to 50 most recent
                
                # Extract subdomains from certificates
                subdomains = set()
                for cert in certificates:
                    if 'name_value' in cert:
                        subdomains.add(cert['name_value'])
                
                ct_data['subdomains_from_ct'] = list(subdomains)
                
                # Certificate analysis
                ct_data['certificate_analysis'] = self._analyze_certificates(certificates)

        except Exception as e:
            self.logger.error(f"Certificate transparency error for {domain}: {e}")
            ct_data['error'] = str(e)

        return ct_data

    async def _collect_http_metadata(self, domain: str) -> Dict[str, Any]:
        """Collect HTTP metadata and response headers."""
        http_data = {
            'http_response': {},
            'https_response': {},
            'redirects': [],
            'response_analysis': {}
        }

        protocols = ['http', 'https']
        
        for protocol in protocols:
            try:
                url = f"{protocol}://{domain}"
                await self.rate_limiter.acquire()
                
                response = requests.get(
                    url, 
                    timeout=30, 
                    allow_redirects=True,
                    headers={'User-Agent': 'Mozilla/5.0 (compatible; ReconFramework/1.0)'}
                )
                
                http_data[f'{protocol}_response'] = {
                    'status_code': response.status_code,
                    'headers': dict(response.headers),
                    'content_length': len(response.content),
                    'server': response.headers.get('Server', 'Unknown'),
                    'final_url': response.url
                }
                
                # Track redirects
                if response.history:
                    http_data['redirects'] = [
                        {'url': r.url, 'status_code': r.status_code} 
                        for r in response.history
                    ]

            except Exception as e:
                self.logger.debug(f"HTTP metadata error for {protocol}://{domain}: {e}")

        return http_data

    async def _analyze_security_headers(self, domain: str) -> Dict[str, Any]:
        """Analyze security headers for the domain."""
        security_analysis = {
            'present_headers': [],
            'missing_headers': [],
            'security_score': 0,
            'recommendations': []
        }

        try:
            url = f"https://{domain}"
            await self.rate_limiter.acquire()
            
            response = requests.get(url, timeout=30)
            headers = response.headers
            
            # Security headers to check
            security_headers = {
                'Strict-Transport-Security': 'HSTS',
                'X-Content-Type-Options': 'Content Type Options',
                'X-Frame-Options': 'Frame Options',
                'X-XSS-Protection': 'XSS Protection',
                'Content-Security-Policy': 'CSP',
                'Referrer-Policy': 'Referrer Policy',
                'Permissions-Policy': 'Permissions Policy'
            }
            
            for header, description in security_headers.items():
                if header in headers:
                    security_analysis['present_headers'].append({
                        'header': header,
                        'value': headers[header],
                        'description': description
                    })
                else:
                    security_analysis['missing_headers'].append({
                        'header': header,
                        'description': description
                    })

            # Calculate security score
            total_headers = len(security_headers)
            present_count = len(security_analysis['present_headers'])
            security_analysis['security_score'] = (present_count / total_headers) * 100

            # Generate recommendations
            security_analysis['recommendations'] = self._generate_security_recommendations(
                security_analysis['missing_headers']
            )

        except Exception as e:
            self.logger.error(f"Security headers analysis error for {domain}: {e}")
            security_analysis['error'] = str(e)

        return security_analysis

    async def _enumerate_subdomains(self, domain: str) -> List[str]:
        """Enumerate subdomains using multiple techniques."""
        subdomains = set()
        
        try:
            # Common subdomain wordlist
            common_subdomains = [
                'www', 'mail', 'ftp', 'admin', 'api', 'blog', 'shop',
                'support', 'help', 'dev', 'test', 'staging', 'beta',
                'app', 'mobile', 'secure', 'vpn', 'remote'
            ]
            
            for subdomain in common_subdomains:
                full_domain = f"{subdomain}.{domain}"
                try:
                    socket.gethostbyname(full_domain)
                    subdomains.add(full_domain)
                except socket.gaierror:
                    pass
                
                await self.rate_limiter.acquire()

        except Exception as e:
            self.logger.error(f"Subdomain enumeration error for {domain}: {e}")

        return list(subdomains)

    async def _collect_historical_data(self, domain: str) -> Dict[str, Any]:
        """Collect historical data from archive.org."""
        historical_data = {
            'wayback_snapshots': [],
            'historical_analysis': {}
        }

        try:
            # Wayback Machine API
            await self.rate_limiter.acquire()
            
            url = f"http://web.archive.org/cdx/search/cdx?url={domain}/*&output=json&limit=10"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                snapshots = response.json()
                if len(snapshots) > 1:  # Skip header row
                    historical_data['wayback_snapshots'] = snapshots[1:]  # Skip header
                    
                    # Analyze historical changes
                    historical_data['historical_analysis'] = self._analyze_historical_changes(
                        snapshots[1:]
                    )

        except Exception as e:
            self.logger.error(f"Historical data collection error for {domain}: {e}")
            historical_data['error'] = str(e)

        return historical_data

    async def _detect_technology_stack(self, domain: str) -> Dict[str, Any]:
        """Detect technology stack from HTTP responses."""
        tech_stack = {
            'web_server': 'Unknown',
            'programming_language': 'Unknown',
            'framework': 'Unknown',
            'cms': 'Unknown',
            'javascript_libraries': [],
            'other_technologies': []
        }

        try:
            url = f"https://{domain}"
            await self.rate_limiter.acquire()
            
            response = requests.get(url, timeout=30)
            content = response.text
            headers = response.headers
            
            # Detect web server
            server_header = headers.get('Server', '').lower()
            if 'apache' in server_header:
                tech_stack['web_server'] = 'Apache'
            elif 'nginx' in server_header:
                tech_stack['web_server'] = 'Nginx'
            elif 'iis' in server_header:
                tech_stack['web_server'] = 'IIS'
            
            # Detect CMS
            if 'wp-content' in content or 'wordpress' in content.lower():
                tech_stack['cms'] = 'WordPress'
            elif 'drupal' in content.lower():
                tech_stack['cms'] = 'Drupal'
            elif 'joomla' in content.lower():
                tech_stack['cms'] = 'Joomla'
            
            # Detect JavaScript libraries
            js_libraries = [
                'jquery', 'react', 'angular', 'vue', 'bootstrap',
                'lodash', 'moment', 'd3', 'chart'
            ]
            
            for lib in js_libraries:
                if lib in content.lower():
                    tech_stack['javascript_libraries'].append(lib)

        except Exception as e:
            self.logger.error(f"Technology detection error for {domain}: {e}")
            tech_stack['error'] = str(e)

        return tech_stack

    async def _scan_vulnerabilities(self, domain: str) -> Dict[str, Any]:
        """Perform basic vulnerability scanning."""
        vulnerabilities = {
            'vulnerability_count': 0,
            'critical_count': 0,
            'high_count': 0,
            'medium_count': 0,
            'low_count': 0,
            'vulnerabilities': []
        }

        try:
            # Basic vulnerability checks
            url = f"https://{domain}"
            await self.rate_limiter.acquire()
            
            response = requests.get(url, timeout=30)
            
            # Check for common vulnerabilities
            vuln_checks = [
                self._check_directory_listing,
                self._check_sql_injection_indicators,
                self._check_xss_indicators,
                self._check_information_disclosure
            ]
            
            for check in vuln_checks:
                vuln_result = check(response)
                if vuln_result:
                    vulnerabilities['vulnerabilities'].append(vuln_result)
                    vulnerabilities['vulnerability_count'] += 1
                    
                    # Categorize by severity
                    severity = vuln_result.get('severity', 'low')
                    if severity == 'critical':
                        vulnerabilities['critical_count'] += 1
                    elif severity == 'high':
                        vulnerabilities['high_count'] += 1
                    elif severity == 'medium':
                        vulnerabilities['medium_count'] += 1
                    else:
                        vulnerabilities['low_count'] += 1

        except Exception as e:
            self.logger.error(f"Vulnerability scanning error for {domain}: {e}")
            vulnerabilities['error'] = str(e)

        return vulnerabilities

    def _analyze_dns_records(self, dns_records: Dict[str, List[str]]) -> Dict[str, Any]:
        """Analyze DNS records for security implications."""
        analysis = {
            'security_issues': [],
            'configuration_issues': [],
            'recommendations': []
        }
        
        # Check for security issues
        if 'TXT' in dns_records:
            for txt_record in dns_records['TXT']:
                if 'v=spf1' in txt_record.lower():
                    analysis['security_issues'].append('SPF record found')
                if 'v=dmarc1' in txt_record.lower():
                    analysis['security_issues'].append('DMARC record found')
        
        # Check for missing security records
        if 'TXT' not in dns_records:
            analysis['configuration_issues'].append('No TXT records found')
            analysis['recommendations'].append('Consider adding SPF and DMARC records')
        
        return analysis

    def _detect_privacy_protection(self, whois_data) -> Dict[str, Any]:
        """Detect if domain has privacy protection enabled."""
        privacy_indicators = [
            'privacy', 'private', 'protected', 'redacted',
            'whoisguard', 'domains by proxy', 'namecheap'
        ]
        
        privacy_detected = False
        for field in ['registrar', 'name', 'organization']:
            if hasattr(whois_data, field) and whois_data.__dict__.get(field):
                field_value = str(whois_data.__dict__[field]).lower()
                if any(indicator in field_value for indicator in privacy_indicators):
                    privacy_detected = True
                    break
        
        return {
            'privacy_protected': privacy_detected,
            'privacy_score': 0.8 if privacy_detected else 0.2
        }

    def _analyze_registrar_reputation(self, registrar: str) -> Dict[str, Any]:
        """Analyze registrar reputation and security."""
        # This is a simplified analysis - in practice, you'd use a reputation database
        suspicious_registrars = ['namecheap', 'godaddy', 'name.com']
        
        is_suspicious = any(sus in registrar.lower() for sus in suspicious_registrars)
        
        return {
            'registrar': registrar,
            'reputation_score': 0.3 if is_suspicious else 0.7,
            'is_suspicious': is_suspicious
        }

    def _analyze_certificates(self, certificates: List[Dict]) -> Dict[str, Any]:
        """Analyze certificate transparency data."""
        analysis = {
            'total_certificates': len(certificates),
            'wildcard_certificates': 0,
            'expired_certificates': 0,
            'certificate_chain_analysis': {}
        }
        
        for cert in certificates:
            if cert.get('name_value', '').startswith('*.'):
                analysis['wildcard_certificates'] += 1
        
        return analysis

    def _generate_security_recommendations(self, missing_headers: List[Dict]) -> List[str]:
        """Generate security recommendations based on missing headers."""
        recommendations = []
        
        for header in missing_headers:
            if header['header'] == 'Strict-Transport-Security':
                recommendations.append('Implement HSTS to enforce HTTPS')
            elif header['header'] == 'Content-Security-Policy':
                recommendations.append('Implement CSP to prevent XSS attacks')
            elif header['header'] == 'X-Frame-Options':
                recommendations.append('Implement X-Frame-Options to prevent clickjacking')
        
        return recommendations

    def _check_directory_listing(self, response) -> Optional[Dict]:
        """Check for directory listing vulnerability."""
        if 'Index of' in response.text or 'Directory listing' in response.text:
            return {
                'type': 'Directory Listing',
                'severity': 'medium',
                'description': 'Directory listing is enabled'
            }
        return None

    def _check_sql_injection_indicators(self, response) -> Optional[Dict]:
        """Check for SQL injection indicators."""
        sql_errors = [
            'mysql_fetch_array', 'ORA-01756', 'Microsoft OLE DB Provider',
            'SQLServer JDBC Driver', 'PostgreSQL query failed'
        ]
        
        for error in sql_errors:
            if error in response.text:
                return {
                    'type': 'SQL Injection Indicator',
                    'severity': 'high',
                    'description': f'SQL error message detected: {error}'
                }
        return None

    def _check_xss_indicators(self, response) -> Optional[Dict]:
        """Check for XSS indicators."""
        if '<script>' in response.text.lower():
            return {
                'type': 'XSS Indicator',
                'severity': 'medium',
                'description': 'Potential XSS vulnerability detected'
            }
        return None

    def _check_information_disclosure(self, response) -> Optional[Dict]:
        """Check for information disclosure."""
        sensitive_info = [
            'password', 'secret', 'key', 'token', 'api_key'
        ]
        
        for info in sensitive_info:
            if info in response.text.lower():
                return {
                    'type': 'Information Disclosure',
                    'severity': 'high',
                    'description': f'Sensitive information detected: {info}'
                }
        return None

    def _mock_passive_data(self, domain: str) -> Dict[str, Any]:
        """Generate mock data for dry run mode."""
        return {
            'domain': domain,
            'collection_type': 'passive',
            'timestamp': datetime.utcnow().isoformat(),
            'dns_records': {
                'A': ['192.168.1.1'],
                'MX': ['mail.example.com']
            },
            'whois_info': {
                'registrar': 'Example Registrar',
                'creation_date': '2020-01-01T00:00:00Z'
            },
            'security_headers': {
                'present_headers': [],
                'missing_headers': ['Strict-Transport-Security'],
                'security_score': 50
            }
        }

    def _mock_enhanced_data(self, domain: str) -> Dict[str, Any]:
        """Generate mock enhanced data for dry run mode."""
        return {
            'domain': domain,
            'collection_type': 'enhanced',
            'timestamp': datetime.utcnow().isoformat(),
            'subdomains': [f'www.{domain}', f'api.{domain}'],
            'technology_stack': {
                'web_server': 'Nginx',
                'cms': 'WordPress'
            },
            'vulnerabilities': {
                'vulnerability_count': 2,
                'critical_count': 0,
                'high_count': 1,
                'medium_count': 1,
                'low_count': 0
            }
        }
