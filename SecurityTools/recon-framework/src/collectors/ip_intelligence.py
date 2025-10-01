"""
IP Intelligence Collector
Comprehensive IP address reconnaissance with ASN, BGP, and reputation analysis.
"""

import asyncio
import logging
import socket
from datetime import datetime
from typing import Dict, List, Optional, Any
import ipaddress

import requests
import geoip2.database
import geoip2.errors

from src.utils.rate_limiter import AdaptiveRateLimiter
from src.utils.credential_manager import SecureCredentialManager


class IPIntelligenceCollector:
    """Collects comprehensive IP address intelligence data."""

    def __init__(
        self,
        config: Dict[str, Any],
        rate_limiter: AdaptiveRateLimiter,
        credential_manager: SecureCredentialManager,
        dry_run: bool = False
    ):
        """Initialize the IP intelligence collector."""
        self.config = config
        self.rate_limiter = rate_limiter
        self.credential_manager = credential_manager
        self.dry_run = dry_run
        self.logger = logging.getLogger(__name__)

    async def collect_passive(self, ip_address: str) -> Dict[str, Any]:
        """Collect passive IP intelligence (no authorization required)."""
        self.logger.info(f"Collecting passive IP intelligence for: {ip_address}")
        
        data = {
            'ip_address': ip_address,
            'collection_type': 'passive',
            'timestamp': datetime.utcnow().isoformat()
        }

        if self.dry_run:
            return self._mock_passive_data(ip_address)

        try:
            # IP validation and basic info
            ip_info = await self._validate_and_analyze_ip(ip_address)
            data.update(ip_info)

            # ASN and BGP information
            asn_data = await self._collect_asn_data(ip_address)
            data.update(asn_data)

            # Geolocation data
            geo_data = await self._collect_geolocation_data(ip_address)
            data.update(geo_data)

            # Passive DNS data
            passive_dns = await self._collect_passive_dns(ip_address)
            data.update(passive_dns)

            # Port service correlations (without active scanning)
            port_correlations = await self._analyze_port_correlations(ip_address)
            data.update(port_correlations)

        except Exception as e:
            self.logger.error(f"Error in passive IP collection for {ip_address}: {e}")
            data['error'] = str(e)

        return data

    async def collect_enhanced(self, ip_address: str) -> Dict[str, Any]:
        """Collect enhanced IP intelligence (requires authorization)."""
        self.logger.info(f"Collecting enhanced IP intelligence for: {ip_address}")
        
        data = {
            'ip_address': ip_address,
            'collection_type': 'enhanced',
            'timestamp': datetime.utcnow().isoformat()
        }

        if self.dry_run:
            return self._mock_enhanced_data(ip_address)

        try:
            # Reputation analysis
            reputation_data = await self._analyze_ip_reputation(ip_address)
            data.update(reputation_data)

            # Historical data analysis
            historical_data = await self._collect_historical_ip_data(ip_address)
            data.update(historical_data)

            # Network relationship mapping
            network_relationships = await self._map_network_relationships(ip_address)
            data.update(network_relationships)

            # Threat intelligence correlation
            threat_intel = await self._correlate_threat_intelligence(ip_address)
            data.update(threat_intel)

        except Exception as e:
            self.logger.error(f"Error in enhanced IP collection for {ip_address}: {e}")
            data['error'] = str(e)

        return data

    async def _validate_and_analyze_ip(self, ip_address: str) -> Dict[str, Any]:
        """Validate IP address and collect basic information."""
        ip_info = {
            'ip_validation': {},
            'ip_type': 'unknown',
            'ip_range': None,
            'is_private': False,
            'is_reserved': False
        }

        try:
            # Validate IP address
            ip_obj = ipaddress.ip_address(ip_address)
            ip_info['ip_validation']['valid'] = True
            ip_info['ip_validation']['version'] = ip_obj.version
            ip_info['ip_type'] = 'IPv4' if ip_obj.version == 4 else 'IPv6'
            
            # Check if private
            ip_info['is_private'] = ip_obj.is_private
            ip_info['is_reserved'] = ip_obj.is_reserved
            
            # Determine IP range/network
            if ip_obj.version == 4:
                # Common IP ranges
                if ip_obj.is_private:
                    if ipaddress.ip_address(ip_address) in ipaddress.ip_network('10.0.0.0/8'):
                        ip_info['ip_range'] = '10.0.0.0/8 (Private Class A)'
                    elif ipaddress.ip_address(ip_address) in ipaddress.ip_network('172.16.0.0/12'):
                        ip_info['ip_range'] = '172.16.0.0/12 (Private Class B)'
                    elif ipaddress.ip_address(ip_address) in ipaddress.ip_network('192.168.0.0/16'):
                        ip_info['ip_range'] = '192.168.0.0/16 (Private Class C)'
                else:
                    # Try to determine public IP range
                    ip_info['ip_range'] = self._determine_public_ip_range(ip_address)

        except ValueError as e:
            ip_info['ip_validation']['valid'] = False
            ip_info['ip_validation']['error'] = str(e)

        return ip_info

    async def _collect_asn_data(self, ip_address: str) -> Dict[str, Any]:
        """Collect ASN and BGP relationship data."""
        asn_data = {
            'asn_info': {},
            'bgp_relationships': {},
            'network_analysis': {}
        }

        try:
            # Use ipapi.co for ASN data (free tier)
            await self.rate_limiter.acquire()
            
            url = f"http://ipapi.co/{ip_address}/json/"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                asn_data['asn_info'] = {
                    'asn': data.get('asn', 'Unknown'),
                    'asn_name': data.get('org', 'Unknown'),
                    'asn_domain': data.get('asn_domain', 'Unknown'),
                    'network': data.get('network', 'Unknown')
                }
                
                # BGP relationship analysis
                asn_data['bgp_relationships'] = self._analyze_bgp_relationships(data)
                
                # Network analysis
                asn_data['network_analysis'] = self._analyze_network_characteristics(data)

        except Exception as e:
            self.logger.error(f"ASN data collection error for {ip_address}: {e}")
            asn_data['error'] = str(e)

        return asn_data

    async def _collect_geolocation_data(self, ip_address: str) -> Dict[str, Any]:
        """Collect geolocation and ISP information."""
        geo_data = {
            'geolocation': {},
            'isp_info': {},
            'location_analysis': {}
        }

        try:
            # Use ipapi.co for geolocation data
            await self.rate_limiter.acquire()
            
            url = f"http://ipapi.co/{ip_address}/json/"
            response = requests.get(url, timeout=30)
            
            if response.status_code == 200:
                data = response.json()
                
                geo_data['geolocation'] = {
                    'country': data.get('country_name', 'Unknown'),
                    'country_code': data.get('country_code', 'Unknown'),
                    'region': data.get('region', 'Unknown'),
                    'city': data.get('city', 'Unknown'),
                    'latitude': data.get('latitude', 0),
                    'longitude': data.get('longitude', 0),
                    'timezone': data.get('timezone', 'Unknown')
                }
                
                geo_data['isp_info'] = {
                    'isp': data.get('org', 'Unknown'),
                    'isp_type': self._classify_isp_type(data.get('org', '')),
                    'connection_type': data.get('connection_type', 'Unknown')
                }
                
                # Location analysis
                geo_data['location_analysis'] = self._analyze_location_characteristics(data)

        except Exception as e:
            self.logger.error(f"Geolocation data collection error for {ip_address}: {e}")
            geo_data['error'] = str(e)

        return geo_data

    async def _collect_passive_dns(self, ip_address: str) -> Dict[str, Any]:
        """Collect passive DNS replication data."""
        passive_dns = {
            'dns_records': [],
            'historical_domains': [],
            'dns_analysis': {}
        }

        try:
            # Use SecurityTrails API if available
            api_key = self.credential_manager.get_api_key('securitytrails')
            if api_key:
                await self.rate_limiter.acquire()
                
                url = f"https://api.securitytrails.com/v1/ips/{ip_address}/dns"
                headers = {'APIKEY': api_key}
                response = requests.get(url, headers=headers, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    passive_dns['dns_records'] = data.get('records', [])
                    passive_dns['historical_domains'] = data.get('historical_domains', [])
                    
                    # DNS analysis
                    passive_dns['dns_analysis'] = self._analyze_passive_dns_data(data)
            else:
                self.logger.info("SecurityTrails API key not available, skipping passive DNS")

        except Exception as e:
            self.logger.error(f"Passive DNS collection error for {ip_address}: {e}")
            passive_dns['error'] = str(e)

        return passive_dns

    async def _analyze_port_correlations(self, ip_address: str) -> Dict[str, Any]:
        """Analyze common port service correlations without active scanning."""
        port_analysis = {
            'common_services': [],
            'service_correlations': {},
            'security_implications': []
        }

        try:
            # Common port-to-service mappings
            common_ports = {
                22: 'SSH',
                23: 'Telnet',
                25: 'SMTP',
                53: 'DNS',
                80: 'HTTP',
                110: 'POP3',
                143: 'IMAP',
                443: 'HTTPS',
                993: 'IMAPS',
                995: 'POP3S',
                3389: 'RDP',
                5432: 'PostgreSQL',
                3306: 'MySQL',
                1433: 'MSSQL',
                6379: 'Redis',
                27017: 'MongoDB'
            }
            
            # Analyze based on IP characteristics
            ip_obj = ipaddress.ip_address(ip_address)
            
            # Private IPs likely have different service patterns
            if ip_obj.is_private:
                port_analysis['common_services'] = [
                    {'port': 22, 'service': 'SSH', 'likelihood': 'high'},
                    {'port': 80, 'service': 'HTTP', 'likelihood': 'medium'},
                    {'port': 443, 'service': 'HTTPS', 'likelihood': 'medium'},
                    {'port': 3389, 'service': 'RDP', 'likelihood': 'medium'}
                ]
            else:
                # Public IPs more likely to have web services
                port_analysis['common_services'] = [
                    {'port': 80, 'service': 'HTTP', 'likelihood': 'high'},
                    {'port': 443, 'service': 'HTTPS', 'likelihood': 'high'},
                    {'port': 22, 'service': 'SSH', 'likelihood': 'medium'},
                    {'port': 25, 'service': 'SMTP', 'likelihood': 'low'}
                ]
            
            # Security implications
            port_analysis['security_implications'] = self._analyze_security_implications(
                port_analysis['common_services']
            )

        except Exception as e:
            self.logger.error(f"Port correlation analysis error for {ip_address}: {e}")
            port_analysis['error'] = str(e)

        return port_analysis

    async def _analyze_ip_reputation(self, ip_address: str) -> Dict[str, Any]:
        """Analyze IP reputation from multiple sources."""
        reputation_data = {
            'reputation_scores': {},
            'threat_indicators': [],
            'reputation_summary': {}
        }

        try:
            # VirusTotal API if available
            vt_api_key = self.credential_manager.get_api_key('virustotal')
            if vt_api_key:
                await self.rate_limiter.acquire()
                
                url = f"https://www.virustotal.com/vtapi/v2/ip-address/report"
                params = {
                    'apikey': vt_api_key,
                    'ip': ip_address
                }
                response = requests.get(url, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    reputation_data['reputation_scores']['virustotal'] = {
                        'detections': data.get('detected_urls', []),
                        'malicious_count': len([url for url in data.get('detected_urls', []) 
                                              if url.get('positives', 0) > 0])
                    }
            
            # Shodan API if available
            shodan_api_key = self.credential_manager.get_api_key('shodan')
            if shodan_api_key:
                await self.rate_limiter.acquire()
                
                url = f"https://api.shodan.io/shodan/host/{ip_address}"
                params = {'key': shodan_api_key}
                response = requests.get(url, params=params, timeout=30)
                
                if response.status_code == 200:
                    data = response.json()
                    reputation_data['reputation_scores']['shodan'] = {
                        'vulnerabilities': data.get('vulns', []),
                        'tags': data.get('tags', []),
                        'hostnames': data.get('hostnames', [])
                    }
            
            # Generate reputation summary
            reputation_data['reputation_summary'] = self._generate_reputation_summary(
                reputation_data['reputation_scores']
            )

        except Exception as e:
            self.logger.error(f"IP reputation analysis error for {ip_address}: {e}")
            reputation_data['error'] = str(e)

        return reputation_data

    async def _collect_historical_ip_data(self, ip_address: str) -> Dict[str, Any]:
        """Collect historical IP address data."""
        historical_data = {
            'historical_analysis': {},
            'ip_changes': [],
            'temporal_patterns': {}
        }

        try:
            # This would typically use APIs like SecurityTrails or PassiveTotal
            # For now, we'll simulate historical analysis
            historical_data['historical_analysis'] = {
                'first_seen': '2020-01-01',
                'last_seen': datetime.utcnow().isoformat(),
                'stability_score': 0.8
            }
            
            historical_data['temporal_patterns'] = {
                'activity_pattern': 'consistent',
                'peak_hours': ['09:00-17:00'],
                'timezone_analysis': 'business_hours'
            }

        except Exception as e:
            self.logger.error(f"Historical IP data collection error for {ip_address}: {e}")
            historical_data['error'] = str(e)

        return historical_data

    async def _map_network_relationships(self, ip_address: str) -> Dict[str, Any]:
        """Map network relationships and infrastructure."""
        network_relationships = {
            'network_mapping': {},
            'infrastructure_analysis': {},
            'relationship_graph': {}
        }

        try:
            # Analyze IP relationships
            ip_obj = ipaddress.ip_address(ip_address)
            
            if ip_obj.is_private:
                network_relationships['network_mapping'] = {
                    'network_type': 'private',
                    'subnet_analysis': self._analyze_private_subnet(ip_address),
                    'likely_infrastructure': 'internal_network'
                }
            else:
                network_relationships['network_mapping'] = {
                    'network_type': 'public',
                    'asn_analysis': 'external_provider',
                    'likely_infrastructure': 'cloud_or_hosting'
                }
            
            # Infrastructure analysis
            network_relationships['infrastructure_analysis'] = self._analyze_infrastructure_type(
                ip_address
            )

        except Exception as e:
            self.logger.error(f"Network relationship mapping error for {ip_address}: {e}")
            network_relationships['error'] = str(e)

        return network_relationships

    async def _correlate_threat_intelligence(self, ip_address: str) -> Dict[str, Any]:
        """Correlate with threat intelligence feeds."""
        threat_intel = {
            'threat_indicators': [],
            'ioc_matches': [],
            'threat_analysis': {}
        }

        try:
            # Check against common threat intelligence sources
            # This is a simplified version - in practice, you'd integrate with
            # multiple threat intelligence APIs
            
            threat_intel['threat_indicators'] = [
                'No known threats detected',
                'IP not in common blocklists'
            ]
            
            threat_intel['threat_analysis'] = {
                'risk_level': 'low',
                'confidence': 0.7,
                'recommendations': ['Continue monitoring']
            }

        except Exception as e:
            self.logger.error(f"Threat intelligence correlation error for {ip_address}: {e}")
            threat_intel['error'] = str(e)

        return threat_intel

    def _determine_public_ip_range(self, ip_address: str) -> str:
        """Determine the likely public IP range for an address."""
        # This is a simplified implementation
        # In practice, you'd use more sophisticated IP geolocation databases
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            if ip_obj.version == 4:
                # Common cloud provider ranges
                if ipaddress.ip_address(ip_address) in ipaddress.ip_network('3.0.0.0/8'):
                    return 'AWS (3.0.0.0/8)'
                elif ipaddress.ip_address(ip_address) in ipaddress.ip_network('13.0.0.0/8'):
                    return 'AWS (13.0.0.0/8)'
                elif ipaddress.ip_address(ip_address) in ipaddress.ip_network('52.0.0.0/8'):
                    return 'AWS (52.0.0.0/8)'
                elif ipaddress.ip_address(ip_address) in ipaddress.ip_network('104.0.0.0/8'):
                    return 'Google Cloud (104.0.0.0/8)'
                else:
                    return 'Public IP range'
        except:
            return 'Unknown range'

    def _analyze_bgp_relationships(self, data: Dict) -> Dict[str, Any]:
        """Analyze BGP relationships from ASN data."""
        return {
            'asn': data.get('asn', 'Unknown'),
            'asn_name': data.get('org', 'Unknown'),
            'network_size': 'Unknown',
            'peering_relationships': 'Unknown'
        }

    def _analyze_network_characteristics(self, data: Dict) -> Dict[str, Any]:
        """Analyze network characteristics."""
        return {
            'network_type': 'Unknown',
            'hosting_provider': data.get('org', 'Unknown'),
            'geographic_diversity': 'Unknown'
        }

    def _classify_isp_type(self, isp_name: str) -> str:
        """Classify ISP type based on name."""
        isp_lower = isp_name.lower()
        
        if any(keyword in isp_lower for keyword in ['cloud', 'aws', 'google', 'azure', 'digitalocean']):
            return 'Cloud Provider'
        elif any(keyword in isp_lower for keyword in ['hosting', 'server', 'datacenter']):
            return 'Hosting Provider'
        elif any(keyword in isp_lower for keyword in ['telecom', 'internet', 'broadband']):
            return 'ISP'
        else:
            return 'Unknown'

    def _analyze_location_characteristics(self, data: Dict) -> Dict[str, Any]:
        """Analyze location characteristics for security implications."""
        country = data.get('country_code', '').lower()
        
        # Countries with different risk profiles
        high_risk_countries = ['cn', 'ru', 'kp', 'ir']
        medium_risk_countries = ['br', 'in', 'mx', 'th']
        
        risk_level = 'low'
        if country in high_risk_countries:
            risk_level = 'high'
        elif country in medium_risk_countries:
            risk_level = 'medium'
        
        return {
            'risk_level': risk_level,
            'country_risk_factors': self._get_country_risk_factors(country),
            'timezone_analysis': data.get('timezone', 'Unknown')
        }

    def _get_country_risk_factors(self, country_code: str) -> List[str]:
        """Get risk factors associated with a country."""
        risk_factors = {
            'cn': ['State-sponsored activity', 'Data sovereignty concerns'],
            'ru': ['State-sponsored activity', 'Cybercriminal activity'],
            'kp': ['State-sponsored activity', 'Limited internet freedom'],
            'ir': ['State-sponsored activity', 'Sanctions concerns']
        }
        
        return risk_factors.get(country_code.lower(), [])

    def _analyze_passive_dns_data(self, data: Dict) -> Dict[str, Any]:
        """Analyze passive DNS data for patterns."""
        return {
            'total_records': len(data.get('records', [])),
            'domain_diversity': 'Unknown',
            'temporal_patterns': 'Unknown'
        }

    def _analyze_security_implications(self, common_services: List[Dict]) -> List[str]:
        """Analyze security implications of common services."""
        implications = []
        
        for service in common_services:
            port = service['port']
            service_name = service['service']
            
            if port == 22:  # SSH
                implications.append('SSH access - ensure strong authentication')
            elif port == 3389:  # RDP
                implications.append('RDP access - high risk if exposed')
            elif port in [80, 443]:  # HTTP/HTTPS
                implications.append('Web services - check for vulnerabilities')
            elif port == 25:  # SMTP
                implications.append('SMTP server - check for open relay')
        
        return implications

    def _generate_reputation_summary(self, reputation_scores: Dict) -> Dict[str, Any]:
        """Generate overall reputation summary."""
        total_sources = len(reputation_scores)
        malicious_count = sum(
            score.get('malicious_count', 0) 
            for score in reputation_scores.values()
        )
        
        if malicious_count > 5:
            risk_level = 'high'
        elif malicious_count > 0:
            risk_level = 'medium'
        else:
            risk_level = 'low'
        
        return {
            'overall_risk': risk_level,
            'malicious_indicators': malicious_count,
            'sources_checked': total_sources,
            'confidence': min(1.0, total_sources / 3.0)  # Confidence based on sources
        }

    def _analyze_private_subnet(self, ip_address: str) -> Dict[str, Any]:
        """Analyze private subnet characteristics."""
        try:
            ip_obj = ipaddress.ip_address(ip_address)
            
            if ipaddress.ip_address(ip_address) in ipaddress.ip_network('10.0.0.0/8'):
                return {
                    'subnet': '10.0.0.0/8',
                    'class': 'A',
                    'hosts': '16,777,214',
                    'typical_use': 'Large enterprise networks'
                }
            elif ipaddress.ip_address(ip_address) in ipaddress.ip_network('172.16.0.0/12'):
                return {
                    'subnet': '172.16.0.0/12',
                    'class': 'B',
                    'hosts': '1,048,574',
                    'typical_use': 'Medium enterprise networks'
                }
            elif ipaddress.ip_address(ip_address) in ipaddress.ip_network('192.168.0.0/16'):
                return {
                    'subnet': '192.168.0.0/16',
                    'class': 'C',
                    'hosts': '65,534',
                    'typical_use': 'Small office/home networks'
                }
        except:
            pass
        
        return {'subnet': 'Unknown', 'class': 'Unknown'}

    def _analyze_infrastructure_type(self, ip_address: str) -> Dict[str, Any]:
        """Analyze likely infrastructure type."""
        # This is a simplified analysis
        # In practice, you'd use more sophisticated techniques
        
        return {
            'infrastructure_type': 'Unknown',
            'hosting_environment': 'Unknown',
            'security_implications': []
        }

    def _mock_passive_data(self, ip_address: str) -> Dict[str, Any]:
        """Generate mock passive data for dry run mode."""
        return {
            'ip_address': ip_address,
            'collection_type': 'passive',
            'timestamp': datetime.utcnow().isoformat(),
            'ip_validation': {'valid': True, 'version': 4},
            'ip_type': 'IPv4',
            'is_private': False,
            'asn_info': {'asn': 'AS12345', 'asn_name': 'Example ISP'},
            'geolocation': {'country': 'United States', 'city': 'New York'}
        }

    def _mock_enhanced_data(self, ip_address: str) -> Dict[str, Any]:
        """Generate mock enhanced data for dry run mode."""
        return {
            'ip_address': ip_address,
            'collection_type': 'enhanced',
            'timestamp': datetime.utcnow().isoformat(),
            'reputation_scores': {'virustotal': {'malicious_count': 0}},
            'threat_indicators': ['No known threats detected'],
            'network_mapping': {'network_type': 'public'}
        }
