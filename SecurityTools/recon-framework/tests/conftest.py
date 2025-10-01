"""
Pytest configuration and fixtures.
"""

import pytest
import asyncio
import tempfile
import shutil
from pathlib import Path
from unittest.mock import Mock


@pytest.fixture(scope="session")
def event_loop():
    """Create an instance of the default event loop for the test session."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()


@pytest.fixture
def temp_dir():
    """Create a temporary directory for testing."""
    temp_path = Path(tempfile.mkdtemp())
    yield temp_path
    shutil.rmtree(temp_path)


@pytest.fixture
def mock_config():
    """Create a mock configuration for testing."""
    return {
        'framework': {
            'name': 'Test Framework',
            'version': '1.0.0',
            'debug': False,
            'dry_run': True
        },
        'rate_limiting': {
            'base_rate': 1.0,
            'max_rate': 10.0,
            'jitter_factor': 0.1,
            'backoff_multiplier': 2.0,
            'max_backoff': 300
        },
        'timeouts': {
            'http': 30,
            'dns': 10,
            'whois': 15,
            'api': 30
        },
        'retry': {
            'max_attempts': 3,
            'base_delay': 1.0,
            'max_delay': 60.0,
            'exponential_base': 2.0
        },
        'api_keys': {
            'shodan': 'test_key',
            'virustotal': 'test_key',
            'hibp': 'test_key'
        },
        'opsec_rules': {
            'restricted_domains': ['*.gov', '*.mil'],
            'restricted_ips': ['10.0.0.0/8', '192.168.0.0/16'],
            'sensitive_keywords': ['secret', 'classified'],
            'authorized_high_sensitivity': ['example.com'],
            'restricted_medium_sensitivity': ['sensitive.example.com']
        },
        'output_settings': {
            'google_sheets': {'enabled': False},
            'jsonl': {'enabled': True},
            'sqlite': {'enabled': True}
        }
    }


@pytest.fixture
def mock_inventory_data():
    """Create mock inventory data for testing."""
    return [
        {
            'inventory_id': '1',
            'input_value': 'example.com',
            'input_type': 'domain',
            'notes': 'Test domain',
            'sensitivity_level': 'public',
            'authorized_scan': True
        },
        {
            'inventory_id': '2',
            'input_value': '192.168.1.1',
            'input_type': 'ip',
            'notes': 'Test IP',
            'sensitivity_level': 'low',
            'authorized_scan': True
        },
        {
            'inventory_id': '3',
            'input_value': 'test@example.com',
            'input_type': 'email',
            'notes': 'Test email',
            'sensitivity_level': 'med',
            'authorized_scan': False
        }
    ]


@pytest.fixture
def mock_domain_intelligence():
    """Create mock domain intelligence data."""
    return {
        'domain': 'example.com',
        'dns_records': {
            'A': ['192.168.1.1'],
            'MX': ['mail.example.com']
        },
        'whois_info': {
            'registrar': 'Example Registrar',
            'creation_date': '2020-01-01T00:00:00Z',
            'expiration_date': '2025-01-01T00:00:00Z'
        },
        'security_headers': {
            'present_headers': ['X-Frame-Options'],
            'missing_headers': ['Strict-Transport-Security', 'Content-Security-Policy'],
            'security_score': 30
        },
        'vulnerabilities': {
            'vulnerability_count': 2,
            'critical_count': 0,
            'high_count': 1,
            'medium_count': 1,
            'low_count': 0,
            'vulnerabilities': [
                {
                    'type': 'XSS',
                    'severity': 'high',
                    'description': 'Cross-site scripting vulnerability'
                }
            ]
        },
        'subdomains': ['www.example.com', 'api.example.com'],
        'technology_stack': {
            'web_server': 'Nginx',
            'cms': 'WordPress',
            'javascript_libraries': ['jQuery']
        }
    }


@pytest.fixture
def mock_ip_intelligence():
    """Create mock IP intelligence data."""
    return {
        'ip_address': '192.168.1.1',
        'ip_validation': {
            'valid': True,
            'version': 4
        },
        'ip_type': 'IPv4',
        'is_private': True,
        'asn_info': {
            'asn': 'AS12345',
            'asn_name': 'Example ISP'
        },
        'geolocation': {
            'country': 'United States',
            'city': 'New York',
            'latitude': 40.7128,
            'longitude': -74.0060
        },
        'reputation_scores': {
            'virustotal': {'malicious_count': 0},
            'shodan': {'vulnerabilities': []}
        },
        'passive_dns': {
            'dns_records': [],
            'historical_domains': []
        }
    }


@pytest.fixture
def mock_digital_footprint():
    """Create mock digital footprint data."""
    return {
        'identifier': 'test@example.com',
        'identifier_type': 'email',
        'breach_analysis': {
            'breach_count': 2,
            'exposed_data': ['email_addresses', 'passwords'],
            'breach_timeline': [
                {
                    'breach_name': 'Example Breach 1',
                    'breach_date': '2020-01-01',
                    'pwn_count': 1000000
                }
            ]
        },
        'platforms': {
            'github': {'exists': True, 'platform': 'github'},
            'linkedin': {'exists': False, 'platform': 'linkedin'}
        },
        'repositories': [
            {
                'name': 'test-repo',
                'language': 'Python',
                'stars': 10,
                'is_private': False
            }
        ],
        'professional_networks': {
            'linkedin_analysis': {
                'profile_exists': False,
                'connection_count': 0
            }
        }
    }


@pytest.fixture
def mock_attack_surface():
    """Create mock attack surface analysis data."""
    return {
        'attack_surface_score': 7,
        'risk_level': 'high',
        'attack_vectors': [
            {
                'vector_type': 'web_security',
                'name': 'Missing HSTS Header',
                'severity': 'medium',
                'description': 'Missing Strict-Transport-Security header',
                'mitigation': 'Implement HSTS header'
            },
            {
                'vector_type': 'vulnerability',
                'name': 'XSS Vulnerability',
                'severity': 'high',
                'description': 'Cross-site scripting vulnerability',
                'mitigation': 'Fix XSS vulnerability'
            }
        ],
        'initial_access_vectors': [
            'Web Application Exploitation',
            'Social Engineering'
        ],
        'password_spray_candidates': [
            {
                'source': 'Example Breach',
                'breach_date': '2020-01-01',
                'password_patterns': ['password123', 'admin123'],
                'target_accounts': ['email_accounts']
            }
        ],
        'phishing_risk_level': 'medium',
        'defensive_recommendations': [
            {
                'category': 'Immediate Actions (24-48 hours)',
                'actions': [
                    {
                        'action': 'Fix high-severity vulnerabilities',
                        'timeline': '24-48 hours',
                        'priority': 'critical'
                    }
                ]
            }
        ],
        'mitre_attack_mapping': [
            {
                'attack_vector': 'XSS Vulnerability',
                'mitre_technique': 'T1059.007',
                'technique_name': 'Client-Side Code Injection',
                'tactic': 'Initial Access'
            }
        ],
        'priority_actions': [
            {
                'action': 'Fix high-severity vulnerabilities',
                'priority': 1,
                'timeline': '24 hours'
            }
        ]
    }


@pytest.fixture
def mock_correlated_data():
    """Create mock correlated data."""
    return {
        'correlation_metadata': {
            'correlation_timestamp': '2023-01-01T00:00:00Z',
            'correlation_confidence': 0.8
        },
        'domain_intelligence': {
            'domain': 'example.com',
            'dns_records': {'A': ['192.168.1.1']},
            'vulnerabilities': {'vulnerability_count': 1}
        },
        'ip_intelligence': {
            'ip_address': '192.168.1.1',
            'geolocation': {'country': 'United States'}
        },
        'digital_footprint': {
            'identifier': 'test@example.com',
            'breach_analysis': {'breach_count': 1}
        },
        'threat_indicators': [
            {
                'indicator': 'High-risk indicators detected',
                'risk_level': 'high',
                'description': 'Multiple security issues found'
            }
        ],
        'intelligence_summary': {
            'executive_summary': 'Security assessment completed with findings',
            'key_findings': ['Vulnerability found', 'Missing security headers'],
            'risk_assessment': {'overall_risk': 'high'}
        }
    }


@pytest.fixture
def mock_rate_limiter():
    """Create mock rate limiter."""
    rate_limiter = Mock()
    rate_limiter.acquire = Mock(return_value=asyncio.sleep(0))
    rate_limiter.record_success = Mock()
    rate_limiter.record_failure = Mock()
    return rate_limiter


@pytest.fixture
def mock_credential_manager():
    """Create mock credential manager."""
    credential_manager = Mock()
    credential_manager.get_api_key = Mock(return_value='test_api_key')
    credential_manager.store_api_key = Mock(return_value=True)
    credential_manager.remove_api_key = Mock(return_value=True)
    return credential_manager


@pytest.fixture
def mock_opsec_validator():
    """Create mock OPSEC validator."""
    validator = Mock()
    validator.validate_scan = Mock(return_value=True)
    validator.get_validation_stats = Mock(return_value={
        'total_validations': 10,
        'successful_validations': 8,
        'failed_validations': 2,
        'success_rate': 0.8
    })
    return validator


@pytest.fixture
def mock_logger():
    """Create mock logger."""
    logger = Mock()
    logger.info = Mock()
    logger.warning = Mock()
    logger.error = Mock()
    logger.debug = Mock()
    return logger


# Pytest configuration
def pytest_configure(config):
    """Configure pytest."""
    config.addinivalue_line(
        "markers", "slow: marks tests as slow (deselect with '-m \"not slow\"')"
    )
    config.addinivalue_line(
        "markers", "integration: marks tests as integration tests"
    )
    config.addinivalue_line(
        "markers", "unit: marks tests as unit tests"
    )


def pytest_collection_modifyitems(config, items):
    """Modify test collection."""
    for item in items:
        # Add unit marker to all tests by default
        if not any(marker.name in ['slow', 'integration'] for marker in item.iter_markers()):
            item.add_marker(pytest.mark.unit)
