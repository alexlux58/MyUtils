"""
Operational Security Validator
Validates scans and operations for OPSEC compliance.
"""

import logging
import re
from typing import Dict, Any, List, Optional
from datetime import datetime, timedelta


class OpSecValidator:
    """Validates operations for operational security compliance."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the OPSEC validator."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        
        # OPSEC rules and restrictions
        self.restricted_domains = self._load_restricted_domains()
        self.restricted_ips = self._load_restricted_ips()
        self.sensitive_keywords = self._load_sensitive_keywords()
        
        # Rate limiting for validation
        self.validation_history = {}
        self.max_validations_per_hour = 100

    def validate_scan(self, target: str, sensitivity_level: str) -> bool:
        """Validate if a scan is allowed for OPSEC compliance."""
        self.logger.info(f"Validating scan for {target} with sensitivity {sensitivity_level}")
        
        try:
            # Check basic validation rules
            if not self._basic_validation(target, sensitivity_level):
                return False
            
            # Check sensitivity-based restrictions
            if not self._sensitivity_validation(target, sensitivity_level):
                return False
            
            # Check domain restrictions
            if not self._domain_validation(target):
                return False
            
            # Check IP restrictions
            if not self._ip_validation(target):
                return False
            
            # Check keyword restrictions
            if not self._keyword_validation(target):
                return False
            
            # Check rate limiting
            if not self._rate_limit_validation(target):
                return False
            
            # Log validation success
            self._log_validation(target, sensitivity_level, True)
            return True
            
        except Exception as e:
            self.logger.error(f"OPSEC validation error for {target}: {e}")
            self._log_validation(target, sensitivity_level, False, str(e))
            return False

    def _basic_validation(self, target: str, sensitivity_level: str) -> bool:
        """Perform basic validation checks."""
        # Check if target is empty or invalid
        if not target or not target.strip():
            self.logger.warning("Empty or invalid target")
            return False
        
        # Check sensitivity level
        valid_sensitivity_levels = ['public', 'low', 'med', 'high']
        if sensitivity_level not in valid_sensitivity_levels:
            self.logger.warning(f"Invalid sensitivity level: {sensitivity_level}")
            return False
        
        # Check target format
        if not self._is_valid_target_format(target):
            self.logger.warning(f"Invalid target format: {target}")
            return False
        
        return True

    def _sensitivity_validation(self, target: str, sensitivity_level: str) -> bool:
        """Validate based on sensitivity level."""
        # High sensitivity targets require additional checks
        if sensitivity_level == 'high':
            # Check if target is in high-sensitivity list
            if not self._is_authorized_high_sensitivity(target):
                self.logger.warning(f"Target {target} not authorized for high sensitivity scanning")
                return False
        
        # Medium sensitivity targets
        elif sensitivity_level == 'med':
            # Check if target is in medium-sensitivity restrictions
            if self._is_restricted_medium_sensitivity(target):
                self.logger.warning(f"Target {target} restricted for medium sensitivity scanning")
                return False
        
        return True

    def _domain_validation(self, target: str) -> bool:
        """Validate domain targets."""
        if not self._is_domain(target):
            return True
        
        # Check against restricted domains
        for restricted_domain in self.restricted_domains:
            if self._matches_domain_pattern(target, restricted_domain):
                self.logger.warning(f"Target {target} matches restricted domain pattern: {restricted_domain}")
                return False
        
        # Check for government/military domains
        if self._is_government_domain(target):
            self.logger.warning(f"Target {target} appears to be a government domain")
            return False
        
        # Check for critical infrastructure domains
        if self._is_critical_infrastructure_domain(target):
            self.logger.warning(f"Target {target} appears to be critical infrastructure")
            return False
        
        return True

    def _ip_validation(self, target: str) -> bool:
        """Validate IP address targets."""
        if not self._is_ip_address(target):
            return True
        
        # Check against restricted IP ranges
        for restricted_ip in self.restricted_ips:
            if self._matches_ip_pattern(target, restricted_ip):
                self.logger.warning(f"Target {target} matches restricted IP pattern: {restricted_ip}")
                return False
        
        # Check for private IP ranges
        if self._is_private_ip(target):
            self.logger.warning(f"Target {target} is a private IP address")
            return False
        
        # Check for reserved IP ranges
        if self._is_reserved_ip(target):
            self.logger.warning(f"Target {target} is a reserved IP address")
            return False
        
        return True

    def _keyword_validation(self, target: str) -> bool:
        """Validate against sensitive keywords."""
        target_lower = target.lower()
        
        for keyword in self.sensitive_keywords:
            if keyword.lower() in target_lower:
                self.logger.warning(f"Target {target} contains sensitive keyword: {keyword}")
                return False
        
        return True

    def _rate_limit_validation(self, target: str) -> bool:
        """Validate rate limiting for scans."""
        current_time = datetime.now()
        hour_key = current_time.strftime("%Y-%m-%d-%H")
        
        # Initialize validation history for this hour
        if hour_key not in self.validation_history:
            self.validation_history[hour_key] = []
        
        # Clean old entries
        cutoff_time = current_time - timedelta(hours=1)
        self.validation_history[hour_key] = [
            entry for entry in self.validation_history[hour_key]
            if entry['timestamp'] > cutoff_time
        ]
        
        # Check rate limit
        if len(self.validation_history[hour_key]) >= self.max_validations_per_hour:
            self.logger.warning(f"Rate limit exceeded for validations in hour {hour_key}")
            return False
        
        return True

    def _is_valid_target_format(self, target: str) -> bool:
        """Check if target has valid format."""
        # Check for basic format validity
        if len(target) < 3 or len(target) > 255:
            return False
        
        # Check for valid characters
        if not re.match(r'^[a-zA-Z0-9.-@_]+$', target):
            return False
        
        return True

    def _is_domain(self, target: str) -> bool:
        """Check if target is a domain."""
        # Basic domain pattern check
        domain_pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*$'
        return bool(re.match(domain_pattern, target))

    def _is_ip_address(self, target: str) -> bool:
        """Check if target is an IP address."""
        # IPv4 pattern
        ipv4_pattern = r'^(\d{1,3}\.){3}\d{1,3}$'
        if re.match(ipv4_pattern, target):
            # Validate IP range
            parts = target.split('.')
            return all(0 <= int(part) <= 255 for part in parts)
        
        # IPv6 pattern (simplified)
        ipv6_pattern = r'^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$'
        return bool(re.match(ipv6_pattern, target))

    def _matches_domain_pattern(self, target: str, pattern: str) -> bool:
        """Check if target matches domain pattern."""
        # Convert pattern to regex
        regex_pattern = pattern.replace('*', '.*')
        return bool(re.match(regex_pattern, target, re.IGNORECASE))

    def _matches_ip_pattern(self, target: str, pattern: str) -> bool:
        """Check if target matches IP pattern."""
        # Handle CIDR notation
        if '/' in pattern:
            try:
                import ipaddress
                return ipaddress.ip_address(target) in ipaddress.ip_network(pattern)
            except:
                return False
        
        # Handle exact match
        return target == pattern

    def _is_government_domain(self, target: str) -> bool:
        """Check if target is a government domain."""
        government_tlds = ['.gov', '.mil', '.gov.uk', '.gov.au', '.gov.ca']
        return any(target.endswith(tld) for tld in government_tlds)

    def _is_critical_infrastructure_domain(self, target: str) -> bool:
        """Check if target is critical infrastructure."""
        critical_keywords = [
            'power', 'electric', 'grid', 'water', 'sewer', 'gas',
            'transport', 'airport', 'railway', 'hospital', 'bank',
            'financial', 'telecom', 'internet', 'dns', 'root'
        ]
        
        target_lower = target.lower()
        return any(keyword in target_lower for keyword in critical_keywords)

    def _is_private_ip(self, target: str) -> bool:
        """Check if target is a private IP address."""
        if not self._is_ip_address(target):
            return False
        
        try:
            import ipaddress
            ip = ipaddress.ip_address(target)
            return ip.is_private
        except:
            return False

    def _is_reserved_ip(self, target: str) -> bool:
        """Check if target is a reserved IP address."""
        if not self._is_ip_address(target):
            return False
        
        try:
            import ipaddress
            ip = ipaddress.ip_address(target)
            return ip.is_reserved or ip.is_loopback or ip.is_multicast
        except:
            return False

    def _is_authorized_high_sensitivity(self, target: str) -> bool:
        """Check if target is authorized for high sensitivity scanning."""
        # This would typically check against an authorization list
        # For now, we'll implement basic checks
        authorized_domains = self.config.get('authorized_high_sensitivity', [])
        return target in authorized_domains

    def _is_restricted_medium_sensitivity(self, target: str) -> bool:
        """Check if target is restricted for medium sensitivity scanning."""
        # This would typically check against a restriction list
        restricted_domains = self.config.get('restricted_medium_sensitivity', [])
        return target in restricted_domains

    def _load_restricted_domains(self) -> List[str]:
        """Load restricted domain patterns."""
        return self.config.get('restricted_domains', [
            '*.gov', '*.mil', '*.gov.uk', '*.gov.au', '*.gov.ca',
            '*.edu', '*.ac.uk', '*.edu.au', '*.edu.ca'
        ])

    def _load_restricted_ips(self) -> List[str]:
        """Load restricted IP patterns."""
        return self.config.get('restricted_ips', [
            '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
            '127.0.0.0/8', '169.254.0.0/16'
        ])

    def _load_sensitive_keywords(self) -> List[str]:
        """Load sensitive keywords."""
        return self.config.get('sensitive_keywords', [
            'classified', 'secret', 'topsecret', 'confidential',
            'internal', 'restricted', 'sensitive', 'private'
        ])

    def _log_validation(self, target: str, sensitivity_level: str, success: bool, error: str = None) -> None:
        """Log validation attempt."""
        current_time = datetime.now()
        hour_key = current_time.strftime("%Y-%m-%d-%H")
        
        validation_entry = {
            'target': target,
            'sensitivity_level': sensitivity_level,
            'success': success,
            'error': error,
            'timestamp': current_time
        }
        
        if hour_key not in self.validation_history:
            self.validation_history[hour_key] = []
        
        self.validation_history[hour_key].append(validation_entry)
        
        # Log the validation
        if success:
            self.logger.info(f"OPSEC validation passed for {target}")
        else:
            self.logger.warning(f"OPSEC validation failed for {target}: {error}")

    def get_validation_stats(self) -> Dict[str, Any]:
        """Get validation statistics."""
        current_time = datetime.now()
        hour_key = current_time.strftime("%Y-%m-%d-%H")
        
        total_validations = 0
        successful_validations = 0
        failed_validations = 0
        
        for hour, validations in self.validation_history.items():
            total_validations += len(validations)
            successful_validations += len([v for v in validations if v['success']])
            failed_validations += len([v for v in validations if not v['success']])
        
        return {
            'total_validations': total_validations,
            'successful_validations': successful_validations,
            'failed_validations': failed_validations,
            'success_rate': successful_validations / total_validations if total_validations > 0 else 0,
            'current_hour_validations': len(self.validation_history.get(hour_key, [])),
            'max_validations_per_hour': self.max_validations_per_hour
        }

    def add_restricted_domain(self, domain_pattern: str) -> None:
        """Add a restricted domain pattern."""
        if domain_pattern not in self.restricted_domains:
            self.restricted_domains.append(domain_pattern)
            self.logger.info(f"Added restricted domain pattern: {domain_pattern}")

    def add_restricted_ip(self, ip_pattern: str) -> None:
        """Add a restricted IP pattern."""
        if ip_pattern not in self.restricted_ips:
            self.restricted_ips.append(ip_pattern)
            self.logger.info(f"Added restricted IP pattern: {ip_pattern}")

    def add_sensitive_keyword(self, keyword: str) -> None:
        """Add a sensitive keyword."""
        if keyword not in self.sensitive_keywords:
            self.sensitive_keywords.append(keyword)
            self.logger.info(f"Added sensitive keyword: {keyword}")

    def clear_validation_history(self) -> None:
        """Clear validation history."""
        self.validation_history.clear()
        self.logger.info("Cleared validation history")
