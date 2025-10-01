"""
Configuration Manager
Manages configuration files and settings for the reconnaissance framework.
"""

import yaml
import json
import logging
from pathlib import Path
from typing import Dict, Any, Optional, Union


class ConfigManager:
    """Manages configuration for the reconnaissance framework."""

    def __init__(self, config_dir: str = "./config"):
        """Initialize the configuration manager."""
        self.config_dir = Path(config_dir)
        self.config_dir.mkdir(parents=True, exist_ok=True)
        self.logger = logging.getLogger(__name__)
        self._config_cache = {}

    def load_config(self) -> Dict[str, Any]:
        """Load configuration from files."""
        config = {
            'default': self._load_default_config(),
            'api_keys': self._load_api_keys(),
            'rate_limits': self._load_rate_limits(),
            'opsec_rules': self._load_opsec_rules(),
            'output_settings': self._load_output_settings()
        }
        
        # Merge configurations
        merged_config = self._merge_configs(config)
        
        # Validate configuration
        self._validate_config(merged_config)
        
        return merged_config

    def _load_default_config(self) -> Dict[str, Any]:
        """Load default configuration."""
        return {
            'framework': {
                'name': 'Enhanced Security Reconnaissance Framework',
                'version': '1.0.0',
                'debug': False,
                'dry_run': False
            },
            'logging': {
                'level': 'INFO',
                'file': 'logs/reconnaissance.log',
                'max_size': '10MB',
                'backup_count': 5
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
            }
        }

    def _load_api_keys(self) -> Dict[str, Any]:
        """Load API keys configuration."""
        api_keys_file = self.config_dir / 'api_keys.yaml'
        
        if api_keys_file.exists():
            try:
                with open(api_keys_file, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                self.logger.warning(f"Failed to load API keys: {e}")
        
        return {}

    def _load_rate_limits(self) -> Dict[str, Any]:
        """Load rate limits configuration."""
        rate_limits_file = self.config_dir / 'rate_limits.yaml'
        
        if rate_limits_file.exists():
            try:
                with open(rate_limits_file, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                self.logger.warning(f"Failed to load rate limits: {e}")
        
        return {
            'default': 1.0,
            'whois': 0.5,
            'dns': 2.0,
            'http': 5.0,
            'api': 1.0,
            'shodan': 1.0,
            'virustotal': 4.0,
            'hibp': 1.5,
            'github': 1.0
        }

    def _load_opsec_rules(self) -> Dict[str, Any]:
        """Load OPSEC rules configuration."""
        opsec_file = self.config_dir / 'opsec_rules.yaml'
        
        if opsec_file.exists():
            try:
                with open(opsec_file, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                self.logger.warning(f"Failed to load OPSEC rules: {e}")
        
        return {
            'restricted_domains': [
                '*.gov', '*.mil', '*.gov.uk', '*.gov.au', '*.gov.ca',
                '*.edu', '*.ac.uk', '*.edu.au', '*.edu.ca'
            ],
            'restricted_ips': [
                '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
                '127.0.0.0/8', '169.254.0.0/16'
            ],
            'sensitive_keywords': [
                'classified', 'secret', 'topsecret', 'confidential',
                'internal', 'restricted', 'sensitive', 'private'
            ],
            'authorized_high_sensitivity': [],
            'restricted_medium_sensitivity': []
        }

    def _load_output_settings(self) -> Dict[str, Any]:
        """Load output settings configuration."""
        output_file = self.config_dir / 'output_settings.yaml'
        
        if output_file.exists():
            try:
                with open(output_file, 'r') as f:
                    return yaml.safe_load(f) or {}
            except Exception as e:
                self.logger.warning(f"Failed to load output settings: {e}")
        
        return {
            'google_sheets': {
                'enabled': False,
                'spreadsheet_id': None,
                'credentials_file': 'credentials.json',
                'token_file': 'token.json'
            },
            'jsonl': {
                'enabled': True,
                'include_raw_data': True,
                'compress': False
            },
            'sqlite': {
                'enabled': True,
                'create_views': True,
                'index_tables': True
            },
            'reports': {
                'generate_summary': True,
                'include_charts': True,
                'export_formats': ['pdf', 'html']
            }
        }

    def _merge_configs(self, configs: Dict[str, Any]) -> Dict[str, Any]:
        """Merge multiple configuration dictionaries."""
        merged = {}
        
        for config_name, config_data in configs.items():
            if isinstance(config_data, dict):
                merged.update(config_data)
            else:
                merged[config_name] = config_data
        
        return merged

    def _validate_config(self, config: Dict[str, Any]) -> None:
        """Validate configuration values."""
        # Validate required sections
        required_sections = ['framework', 'logging', 'rate_limiting']
        for section in required_sections:
            if section not in config:
                self.logger.warning(f"Missing required configuration section: {section}")
        
        # Validate rate limiting values
        rate_limiting = config.get('rate_limiting', {})
        if 'base_rate' in rate_limiting:
            if not isinstance(rate_limiting['base_rate'], (int, float)) or rate_limiting['base_rate'] <= 0:
                self.logger.warning("Invalid base_rate value, using default")
                rate_limiting['base_rate'] = 1.0
        
        # Validate timeout values
        timeouts = config.get('timeouts', {})
        for timeout_name, timeout_value in timeouts.items():
            if not isinstance(timeout_value, (int, float)) or timeout_value <= 0:
                self.logger.warning(f"Invalid timeout value for {timeout_name}, using default")
                timeouts[timeout_name] = 30
        
        # Validate logging level
        logging_config = config.get('logging', {})
        if 'level' in logging_config:
            valid_levels = ['DEBUG', 'INFO', 'WARNING', 'ERROR', 'CRITICAL']
            if logging_config['level'].upper() not in valid_levels:
                self.logger.warning("Invalid logging level, using INFO")
                logging_config['level'] = 'INFO'

    def save_config(self, config: Dict[str, Any], filename: str = 'config.yaml') -> bool:
        """Save configuration to file."""
        try:
            config_file = self.config_dir / filename
            
            with open(config_file, 'w') as f:
                yaml.dump(config, f, default_flow_style=False, indent=2)
            
            self.logger.info(f"Configuration saved to {config_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to save configuration: {e}")
            return False

    def get_setting(self, key_path: str, default: Any = None) -> Any:
        """Get a configuration setting using dot notation."""
        keys = key_path.split('.')
        value = self._config_cache
        
        for key in keys:
            if isinstance(value, dict) and key in value:
                value = value[key]
            else:
                return default
        
        return value

    def set_setting(self, key_path: str, value: Any) -> None:
        """Set a configuration setting using dot notation."""
        keys = key_path.split('.')
        config = self._config_cache
        
        for key in keys[:-1]:
            if key not in config:
                config[key] = {}
            config = config[key]
        
        config[keys[-1]] = value

    def create_example_configs(self) -> None:
        """Create example configuration files."""
        # API keys example
        api_keys_example = {
            'shodan': 'your_shodan_api_key_here',
            'virustotal': 'your_virustotal_api_key_here',
            'hibp': 'your_hibp_api_key_here',
            'github': 'your_github_token_here',
            'securitytrails': 'your_securitytrails_api_key_here',
            'censys': 'your_censys_id:your_censys_secret_here'
        }
        
        api_keys_file = self.config_dir / 'api_keys.yaml.example'
        with open(api_keys_file, 'w') as f:
            yaml.dump(api_keys_example, f, default_flow_style=False, indent=2)
        
        # Rate limits example
        rate_limits_example = {
            'default': 1.0,
            'whois': 0.5,
            'dns': 2.0,
            'http': 5.0,
            'api': 1.0,
            'shodan': 1.0,
            'virustotal': 4.0,
            'hibp': 1.5,
            'github': 1.0
        }
        
        rate_limits_file = self.config_dir / 'rate_limits.yaml.example'
        with open(rate_limits_file, 'w') as f:
            yaml.dump(rate_limits_example, f, default_flow_style=False, indent=2)
        
        # OPSEC rules example
        opsec_rules_example = {
            'restricted_domains': [
                '*.gov', '*.mil', '*.gov.uk', '*.gov.au', '*.gov.ca',
                '*.edu', '*.ac.uk', '*.edu.au', '*.edu.ca'
            ],
            'restricted_ips': [
                '10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16',
                '127.0.0.0/8', '169.254.0.0/16'
            ],
            'sensitive_keywords': [
                'classified', 'secret', 'topsecret', 'confidential',
                'internal', 'restricted', 'sensitive', 'private'
            ],
            'authorized_high_sensitivity': [
                'example.com',
                'test.example.com'
            ],
            'restricted_medium_sensitivity': [
                'sensitive.example.com'
            ]
        }
        
        opsec_file = self.config_dir / 'opsec_rules.yaml.example'
        with open(opsec_file, 'w') as f:
            yaml.dump(opsec_rules_example, f, default_flow_style=False, indent=2)
        
        # Output settings example
        output_settings_example = {
            'google_sheets': {
                'enabled': False,
                'spreadsheet_id': None,
                'credentials_file': 'credentials.json',
                'token_file': 'token.json'
            },
            'jsonl': {
                'enabled': True,
                'include_raw_data': True,
                'compress': False
            },
            'sqlite': {
                'enabled': True,
                'create_views': True,
                'index_tables': True
            },
            'reports': {
                'generate_summary': True,
                'include_charts': True,
                'export_formats': ['pdf', 'html']
            }
        }
        
        output_file = self.config_dir / 'output_settings.yaml.example'
        with open(output_file, 'w') as f:
            yaml.dump(output_settings_example, f, default_flow_style=False, indent=2)
        
        self.logger.info(f"Example configuration files created in {self.config_dir}")

    def reload_config(self) -> Dict[str, Any]:
        """Reload configuration from files."""
        self._config_cache.clear()
        return self.load_config()

    def get_config_summary(self) -> Dict[str, Any]:
        """Get a summary of the current configuration."""
        config = self.load_config()
        
        summary = {
            'framework': config.get('framework', {}),
            'api_keys_configured': len(config.get('api_keys', {})),
            'rate_limits_configured': len(config.get('rate_limits', {})),
            'opsec_rules_configured': len(config.get('opsec_rules', {})),
            'output_formats': {
                'google_sheets': config.get('google_sheets', {}).get('enabled', False),
                'jsonl': config.get('jsonl', {}).get('enabled', True),
                'sqlite': config.get('sqlite', {}).get('enabled', True)
            }
        }
        
        return summary
