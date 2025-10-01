"""
Secure Credential Manager
Manages API keys and credentials with encryption and secure storage.
"""

import json
import logging
import os
import secrets
from pathlib import Path
from typing import Dict, Any, Optional
import base64

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    Fernet = None
    hashes = None
    PBKDF2HMAC = None


class SecureCredentialManager:
    """Manages API keys and credentials with encryption."""

    def __init__(self, config: Dict[str, Any]):
        """Initialize the credential manager."""
        self.config = config
        self.logger = logging.getLogger(__name__)
        self.credentials_file = Path(config.get('credentials_file', 'credentials.json'))
        self.encryption_key_file = Path(config.get('encryption_key_file', '.encryption_key'))
        self.fernet = None
        
        # Initialize encryption
        self._initialize_encryption()

    def _initialize_encryption(self) -> None:
        """Initialize encryption for credential storage."""
        if not CRYPTO_AVAILABLE:
            self.logger.warning("Cryptography not available, storing credentials in plain text")
            return
        
        try:
            # Load or create encryption key
            encryption_key = self._get_or_create_encryption_key()
            self.fernet = Fernet(encryption_key)
        except Exception as e:
            self.logger.error(f"Failed to initialize encryption: {e}")
            self.fernet = None

    def _get_or_create_encryption_key(self) -> bytes:
        """Get or create encryption key."""
        if self.encryption_key_file.exists():
            with open(self.encryption_key_file, 'rb') as f:
                return f.read()
        else:
            # Create new encryption key
            key = Fernet.generate_key()
            with open(self.encryption_key_file, 'wb') as f:
                f.write(key)
            # Set restrictive permissions
            os.chmod(self.encryption_key_file, 0o600)
            return key

    def store_api_key(self, service: str, api_key: str) -> bool:
        """Store an API key securely."""
        try:
            credentials = self._load_credentials()
            credentials[service] = api_key
            
            if self.fernet:
                # Encrypt the credentials
                credentials_json = json.dumps(credentials).encode()
                encrypted_data = self.fernet.encrypt(credentials_json)
                with open(self.credentials_file, 'wb') as f:
                    f.write(encrypted_data)
            else:
                # Store in plain text (fallback)
                with open(self.credentials_file, 'w') as f:
                    json.dump(credentials, f, indent=2)
            
            # Set restrictive permissions
            os.chmod(self.credentials_file, 0o600)
            
            self.logger.info(f"Stored API key for {service}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to store API key for {service}: {e}")
            return False

    def get_api_key(self, service: str) -> Optional[str]:
        """Get an API key for a service."""
        try:
            credentials = self._load_credentials()
            return credentials.get(service)
        except Exception as e:
            self.logger.error(f"Failed to get API key for {service}: {e}")
            return None

    def remove_api_key(self, service: str) -> bool:
        """Remove an API key for a service."""
        try:
            credentials = self._load_credentials()
            if service in credentials:
                del credentials[service]
                
                if self.fernet:
                    # Encrypt the credentials
                    credentials_json = json.dumps(credentials).encode()
                    encrypted_data = self.fernet.encrypt(credentials_json)
                    with open(self.credentials_file, 'wb') as f:
                        f.write(encrypted_data)
                else:
                    # Store in plain text (fallback)
                    with open(self.credentials_file, 'w') as f:
                        json.dump(credentials, f, indent=2)
                
                self.logger.info(f"Removed API key for {service}")
                return True
            else:
                self.logger.warning(f"No API key found for {service}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to remove API key for {service}: {e}")
            return False

    def list_services(self) -> list:
        """List all services with stored credentials."""
        try:
            credentials = self._load_credentials()
            return list(credentials.keys())
        except Exception as e:
            self.logger.error(f"Failed to list services: {e}")
            return []

    def _load_credentials(self) -> Dict[str, str]:
        """Load credentials from file."""
        if not self.credentials_file.exists():
            return {}
        
        try:
            if self.fernet:
                # Decrypt the credentials
                with open(self.credentials_file, 'rb') as f:
                    encrypted_data = f.read()
                decrypted_data = self.fernet.decrypt(encrypted_data)
                return json.loads(decrypted_data.decode())
            else:
                # Load plain text (fallback)
                with open(self.credentials_file, 'r') as f:
                    return json.load(f)
        except Exception as e:
            self.logger.error(f"Failed to load credentials: {e}")
            return {}

    def generate_secure_password(self, length: int = 32) -> str:
        """Generate a secure password."""
        return secrets.token_urlsafe(length)

    def generate_api_key(self, length: int = 32) -> str:
        """Generate a secure API key."""
        return secrets.token_hex(length)

    def validate_api_key_format(self, service: str, api_key: str) -> bool:
        """Validate API key format for a service."""
        # Basic validation rules for common services
        validation_rules = {
            'shodan': lambda key: len(key) >= 32 and key.isalnum(),
            'virustotal': lambda key: len(key) >= 64 and key.isalnum(),
            'hibp': lambda key: len(key) >= 40 and key.isalnum(),
            'github': lambda key: key.startswith('ghp_') and len(key) >= 40,
            'securitytrails': lambda key: len(key) >= 32 and key.isalnum(),
            'censys': lambda key: len(key) >= 40 and ':' in key
        }
        
        validator = validation_rules.get(service.lower())
        if validator:
            return validator(api_key)
        
        # Default validation
        return len(api_key) >= 8

    def get_credential_status(self) -> Dict[str, Any]:
        """Get status of all credentials."""
        try:
            credentials = self._load_credentials()
            status = {
                'total_services': len(credentials),
                'services': {},
                'encryption_enabled': self.fernet is not None,
                'credentials_file': str(self.credentials_file),
                'encryption_key_file': str(self.encryption_key_file)
            }
            
            for service, api_key in credentials.items():
                status['services'][service] = {
                    'has_key': bool(api_key),
                    'key_length': len(api_key) if api_key else 0,
                    'is_valid_format': self.validate_api_key_format(service, api_key) if api_key else False
                }
            
            return status
            
        except Exception as e:
            self.logger.error(f"Failed to get credential status: {e}")
            return {'error': str(e)}

    def export_credentials(self, output_file: str, include_keys: bool = False) -> bool:
        """Export credentials to a file (for backup purposes)."""
        try:
            credentials = self._load_credentials()
            
            export_data = {
                'export_timestamp': str(datetime.now()),
                'services': {}
            }
            
            for service, api_key in credentials.items():
                export_data['services'][service] = {
                    'has_key': bool(api_key),
                    'key_length': len(api_key) if api_key else 0
                }
                
                if include_keys and api_key:
                    export_data['services'][service]['api_key'] = api_key
            
            with open(output_file, 'w') as f:
                json.dump(export_data, f, indent=2)
            
            self.logger.info(f"Exported credentials to {output_file}")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to export credentials: {e}")
            return False

    def import_credentials(self, import_file: str) -> bool:
        """Import credentials from a file."""
        try:
            with open(import_file, 'r') as f:
                import_data = json.load(f)
            
            if 'services' not in import_data:
                self.logger.error("Invalid import file format")
                return False
            
            imported_count = 0
            for service, data in import_data['services'].items():
                if 'api_key' in data and data['api_key']:
                    if self.store_api_key(service, data['api_key']):
                        imported_count += 1
            
            self.logger.info(f"Imported {imported_count} credentials")
            return True
            
        except Exception as e:
            self.logger.error(f"Failed to import credentials: {e}")
            return False

    def cleanup_old_credentials(self, max_age_days: int = 90) -> int:
        """Clean up old or unused credentials."""
        # This is a placeholder for future implementation
        # In a real implementation, you might track credential usage
        # and remove unused ones
        self.logger.info("Credential cleanup not implemented yet")
        return 0

    def rotate_credentials(self, service: str) -> Optional[str]:
        """Rotate credentials for a service (generate new key)."""
        try:
            # Generate new API key
            new_key = self.generate_api_key()
            
            # Store new key
            if self.store_api_key(service, new_key):
                self.logger.info(f"Rotated credentials for {service}")
                return new_key
            else:
                self.logger.error(f"Failed to rotate credentials for {service}")
                return None
                
        except Exception as e:
            self.logger.error(f"Error rotating credentials for {service}: {e}")
            return None
