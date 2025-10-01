"""
Logging Configuration
Configures structured logging for the reconnaissance framework.
"""

import logging
import logging.handlers
import sys
from pathlib import Path
from typing import Optional
import json
from datetime import datetime


class StructuredFormatter(logging.Formatter):
    """Custom formatter for structured logging."""

    def format(self, record):
        """Format log record as structured JSON."""
        log_entry = {
            'timestamp': datetime.utcnow().isoformat(),
            'level': record.levelname,
            'logger': record.name,
            'message': record.getMessage(),
            'module': record.module,
            'function': record.funcName,
            'line': record.lineno
        }
        
        # Add exception info if present
        if record.exc_info:
            log_entry['exception'] = self.formatException(record.exc_info)
        
        # Add extra fields
        for key, value in record.__dict__.items():
            if key not in ['name', 'msg', 'args', 'levelname', 'levelno', 'pathname',
                          'filename', 'module', 'lineno', 'funcName', 'created',
                          'msecs', 'relativeCreated', 'thread', 'threadName',
                          'processName', 'process', 'getMessage', 'exc_info',
                          'exc_text', 'stack_info']:
                log_entry[key] = value
        
        return json.dumps(log_entry, default=str)


def setup_logging(log_level: int = logging.INFO, log_file: Optional[str] = None) -> None:
    """Setup structured logging for the reconnaissance framework."""
    
    # Create logger
    logger = logging.getLogger()
    logger.setLevel(log_level)
    
    # Clear existing handlers
    logger.handlers.clear()
    
    # Create formatters
    console_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    structured_formatter = StructuredFormatter()
    
    # Console handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(log_level)
    console_handler.setFormatter(console_formatter)
    logger.addHandler(console_handler)
    
    # File handler (if specified)
    if log_file:
        log_path = Path(log_file)
        log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Rotating file handler
        file_handler = logging.handlers.RotatingFileHandler(
            log_file,
            maxBytes=10*1024*1024,  # 10MB
            backupCount=5
        )
        file_handler.setLevel(log_level)
        file_handler.setFormatter(structured_formatter)
        logger.addHandler(file_handler)
    
    # Security handler (for sensitive operations)
    security_handler = SecurityLogHandler()
    security_handler.setLevel(logging.WARNING)
    security_handler.setFormatter(structured_formatter)
    logger.addHandler(security_handler)
    
    # Suppress noisy third-party loggers
    logging.getLogger('urllib3').setLevel(logging.WARNING)
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('selenium').setLevel(logging.WARNING)


class SecurityLogHandler(logging.Handler):
    """Custom handler for security-sensitive log entries."""
    
    def __init__(self):
        super().__init__()
        self.security_log_file = Path('logs/security.log')
        self.security_log_file.parent.mkdir(parents=True, exist_ok=True)
    
    def emit(self, record):
        """Emit security log entry."""
        try:
            # Only log security-related messages
            if not self._is_security_related(record):
                return
            
            # Mask sensitive information
            masked_record = self._mask_sensitive_data(record)
            
            # Write to security log
            with open(self.security_log_file, 'a') as f:
                f.write(f"{datetime.utcnow().isoformat()} - {masked_record.getMessage()}\n")
                
        except Exception:
            # Avoid infinite recursion
            pass
    
    def _is_security_related(self, record) -> bool:
        """Check if log record is security-related."""
        security_keywords = [
            'security', 'vulnerability', 'breach', 'attack', 'threat',
            'credential', 'password', 'api_key', 'token', 'secret',
            'opsec', 'validation', 'unauthorized', 'forbidden'
        ]
        
        message = record.getMessage().lower()
        return any(keyword in message for keyword in security_keywords)
    
    def _mask_sensitive_data(self, record) -> logging.LogRecord:
        """Mask sensitive data in log record."""
        # Create a copy of the record
        masked_record = logging.LogRecord(
            record.name, record.levelno, record.pathname,
            record.lineno, record.msg, record.args, record.exc_info
        )
        
        # Mask common sensitive patterns
        message = record.getMessage()
        masked_message = self._mask_string(message)
        masked_record.msg = masked_message
        
        return masked_record
    
    def _mask_string(self, text: str) -> str:
        """Mask sensitive patterns in text."""
        import re
        
        # Mask API keys
        text = re.sub(r'api[_-]?key["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?', 
                     'api_key=***MASKED***', text, flags=re.IGNORECASE)
        
        # Mask passwords
        text = re.sub(r'password["\']?\s*[:=]\s*["\']?[^"\'\s]+["\']?', 
                     'password=***MASKED***', text, flags=re.IGNORECASE)
        
        # Mask tokens
        text = re.sub(r'token["\']?\s*[:=]\s*["\']?[a-zA-Z0-9]{20,}["\']?', 
                     'token=***MASKED***', text, flags=re.IGNORECASE)
        
        # Mask email addresses
        text = re.sub(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b', 
                     '***@***.***', text)
        
        # Mask IP addresses
        text = re.sub(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b', 
                     '***.***.***.***', text)
        
        return text


class ReconLogger:
    """Custom logger for reconnaissance operations."""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
    
    def log_scan_start(self, target: str, scan_type: str) -> None:
        """Log scan start."""
        self.logger.info(f"Starting {scan_type} scan for {target}", 
                        extra={'scan_type': scan_type, 'target': target, 'event': 'scan_start'})
    
    def log_scan_complete(self, target: str, scan_type: str, duration: float) -> None:
        """Log scan completion."""
        self.logger.info(f"Completed {scan_type} scan for {target} in {duration:.2f}s", 
                        extra={'scan_type': scan_type, 'target': target, 'duration': duration, 'event': 'scan_complete'})
    
    def log_scan_error(self, target: str, scan_type: str, error: str) -> None:
        """Log scan error."""
        self.logger.error(f"Error in {scan_type} scan for {target}: {error}", 
                         extra={'scan_type': scan_type, 'target': target, 'error': error, 'event': 'scan_error'})
    
    def log_finding(self, target: str, finding_type: str, severity: str, description: str) -> None:
        """Log security finding."""
        self.logger.warning(f"Security finding for {target}: {description}", 
                           extra={'target': target, 'finding_type': finding_type, 'severity': severity, 'event': 'finding'})
    
    def log_rate_limit(self, service: str, wait_time: float) -> None:
        """Log rate limiting."""
        self.logger.info(f"Rate limited for {service}, waiting {wait_time:.2f}s", 
                        extra={'service': service, 'wait_time': wait_time, 'event': 'rate_limit'})
    
    def log_opsec_violation(self, target: str, violation: str) -> None:
        """Log OPSEC violation."""
        self.logger.warning(f"OPSEC violation for {target}: {violation}", 
                           extra={'target': target, 'violation': violation, 'event': 'opsec_violation'})
    
    def log_data_collection(self, source: str, data_type: str, count: int) -> None:
        """Log data collection."""
        self.logger.info(f"Collected {count} {data_type} records from {source}", 
                        extra={'source': source, 'data_type': data_type, 'count': count, 'event': 'data_collection'})
    
    def log_api_usage(self, service: str, endpoint: str, status_code: int) -> None:
        """Log API usage."""
        level = logging.INFO if 200 <= status_code < 300 else logging.WARNING
        self.logger.log(level, f"API call to {service}: {endpoint} -> {status_code}", 
                       extra={'service': service, 'endpoint': endpoint, 'status_code': status_code, 'event': 'api_call'})


def get_logger(name: str) -> ReconLogger:
    """Get a reconnaissance logger instance."""
    return ReconLogger(name)
