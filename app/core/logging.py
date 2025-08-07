"""
Logging configuration for Ultimate Planner
Provides structured logging with security event support
"""

import logging
import sys
from typing import Optional


class SecurityLogger:
    """Enhanced logger for security events"""
    
    def __init__(self, name: str):
        self.logger = logging.getLogger(name)
        self._setup_logger()
    
    def _setup_logger(self):
        """Setup logger with appropriate handlers and formatters"""
        if not self.logger.handlers:
            handler = logging.StreamHandler(sys.stdout)
            
            # Use JSON format for structured logging
            formatter = logging.Formatter(
                '{"timestamp": "%(asctime)s", "level": "%(levelname)s", '
                '"module": "%(name)s", "message": "%(message)s"}'
            )
            handler.setFormatter(formatter)
            
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def info(self, message: str, extra: Optional[dict] = None):
        """Log info message"""
        self.logger.info(message, extra=extra or {})
    
    def warning(self, message: str, extra: Optional[dict] = None):
        """Log warning message"""
        self.logger.warning(message, extra=extra or {})
    
    def error(self, message: str, extra: Optional[dict] = None):
        """Log error message"""
        self.logger.error(message, extra=extra or {})
    
    def critical(self, message: str, extra: Optional[dict] = None):
        """Log critical message"""
        self.logger.critical(message, extra=extra or {})
    
    def debug(self, message: str, extra: Optional[dict] = None):
        """Log debug message"""
        self.logger.debug(message, extra=extra or {})


def get_logger(name: str) -> SecurityLogger:
    """Get logger instance for the specified module"""
    return SecurityLogger(name)