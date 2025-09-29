"""
Adaptive Rate Limiter
Implements intelligent rate limiting with jitter and backoff strategies.
"""

import asyncio
import logging
import random
import time
from typing import Dict, Any, Optional
from datetime import datetime, timedelta


class AdaptiveRateLimiter:
    """Adaptive rate limiter with intelligent backoff and jitter."""

    def __init__(self, base_rate: float = 1.0, max_rate: float = 10.0):
        """Initialize the rate limiter."""
        self.base_rate = base_rate
        self.max_rate = max_rate
        self.current_rate = base_rate
        self.logger = logging.getLogger(__name__)
        
        # Rate limiting state
        self.last_request_time = 0
        self.request_count = 0
        self.window_start = time.time()
        self.window_requests = 0
        self.window_duration = 60  # 1 minute windows
        
        # Backoff state
        self.consecutive_failures = 0
        self.backoff_until = 0
        self.max_backoff = 300  # 5 minutes max backoff
        
        # Jitter configuration
        self.jitter_factor = 0.1  # 10% jitter
        
        # Rate limiting configuration
        self.rate_limits = {
            'default': 1.0,
            'whois': 0.5,
            'dns': 2.0,
            'http': 5.0,
            'api': 1.0
        }

    async def acquire(self, request_type: str = 'default') -> None:
        """Acquire permission to make a request."""
        # Check if we're in backoff
        if time.time() < self.backoff_until:
            wait_time = self.backoff_until - time.time()
            self.logger.debug(f"Rate limiter in backoff, waiting {wait_time:.2f} seconds")
            await asyncio.sleep(wait_time)
        
        # Get rate limit for request type
        rate_limit = self.rate_limits.get(request_type, self.rate_limit)
        
        # Calculate wait time
        wait_time = self._calculate_wait_time(rate_limit)
        
        if wait_time > 0:
            self.logger.debug(f"Rate limiting: waiting {wait_time:.2f} seconds")
            await asyncio.sleep(wait_time)
        
        # Update state
        self._update_state()

    def _calculate_wait_time(self, rate_limit: float) -> float:
        """Calculate how long to wait before next request."""
        current_time = time.time()
        
        # Reset window if needed
        if current_time - self.window_start >= self.window_duration:
            self.window_start = current_time
            self.window_requests = 0
        
        # Calculate time since last request
        time_since_last = current_time - self.last_request_time
        
        # Calculate minimum interval between requests
        min_interval = 1.0 / rate_limit
        
        # Add jitter
        jitter = random.uniform(0, min_interval * self.jitter_factor)
        wait_time = max(0, min_interval - time_since_last + jitter)
        
        return wait_time

    def _update_state(self) -> None:
        """Update rate limiter state after a request."""
        current_time = time.time()
        self.last_request_time = current_time
        self.window_requests += 1
        self.request_count += 1

    def record_success(self) -> None:
        """Record a successful request."""
        self.consecutive_failures = 0
        self._adjust_rate_up()

    def record_failure(self, error_code: Optional[int] = None) -> None:
        """Record a failed request and adjust rate accordingly."""
        self.consecutive_failures += 1
        
        # Determine backoff strategy based on error code
        if error_code == 429:  # Too Many Requests
            self._handle_rate_limit_error()
        elif error_code and 500 <= error_code < 600:  # Server errors
            self._handle_server_error()
        else:
            self._handle_general_error()

    def _handle_rate_limit_error(self) -> None:
        """Handle rate limit errors (HTTP 429)."""
        # Exponential backoff for rate limit errors
        backoff_time = min(
            self.base_rate * (2 ** self.consecutive_failures),
            self.max_backoff
        )
        self.backoff_until = time.time() + backoff_time
        
        # Reduce rate
        self.current_rate = max(
            self.base_rate * 0.5,
            self.current_rate * 0.8
        )
        
        self.logger.warning(
            f"Rate limit hit, backing off for {backoff_time:.2f} seconds, "
            f"reducing rate to {self.current_rate:.2f} req/s"
        )

    def _handle_server_error(self) -> None:
        """Handle server errors (5xx)."""
        # Linear backoff for server errors
        backoff_time = min(
            self.consecutive_failures * 10,  # 10 seconds per failure
            self.max_backoff
        )
        self.backoff_until = time.time() + backoff_time
        
        self.logger.warning(
            f"Server error, backing off for {backoff_time:.2f} seconds"
        )

    def _handle_general_error(self) -> None:
        """Handle general errors."""
        # Slight backoff for general errors
        backoff_time = min(
            self.consecutive_failures * 2,  # 2 seconds per failure
            30  # Max 30 seconds
        )
        self.backoff_until = time.time() + backoff_time
        
        self.logger.debug(
            f"Request failed, backing off for {backoff_time:.2f} seconds"
        )

    def _adjust_rate_up(self) -> None:
        """Gradually increase rate after successful requests."""
        if self.consecutive_failures == 0:
            # Increase rate gradually
            self.current_rate = min(
                self.max_rate,
                self.current_rate * 1.1
            )

    def _adjust_rate_down(self) -> None:
        """Decrease rate after failures."""
        self.current_rate = max(
            self.base_rate * 0.5,
            self.current_rate * 0.9
        )

    @property
    def rate_limit(self) -> float:
        """Get current rate limit."""
        return self.current_rate

    def get_stats(self) -> Dict[str, Any]:
        """Get rate limiter statistics."""
        current_time = time.time()
        
        return {
            'current_rate': self.current_rate,
            'base_rate': self.base_rate,
            'max_rate': self.max_rate,
            'request_count': self.request_count,
            'consecutive_failures': self.consecutive_failures,
            'backoff_until': self.backoff_until,
            'is_in_backoff': current_time < self.backoff_until,
            'window_requests': self.window_requests,
            'window_duration': self.window_duration,
            'time_since_last_request': current_time - self.last_request_time
        }

    def reset(self) -> None:
        """Reset rate limiter state."""
        self.current_rate = self.base_rate
        self.consecutive_failures = 0
        self.backoff_until = 0
        self.request_count = 0
        self.window_start = time.time()
        self.window_requests = 0
        self.last_request_time = 0

    def set_rate_limit(self, request_type: str, rate: float) -> None:
        """Set rate limit for a specific request type."""
        self.rate_limits[request_type] = rate
        self.logger.info(f"Set rate limit for {request_type} to {rate} req/s")

    def get_rate_limit(self, request_type: str) -> float:
        """Get rate limit for a specific request type."""
        return self.rate_limits.get(request_type, self.base_rate)
