import time
import functools
import logging
from typing import Callable, Optional

logger = logging.getLogger(__name__)

class RateLimiter:
    """Rate limiter to control the frequency of network requests."""
    
    def __init__(self, requests_per_minute: Optional[int] = None, delay_seconds: float = 0.0):
        self.min_interval = 0.0
        
        if requests_per_minute and requests_per_minute > 0:
            self.min_interval = 60.0 / requests_per_minute
        elif delay_seconds > 0:
            self.min_interval = delay_seconds
            
        self.last_request_time = 0.0
        
    def wait(self):
        """Wait if necessary to respect the configured rate limit."""
        if self.min_interval <= 0:
            return
            
        elapsed = time.time() - self.last_request_time
        if elapsed < self.min_interval:
            sleep_time = self.min_interval - elapsed
            logger.debug(f"RateLimiter: Sleeping for {sleep_time:.2f}s to respect limit")
            time.sleep(sleep_time)
            
        self.last_request_time = time.time()

def rate_limited(requests_per_minute: Optional[int] = None, delay_seconds: float = 0.0):
    """
    Decorator for rate-limited functions.
    
    Can be configured via arguments or by accessing self.config.rate_limit
    and self.config.delay on the bound instance (e.g., CompleteSecurityScanner).
    """
    def decorator(func: Callable):
        # We need to map instances to their limiters if the decorator
        # parameters are dynamic based on the instance.
        _limiters = {}
        
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            # args[0] is typically 'self' in a method
            if args and hasattr(args[0], 'config'):
                instance = args[0]
                instance_id = id(instance)
                
                if instance_id not in _limiters:
                    # Dynamically pull from instance config
                    rpm = getattr(instance.config, 'rate_limit', requests_per_minute)
                    delay = getattr(instance.config, 'delay', delay_seconds)
                    _limiters[instance_id] = RateLimiter(requests_per_minute=rpm, delay_seconds=delay)
                
                limiter = _limiters[instance_id]
            else:
                # Static fallback for non-method usage
                limiter = RateLimiter(requests_per_minute=requests_per_minute, delay_seconds=delay_seconds)
                
            limiter.wait()
            return func(*args, **kwargs)
        return wrapper
    return decorator
