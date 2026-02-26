from typing import Optional, List, Dict, Any, Union
from pydantic import BaseModel, HttpUrl, Field, validator

class ScanConfig(BaseModel):
    """Configuration model for CompleteSecurityScanner initialized with strict validation."""
    
    timeout: int = Field(default=30, ge=1, le=300, description="Request timeout in seconds")
    max_workers: int = Field(default=3, ge=1, le=50, description="Max concurrent scanning workers")
    verify_ssl: bool = Field(default=True, description="Verify SSL certificates during scanning")
    oob_enabled: bool = Field(default=False, description="Enable Out-Of-Band (Interact.sh) detection")
    stealth: bool = Field(default=False, description="Enable stealth mode and anti-WAF detection behaviors")
    
    # Specific stealth configurations
    rate_limit: Optional[int] = Field(default=None, description="Requests per minute rate limit")
    delay: float = Field(default=0.5, ge=0.0, description="Delay between requests in seconds")
    
    @validator('timeout')
    def validate_timeout(cls, v):
        if not (1 <= v <= 300):
            raise ValueError("Timeout must be between 1 and 300 seconds")
        return v
        
    @validator('max_workers')
    def validate_workers(cls, v):
        if not (1 <= v <= 50):
            raise ValueError("Max workers must be between 1 and 50")
        return v
        
    @validator('delay')
    def validate_delay(cls, v, values):
        if values.get('stealth') and v < 1.0:
            return 1.0  # Force at least 1s delay in stealth mode
        return v
