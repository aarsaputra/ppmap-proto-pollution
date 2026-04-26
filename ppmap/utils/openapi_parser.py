"""
OpenAPI / Swagger v2|v3 Parser Utility
=======================================
Automatically maps API endpoints and parameter schemas from an OpenAPI spec
file (JSON or YAML) into PPMAP scan targets.

Usage (CLI):
    python ppmap.py --scan --openapi openapi.json https://api.target.com

Usage (Python):
    from ppmap.utils.openapi_parser import OpenAPIParser
    parser = OpenAPIParser("openapi.yaml")
    endpoints = parser.get_scan_targets(base_url="https://api.target.com")
"""

import json
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin

logger = logging.getLogger(__name__)


class OpenAPIParser:
    """
    Parses an OpenAPI 2.x (Swagger) or 3.x spec and extracts
    scan targets (URL + parameter names) for PPMAP.
    """

    def __init__(self, spec_path: str):
        self.spec_path = Path(spec_path)
        self.spec: Dict[str, Any] = {}
        self._load()

    def _load(self):
        """Load and parse the spec file (JSON or YAML)."""
        content = self.spec_path.read_text(encoding="utf-8")
        if self.spec_path.suffix in (".yaml", ".yml"):
            try:
                import yaml
                self.spec = yaml.safe_load(content)
            except ImportError:
                raise RuntimeError(
                    "PyYAML is required for YAML OpenAPI specs: pip install pyyaml"
                )
        else:
            self.spec = json.loads(content)
        logger.info(f"[OpenAPI] Loaded spec: {self.spec_path.name}")

    @property
    def version(self) -> str:
        """Detect spec version: 'v2' or 'v3'."""
        if "swagger" in self.spec:
            return "v2"
        if "openapi" in self.spec:
            return "v3"
        return "unknown"

    def _get_base_url(self, override_base: Optional[str] = None) -> str:
        if override_base:
            return override_base.rstrip("/")

        if self.version == "v2":
            host = self.spec.get("host", "localhost")
            schemes = self.spec.get("schemes", ["https"])
            base_path = self.spec.get("basePath", "/")
            return f"{schemes[0]}://{host}{base_path}".rstrip("/")

        # v3: pick first server
        servers = self.spec.get("servers", [{"url": "http://localhost"}])
        return servers[0]["url"].rstrip("/")

    def get_scan_targets(self, base_url: Optional[str] = None) -> List[Dict[str, Any]]:
        """
        Return a list of dicts with:
            - url: full endpoint URL
            - method: HTTP method (GET, POST, etc.)
            - query_params: list of query param names to fuzz
            - body_params: list of body field names to fuzz
        """
        resolved_base = self._get_base_url(base_url)
        paths = self.spec.get("paths", {})
        targets = []

        for path, methods in paths.items():
            full_url = f"{resolved_base}{path}"
            for method, operation in methods.items():
                if method.lower() not in ("get", "post", "put", "patch", "delete"):
                    continue
                if not isinstance(operation, dict):
                    continue

                query_params = []
                body_params = []

                # OpenAPI v2 / v3 parameter extraction
                for param in operation.get("parameters", []):
                    loc = param.get("in", "")
                    name = param.get("name", "")
                    if loc == "query":
                        query_params.append(name)
                    elif loc in ("body", "formData"):
                        body_params.append(name)

                # OpenAPI v3 requestBody schema extraction
                req_body = operation.get("requestBody", {})
                if req_body:
                    content = req_body.get("content", {})
                    for media_type, media_info in content.items():
                        schema = media_info.get("schema", {})
                        props = schema.get("properties", {})
                        body_params.extend(props.keys())

                targets.append(
                    {
                        "url": full_url,
                        "method": method.upper(),
                        "query_params": list(set(query_params)),
                        "body_params": list(set(body_params)),
                    }
                )
                logger.debug(f"[OpenAPI] {method.upper()} {full_url} | Q:{query_params} B:{body_params}")

        logger.info(f"[OpenAPI] Extracted {len(targets)} endpoint targets from spec.")
        return targets

    def get_urls_only(self, base_url: Optional[str] = None) -> List[str]:
        """Return just the endpoint URLs (no parameter detail)."""
        return [t["url"] for t in self.get_scan_targets(base_url)]
