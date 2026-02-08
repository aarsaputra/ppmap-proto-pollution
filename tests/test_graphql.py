"""
Unit tests for GraphQL Scanner
"""
import pytest
from unittest.mock import MagicMock, patch
import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from ppmap.graphql import (
    GraphQLScanner,
    GraphQLFinding,
    GRAPHQL_PP_PAYLOADS,
    scan_graphql
)


class TestGraphQLScanner:
    """Tests for GraphQLScanner class."""
    
    @pytest.fixture
    def scanner(self):
        """Create scanner instance."""
        return GraphQLScanner(timeout=5)
    
    def test_init(self, scanner):
        """Should initialize with default settings."""
        assert scanner.timeout == 5
        assert 'Content-Type' in scanner.headers
    
    @patch('ppmap.graphql.requests.Session')
    def test_detect_graphql_endpoint_found(self, mock_session, scanner):
        """Should detect GraphQL endpoint."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'data': {'__typename': 'Query'}}
        
        scanner.session.post = MagicMock(return_value=mock_resp)
        
        endpoint = scanner.detect_graphql_endpoint('http://example.com')
        
        assert endpoint is not None
    
    @patch('ppmap.graphql.requests.Session')
    def test_detect_graphql_endpoint_not_found(self, mock_session, scanner):
        """Should return None when no endpoint found."""
        mock_resp = MagicMock()
        mock_resp.status_code = 404
        
        scanner.session.post = MagicMock(return_value=mock_resp)
        
        endpoint = scanner.detect_graphql_endpoint('http://example.com')
        
        assert endpoint is None
    
    @patch('ppmap.graphql.requests.Session')
    def test_introspect_schema(self, mock_session, scanner):
        """Should perform schema introspection."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            'data': {
                '__schema': {
                    'types': [{'name': 'Query'}],
                    'queryType': {'name': 'Query'}
                }
            }
        }
        
        scanner.session.post = MagicMock(return_value=mock_resp)
        
        schema = scanner.introspect_schema('http://example.com/graphql')
        
        assert schema is not None
        assert 'types' in schema
    
    @patch('ppmap.graphql.requests.Session')
    def test_test_mutation_pp(self, mock_session, scanner):
        """Should test mutations for PP."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'data': {'updateSettings': {'success': True, 'isAdmin': True}}}
        
        scanner.session.post = MagicMock(return_value=mock_resp)
        
        findings = scanner.test_mutation_pp('http://example.com/graphql')
        
        # Should find indicators in response
        assert isinstance(findings, list)
    
    @patch('ppmap.graphql.requests.Session')
    def test_test_query_pp(self, mock_session, scanner):
        """Should test queries for PP."""
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {'data': {'users': []}}
        
        scanner.session.post = MagicMock(return_value=mock_resp)
        
        findings = scanner.test_query_pp('http://example.com/graphql')
        
        assert isinstance(findings, list)


class TestGraphQLFinding:
    """Tests for GraphQLFinding dataclass."""
    
    def test_create_finding(self):
        """Should create finding with defaults."""
        finding = GraphQLFinding(
            endpoint='http://example.com/graphql',
            operation_type='mutation',
            operation_name='updateUser',
            payload='{"query": "mutation { updateUser }"}',
            response={'data': {}}
        )
        
        assert finding.severity == 'HIGH'
        assert finding.verified is False


class TestGraphQLPayloads:
    """Tests for payload definitions."""
    
    def test_mutation_payloads_exist(self):
        """Should have mutation payloads."""
        assert 'mutation_injection' in GRAPHQL_PP_PAYLOADS
        assert len(GRAPHQL_PP_PAYLOADS['mutation_injection']) > 0
    
    def test_query_payloads_exist(self):
        """Should have query payloads."""
        assert 'query_injection' in GRAPHQL_PP_PAYLOADS
        assert len(GRAPHQL_PP_PAYLOADS['query_injection']) > 0
    
    def test_payloads_have_proto(self):
        """Injection payloads should contain __proto__ or constructor."""
        injection_categories = ['mutation_injection', 'query_injection']
        for category in injection_categories:
            payloads = GRAPHQL_PP_PAYLOADS[category]
            for payload in payloads:
                payload_str = json.dumps(payload)
                assert '__proto__' in payload_str or 'constructor' in payload_str


class TestScanGraphQL:
    """Tests for scan_graphql convenience function."""
    
    @patch('ppmap.graphql.GraphQLScanner')
    def test_returns_list(self, mock_scanner_class):
        """Should return list of findings."""
        mock_scanner = MagicMock()
        mock_scanner.scan_endpoint.return_value = []
        mock_scanner_class.return_value = mock_scanner
        
        results = scan_graphql('http://example.com')
        
        assert isinstance(results, list)
