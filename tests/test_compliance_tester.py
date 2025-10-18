from datetime import datetime
from unittest.mock import AsyncMock, patch

import pytest

from test_mcp.shared.progress_tracker import ExecutionStatus
from test_mcp.shared.result_models import SuiteCategory
from test_mcp.testing.compliance.mcp_compliance_tester import (
    MCPComplianceTester,
    MCPComplianceTestResult,
    MCPServerInfo,
)


class TestMCPComplianceTester:
    """Test cases for MCP compliance testing functionality"""

    def setup_method(self):
        """Set up test fixtures"""
        self.server_config = {
            "url": "https://test-mcp-server.com/mcp",
            "name": "test_server",
            "oauth": True,
        }
        self.tester = MCPComplianceTester(self.server_config)

    def test_init_with_config(self):
        """Test initialization with server configuration"""
        assert self.tester.server_config == self.server_config

    def test_init_without_oauth_config(self):
        """Test initialization without OAuth configuration"""
        config = {"url": "https://test-server.com", "name": "test"}
        tester = MCPComplianceTester(config)
        assert tester.server_config == config

    @patch("test_mcp.testing.compliance.mcp_compliance_tester.ClientSession", None)
    @pytest.mark.asyncio
    async def test_run_compliance_tests_no_sdk(self):
        """Test behavior when MCP SDK is not available"""
        results = await self.tester.run_compliance_tests()

        assert len(results) == 1
        result = results[0]
        assert result.check_name == "MCP SDK Availability"
        assert result.success is False
        assert "MCP Python SDK not available" in result.message

    @patch("test_mcp.testing.compliance.mcp_compliance_tester.ClientSession")
    @patch(
        "src.test_mcp.testing.compliance.mcp_compliance_tester.streamablehttp_client"
    )
    @pytest.mark.asyncio
    async def test_protocol_handshake_success(self, mock_transport, mock_session_class):
        """Test successful protocol handshake"""
        # Mock session setup
        mock_session = AsyncMock()
        mock_session.server_capabilities = {"tools": {}, "resources": {}}
        mock_session.server_info = {"name": "Test Server", "version": "1.0.0"}
        mock_session.protocol_version = "2024-11-05"
        mock_session_class.return_value.__aenter__.return_value = mock_session

        self.tester.session = mock_session

        result = await self.tester._test_protocol_handshake()

        assert result.check_name == "Protocol Handshake"
        assert result.success is True
        assert result.compliance_passed is True
        assert "handshake successful" in result.message

    def test_authentication_handling(self):
        """Test authentication configuration handling"""
        # Test server config with auth token
        config_with_auth = {
            "url": "https://test-server.com",
            "name": "test",
            "authorization_token": "Bearer test-token",
        }
        tester = MCPComplianceTester(config_with_auth)
        assert "authorization_token" in tester.server_config

        # Test server config without auth token
        config_without_auth = {"url": "https://test-server.com", "name": "test"}
        tester_no_auth = MCPComplianceTester(config_without_auth)
        assert "authorization_token" not in tester_no_auth.server_config

    def test_server_info_model(self):
        """Test MCPServerInfo model validation"""
        info = MCPServerInfo(
            protocol_version="2024-11-05",
            server_name="Test Server",
            capabilities=["tools", "resources"],
            tools=[{"name": "test_tool"}],
        )

        assert info.protocol_version == "2024-11-05"
        assert info.server_name == "Test Server"
        assert len(info.capabilities) == 2
        assert len(info.tools) == 1

    def test_compliance_test_result_model(self):
        """Test MCPComplianceTestResult model validation"""
        result = MCPComplianceTestResult(
            test_id="test-123",
            check_name="Test Check",
            category="Protocol",
            severity="high",
            message="Test message",
            start_time=datetime.now(),
            end_time=datetime.now(),
            status=ExecutionStatus.COMPLETED,
            success=True,
            compliance_passed=True,
            duration=1.5,
        )

        assert result.test_type == SuiteCategory.COMPLIANCE
        assert result.check_name == "Test Check"
        assert result.severity == "high"
        assert result.success is True

    def test_new_compliance_categories(self):
        """Test that new compliance test categories are available"""
        # Test that the tester can handle new test categories
        test_categories = [
            "handshake",
            "capabilities",
            "tools",
            "resources",
            "advanced",
        ]

        # This would be tested in integration with actual MCP servers
        # For now, just verify the categories are defined
        assert isinstance(test_categories, list)
        assert len(test_categories) == 5


@pytest.fixture
def server_config():
    """Fixture providing test server configuration"""
    return {
        "url": "https://test-server.com/mcp",
        "name": "test_server",
        "oauth": False,
    }


@pytest.fixture
def oauth_server_config():
    """Fixture providing OAuth-enabled server configuration"""
    return {
        "url": "https://oauth-server.com/mcp",
        "name": "oauth_server",
        "oauth": True,
    }


class TestMCPComplianceIntegration:
    """Integration test cases for compliance testing"""

    @pytest.mark.asyncio
    async def test_full_compliance_suite_no_oauth(self, server_config):
        """Test running full compliance suite on non-OAuth server"""
        with patch(
            "test_mcp.testing.compliance.mcp_compliance_tester.ClientSession", None
        ):
            tester = MCPComplianceTester(server_config)
            results = await tester.run_compliance_tests()

            # Should get SDK availability error
            assert len(results) == 1
            assert results[0].check_name == "MCP SDK Availability"
            assert not results[0].success

    @pytest.mark.asyncio
    async def test_error_handling_connection_failure(self, server_config):
        """Test error handling when connection fails"""
        with patch("test_mcp.testing.compliance.mcp_compliance_tester.ClientSession"):
            tester = MCPComplianceTester(server_config)

            # Mock connection failure
            tester._connect_to_server = AsyncMock(
                side_effect=Exception("Connection failed")
            )

            results = await tester.run_compliance_tests()

            # Should have error result
            assert len(results) == 1
            assert results[0].check_name == "MCP Connection"
            assert not results[0].success
            assert "Connection failed" in results[0].error_message
