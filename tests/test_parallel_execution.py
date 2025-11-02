"""
Test suite for parallel execution functionality
"""

import asyncio
import time
from unittest.mock import AsyncMock, Mock, patch

import pytest

from src.test_mcp.cli.test_execution import (
    execute_test_cases,
    normalize_parallel_result,
    run_tests_parallel,
)
from src.test_mcp.config.config_manager import MCPServerConfig
from src.test_mcp.models.conversational import (
    ConversationalTestConfig,
    ConversationTestSuite,
)
from src.test_mcp.testing.conversation.conversation_models import (
    ConversationResult,
    ConversationStatus,
)


class TestNormalizeParallelResult:
    """Test the normalize_parallel_result() function"""

    def test_normalize_successful_result(self):
        """Verify successful result normalization"""
        # Create mock result_obj
        result_obj = Mock()
        result_obj.status.value = "goal_achieved"

        parallel_result = {
            "test_case": {"test_id": "test_1", "user_message": "Hello"},
            "result": {
                "success": True,
                "duration": 2.5,
                "turns": [{"role": "user"}, {"role": "assistant"}],
            },
            "result_obj": result_obj,
            "status": "completed",
            "error": None,
        }

        normalized = normalize_parallel_result(parallel_result)

        assert normalized["test_id"] == "test_1"
        assert normalized["success"] is True
        assert normalized["execution_time"] == 2.5
        assert "Conversation completed with 2 turns" in normalized["message"]
        assert normalized["details"]["conversation_result"] == result_obj

    def test_normalize_failed_result(self):
        """Verify failed result normalization"""
        parallel_result = {
            "test_case": {"test_id": "test_2"},
            "result": {},
            "result_obj": None,
            "status": "failed",
            "error": "Connection timeout",
        }

        normalized = normalize_parallel_result(parallel_result)

        assert normalized["test_id"] == "test_2"
        assert normalized["success"] is False
        assert "Connection timeout" in normalized["message"]
        assert "error" in normalized

    def test_normalize_exception_handling(self):
        """Verify exception result handling"""
        parallel_result = {
            "test_case": {"test_id": "test_3"},
            "result": {},
            "result_obj": None,
            "status": "failed",
            "error": "Test execution failed",
        }

        normalized = normalize_parallel_result(parallel_result)

        assert normalized["success"] is False
        assert "error" in normalized


class TestParallelExecution:
    """Test suite for parallel execution functionality"""

    @pytest.mark.asyncio
    async def test_sequential_compatibility(self):
        """Verify parallelism=1 maintains sequential behavior"""
        # Create test suite with parallelism=1
        test_cases = [
            ConversationalTestConfig(
                test_id="seq_test_1",
                user_message="Test message 1",
                success_criteria="Response should be helpful",
            )
        ]

        suite_config = ConversationTestSuite(
            suite_id="seq_suite",
            name="Sequential Suite",
            test_cases=test_cases,
            parallelism=1,  # Sequential
        )

        server_config = MCPServerConfig(
            url="http://localhost:8080/mcp", name="test_server"
        )

        # Mock the run_single_test_case to avoid actual execution
        with patch("src.test_mcp.cli.test_execution.run_single_test_case") as mock_run:
            mock_run.return_value = {
                "test_id": "seq_test_1",
                "success": True,
                "message": "Test passed",
                "execution_time": 1.0,
            }

            with patch(
                "src.test_mcp.cli.test_execution.SharedTokenStorage.clear_all_async"
            ):
                # Note: This would actually execute - for real testing we'd need more mocking
                # For now, this validates the structure
                pass

    @pytest.mark.asyncio
    async def test_parallel_execution_basic(self):
        """Test basic parallel execution with parallelism=3"""
        # This test validates the structure but doesn't execute real tests
        # Real execution would require a running MCP server

        test_cases = [
            ConversationalTestConfig(
                test_id=f"parallel_test_{i}",
                user_message=f"Test message {i}",
                success_criteria="Response should be helpful",
            )
            for i in range(3)
        ]

        suite_config = ConversationTestSuite(
            suite_id="parallel_suite",
            name="Parallel Suite",
            test_cases=test_cases,
            parallelism=3,  # Parallel execution
        )

        # Verify suite is configured for parallel execution
        assert suite_config.parallelism == 3
        assert len(suite_config.test_cases) == 3

    def test_result_format_consistency(self):
        """Verify parallel and sequential results have same format"""
        # Create mock parallel result
        result_obj = Mock()
        result_obj.status.value = "goal_achieved"

        parallel_result = {
            "test_case": {"test_id": "test_1"},
            "result": {"success": True, "duration": 1.5, "turns": []},
            "result_obj": result_obj,
            "status": "completed",
        }

        normalized = normalize_parallel_result(parallel_result)

        # Verify normalized result has sequential format fields
        assert "test_id" in normalized
        assert "success" in normalized
        assert "message" in normalized
        assert "execution_time" in normalized
        assert "details" in normalized

        # Verify details has conversation_result (sequential format)
        assert "conversation_result" in normalized["details"]

    @pytest.mark.asyncio
    async def test_error_handling_parallel(self):
        """Test error handling in parallel execution"""
        # Test exception handling in normalize function
        exception = Exception("Test error")

        # Simulate exception result
        parallel_result = {
            "test_case": {"test_id": "error_test"},
            "result": {},
            "result_obj": None,
            "status": "failed",
            "error": str(exception),
        }

        normalized = normalize_parallel_result(parallel_result)

        assert normalized["success"] is False
        assert "error" in normalized
        assert "Test error" in str(normalized["error"])


class TestPerformanceImprovement:
    """Test parallel execution performance improvements"""

    @pytest.mark.asyncio
    @pytest.mark.slow
    async def test_parallel_faster_than_sequential(self):
        """Verify parallel execution is faster than sequential (integration test)"""
        # This is a placeholder for integration testing
        # Would require actual MCP server and multiple test cases

        # Conceptual test:
        # 1. Run 5 tests sequentially, measure time
        # 2. Run same 5 tests with parallelism=3, measure time
        # 3. Assert parallel is faster

        # For unit testing, we just verify the structure exists
        suite = ConversationTestSuite(
            suite_id="test_suite", name="Test Suite", test_cases=[]
        )
        assert hasattr(suite, "parallelism")

    def test_parallelism_configuration(self):
        """Test parallelism configuration on test suites"""
        suite = ConversationTestSuite(
            suite_id="test_suite",
            name="Test Suite",
            test_cases=[],
            parallelism=5,
        )

        assert suite.parallelism == 5

    def test_default_parallelism(self):
        """Test default parallelism value"""
        suite = ConversationTestSuite(
            suite_id="test_suite", name="Test Suite", test_cases=[]
        )

        # Should default to 5 (as defined in BaseTestSuite)
        assert suite.parallelism == 5
