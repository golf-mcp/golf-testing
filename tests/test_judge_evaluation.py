"""Tests for judge evaluation consistency between parallel/sequential"""
import asyncio
import pytest
from unittest.mock import Mock, AsyncMock, MagicMock, patch
from src.test_mcp.cli.test_execution import (
    should_enable_judge_evaluation,
    evaluate_results_with_judge,
    count_successful_tests,
)


def test_judge_enablement_rules():
    """Test judge enablement follows correct rules"""
    # Conversational: always judge
    assert should_enable_judge_evaluation("conversational", 1) == True
    assert should_enable_judge_evaluation("conversational", 5) == True

    # Security: never judge
    assert should_enable_judge_evaluation("security", 1) == False
    assert should_enable_judge_evaluation("security", 5) == False

    # Compliance: never judge
    assert should_enable_judge_evaluation("compliance", 1) == False
    assert should_enable_judge_evaluation("compliance", 5) == False


def test_count_successful_with_judge():
    """Test success counting uses judge when enabled"""
    results = [
        {"test_id": "test1", "success": False, "evaluation": {"success": True}},
        {"test_id": "test2", "success": False, "evaluation": {"success": False}},
        {"test_id": "test3", "success": True, "evaluation": {"success": True}},
    ]

    # For conversational (judge enabled), should use evaluation.success
    count = count_successful_tests(results, "conversational", 1)
    assert count == 2  # test1 and test3 have evaluation.success == True

    # For security (judge disabled), should use success field
    count = count_successful_tests(results, "security", 1)
    assert count == 1  # Only test3 has success == True


def test_count_successful_without_judge():
    """Test success counting uses execution success when judge disabled"""
    results = [
        {"test_id": "test1", "success": True},
        {"test_id": "test2", "success": False},
        {"test_id": "test3", "success": True},
    ]

    # For security (judge disabled), should use success field
    count = count_successful_tests(results, "security", 1)
    assert count == 2


@pytest.mark.asyncio
async def test_evaluate_results_skips_when_disabled():
    """Test evaluate_results_with_judge skips for security/compliance"""
    results = [
        {"test_id": "test1", "status": "completed", "result_obj": Mock()}
    ]
    mock_console = Mock()

    # Should skip for security
    await evaluate_results_with_judge(
        results=results,
        suite_type="security",
        parallelism=5,
        console=mock_console,
        verbose=False
    )

    # No evaluation should be added
    assert "evaluation" not in results[0]


@pytest.mark.asyncio
async def test_evaluate_results_runs_for_conversational():
    """Test evaluate_results_with_judge runs for conversational"""
    # Mock conversation result
    mock_conversation_result = Mock()
    mock_conversation_result.model_dump = Mock(return_value={
        "overall_score": 8.0,
        "criteria_scores": {},
        "reasoning": "Test passed",
        "success": True
    })

    results = [
        {
            "test_id": "test1",
            "status": "completed",
            "result_obj": mock_conversation_result
        }
    ]
    mock_console = Mock()
    mock_console.print = Mock()

    # Mock the ConversationJudge
    with patch("src.test_mcp.cli.test_execution.ConversationJudge") as MockJudge:
        mock_judge = Mock()
        mock_eval_result = Mock()
        mock_eval_result.success = True
        mock_eval_result.model_dump = Mock(return_value={
            "overall_score": 8.0,
            "criteria_scores": {},
            "reasoning": "Test passed",
            "success": True
        })
        # Mock the async batch method which is now called
        mock_judge.evaluate_conversations_batch_async = AsyncMock(return_value=[mock_eval_result])
        MockJudge.return_value = mock_judge

        # Should run for conversational
        await evaluate_results_with_judge(
            results=results,
            suite_type="conversational",
            parallelism=1,
            console=mock_console,
            verbose=False
        )

        # Evaluation should be added
        assert "evaluation" in results[0]
        assert results[0]["evaluation"]["success"] == True


@pytest.mark.asyncio
async def test_evaluate_results_handles_both_formats():
    """Test evaluate_results_with_judge handles parallel and sequential formats"""
    # Parallel format (result_obj)
    parallel_result = {
        "test_id": "test1",
        "status": "completed",
        "result_obj": Mock()
    }

    # Sequential format (details.conversation_result)
    sequential_result = {
        "test_id": "test2",
        "status": "completed",
        "details": {
            "conversation_result": Mock()
        }
    }

    results = [parallel_result, sequential_result]
    mock_console = Mock()
    mock_console.print = Mock()

    with patch("src.test_mcp.cli.test_execution.ConversationJudge") as MockJudge:
        mock_judge = Mock()
        mock_eval_result = Mock()
        mock_eval_result.success = True
        mock_eval_result.model_dump = Mock(return_value={
            "overall_score": 8.0,
            "criteria_scores": {},
            "reasoning": "Test passed",
            "success": True
        })
        # Mock the async batch method which is now called
        mock_judge.evaluate_conversations_batch_async = AsyncMock(return_value=[mock_eval_result, mock_eval_result])
        MockJudge.return_value = mock_judge

        await evaluate_results_with_judge(
            results=results,
            suite_type="conversational",
            parallelism=1,
            console=mock_console,
            verbose=False
        )

        # Both should have evaluations
        assert "evaluation" in results[0]
        assert "evaluation" in results[1]


@pytest.mark.asyncio
async def test_evaluate_results_handles_judge_failure():
    """Test evaluate_results_with_judge handles judge failures gracefully"""
    mock_conversation_result = Mock()

    results = [
        {
            "test_id": "test1",
            "status": "completed",
            "result_obj": mock_conversation_result
        }
    ]
    mock_console = Mock()
    mock_console.print = Mock()

    with patch("src.test_mcp.cli.test_execution.ConversationJudge") as MockJudge:
        mock_judge = Mock()
        # Make judge raise exception
        mock_judge.evaluate_conversations_batch_async = AsyncMock(side_effect=Exception("Judge failed"))
        MockJudge.return_value = mock_judge

        await evaluate_results_with_judge(
            results=results,
            suite_type="conversational",
            parallelism=1,
            console=mock_console,
            verbose=False
        )

        # When batch evaluation fails, no evaluations are added (whole batch fails)
        # This is expected behavior - the function catches the exception and prints a warning
        # but doesn't add evaluations to results
        assert "evaluation" not in results[0]
