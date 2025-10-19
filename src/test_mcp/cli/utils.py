#!/usr/bin/env python3
"""
CLI utility functions for file operations, validation, and error handling
"""

import asyncio
import sys
import traceback
from datetime import datetime
from enum import Enum
from pathlib import Path

import click

from ..config.config_manager import ConfigManager
from ..shared.file_utils import (
    ensure_results_directory_structure,
    safe_json_dump,
    safe_json_load_model,
    validate_required_api_keys,
)
from ..testing.core.test_models import TestCase


def serialize_nested_models(obj):
    """
    Recursively serialize nested Pydantic models to JSON-serializable dictionaries.

    Args:
        obj: Any object that may contain nested Pydantic models

    Returns:
        JSON-serializable version of the object with all Pydantic models converted to dicts
    """
    if hasattr(obj, "model_dump"):
        # This is a Pydantic model - convert it using mode='json' for better compatibility
        try:
            return serialize_nested_models(obj.model_dump(mode="json"))
        except Exception as e:
            # If model_dump fails, try to get dict representation another way
            try:
                return serialize_nested_models(dict(obj))
            except Exception:
                # Last resort: convert to string representation
                return f"<Serialization Error: {type(obj).__name__}: {str(e)[:100]}>"
    elif isinstance(obj, Enum):
        # Convert enum to its value
        return obj.value
    elif isinstance(obj, dict):
        # Recursively process dictionary values
        return {key: serialize_nested_models(value) for key, value in obj.items()}
    elif isinstance(obj, list | tuple):
        # Recursively process list/tuple items
        return [serialize_nested_models(item) for item in obj]
    elif isinstance(obj, datetime):
        # Convert datetime to ISO format string
        return obj.isoformat()
    else:
        # Return primitive types as-is
        return obj


def handle_execution_errors(results: list, test_suite) -> tuple:
    """Process execution results and handle errors gracefully"""

    successful_results = []
    error_results = []

    for i, result in enumerate(results):
        if isinstance(result, Exception):
            # Convert exception to error result
            test_case = test_suite.test_cases[i]
            error_result = {
                "test_id": test_case.test_id,
                "success": False,
                "error_message": str(result),
                "error_type": type(result).__name__,
            }
            error_results.append(error_result)

            # Log error with context
            click.echo(f"❌ Test {test_case.test_id} failed: {str(result)[:100]}")

        else:
            successful_results.append(result)

    # Show error summary if there were failures
    if error_results:
        click.echo(
            f"\\nWarning: {len(error_results)} tests failed due to execution errors."
        )
        click.echo("Check detailed logs above for specific error messages.")
        click.echo(
            "Common issues: API rate limits, network timeouts, configuration errors."
        )

    return successful_results, error_results


def validate_api_keys():
    """Validate that required API keys are available"""
    keys = validate_required_api_keys("ANTHROPIC_API_KEY", "OPENAI_API_KEY")
    return keys["ANTHROPIC_API_KEY"], keys["OPENAI_API_KEY"]


def load_json_file(file_path: str, model_class):
    """Load and validate JSON file against a Pydantic model"""
    return safe_json_load_model(
        file_path, model_class, f"loading {model_class.__name__}"
    )


def ensure_results_directory():
    """Create XDG-compliant test results directory structure"""
    config_manager = ConfigManager()
    system_paths = config_manager.paths.get_system_paths()
    results_dir = system_paths["data_dir"] / "results"

    return ensure_results_directory_structure(results_dir)


def ensure_local_results_directory():
    """Create local test results directory structure in current working directory"""
    results_dir = Path("./test_results")
    return ensure_results_directory_structure(results_dir)


def _generate_markdown_report_safe(test_run_data: dict, json_file) -> None:
    """Generate markdown report alongside JSON, failing gracefully"""
    try:
        from .markdown_report import generate_markdown_report  # noqa: F401 - imported here to avoid circular dependency

        markdown_file = json_file.with_suffix(".md")
        generate_markdown_report(test_run_data, markdown_file)
    except Exception as e:
        click.echo(f"Warning: Could not generate markdown report: {e}", err=True)


def write_test_results_with_location(
    run_id: str, test_run, evaluations, summary, use_global_dir: bool = False
):
    """Write test results to JSON files with location choice"""
    import os
    import uuid

    if use_global_dir:
        runs_dir = ensure_results_directory()  # Existing XDG function
    else:
        runs_dir = ensure_local_results_directory()  # New local function

    # Generate datetime prefix with collision safety
    # Add process ID, microseconds, and UUID for collision safety
    datetime_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")[
        :-3
    ]  # Include milliseconds
    unique_id = str(uuid.uuid4())[:8]
    filename_prefix = f"{datetime_str}_{os.getpid()}_{unique_id}_{run_id}"

    # Use recursive serialization to handle all nested Pydantic models
    test_run_data = serialize_nested_models(test_run)

    if evaluations:
        test_run_data["evaluations"] = serialize_nested_models(evaluations)

    if summary:
        test_run_data["summary"] = serialize_nested_models(summary)

    # Write main test run results (now includes evaluations and summary)
    run_file = runs_dir / f"{filename_prefix}.json"
    safe_json_dump(test_run_data, run_file, "writing test results")

    _generate_markdown_report_safe(test_run_data, run_file)

    # Return run_file and None for eval_file to maintain backward compatibility
    return run_file, None


def convert_test_case_definition_to_test_case(test_case_def, server_name: str):
    """Convert TestCaseDefinition from JSON to TestCase for ConversationManager"""
    return TestCase(
        test_id=test_case_def.test_id,
        user_message=test_case_def.user_message,
        success_criteria=test_case_def.success_criteria,
        mcp_server=server_name,
        timeout_seconds=test_case_def.timeout_seconds,
        metadata=test_case_def.metadata or {},
    )


def write_test_results(run_id: str, test_run, evaluations, summary):
    """Write test results to JSON files"""
    import os
    import uuid

    runs_dir = ensure_results_directory()

    # Generate datetime prefix with collision safety
    # Add process ID, microseconds, and UUID for collision safety
    datetime_str = datetime.now().strftime("%Y-%m-%d_%H-%M-%S-%f")[
        :-3
    ]  # Include milliseconds
    unique_id = str(uuid.uuid4())[:8]
    filename_prefix = f"{datetime_str}_{os.getpid()}_{unique_id}_{run_id}"

    # Use recursive serialization to handle all nested Pydantic models
    test_run_data = serialize_nested_models(test_run)

    if evaluations:
        test_run_data["evaluations"] = serialize_nested_models(evaluations)

    if summary:
        test_run_data["summary"] = serialize_nested_models(summary)

    # Write main test run results (now includes evaluations and summary)
    run_file = runs_dir / f"{filename_prefix}.json"
    safe_json_dump(test_run_data, run_file, "writing test results")

    _generate_markdown_report_safe(test_run_data, run_file)

    # Return run_file, None, None to maintain backward compatibility
    return run_file, None, None


def handle_connection_error(error: Exception, server_url: str | None = None) -> str:
    """Convert connection errors to user-friendly messages"""
    error_msg = str(error).lower()

    if "ssl" in error_msg or "certificate" in error_msg:
        return "❌ SSL/Certificate error connecting to server. Please check the server's SSL configuration."
    elif "connection refused" in error_msg:
        return f"❌ Connection refused. The server at {server_url or 'the specified URL'} is not running or not accessible."
    elif (
        "connection cancelled" in error_msg or "server may be unreachable" in error_msg
    ):
        return f"❌ Unable to connect to server at {server_url or 'the specified URL'}. Please verify:\n   • Server is running and accessible\n   • URL is correct\n   • Network connectivity is available"
    elif "timeout" in error_msg:
        return f"❌ Connection timeout. The server at {server_url or 'the specified URL'} is taking too long to respond."
    elif "not found" in error_msg or "404" in error_msg:
        return "❌ Server endpoint not found. Please check the URL path."
    else:
        return f"❌ Connection error: {error!s}"


def handle_async_error(error: Exception, verbose: bool = False) -> str:
    """Convert async task errors to user-friendly messages"""
    error_msg = str(error).lower()

    if "attempted to exit cancel scope" in error_msg:
        return "❌ Internal async task management error. This may be due to a coding issue with nested event loops."
    elif "task was cancelled" in error_msg:
        return (
            "❌ Operation was cancelled. This may be due to a timeout or interruption."
        )
    elif "future cancelled" in error_msg:
        return "❌ Test execution was cancelled unexpectedly."
    elif "unhandled exception" in error_msg and "asyncio" in error_msg:
        return "❌ Unhandled async error occurred during test execution."
    elif verbose:
        return f"❌ Async error: {error!s}"
    else:
        return "❌ An async execution error occurred. Use --verbose for details."


def safe_run_async(
    coro,
    error_context: str | None = None,
    server_url: str | None = None,
    verbose: bool = False,
):
    """Safely run an async coroutine with proper error handling"""
    try:
        return asyncio.run(coro)
    except KeyboardInterrupt:
        click.echo("\n❌ Operation cancelled by user")
        sys.exit(1)
    except Exception as e:
        # Check if it's a connection error
        if any(
            keyword in str(e).lower()
            for keyword in ["connection", "ssl", "timeout", "refused", "unreachable"]
        ):
            click.echo(handle_connection_error(e, server_url))
        # Check if it's an async error
        elif any(
            keyword in str(e).lower()
            for keyword in ["cancel scope", "task", "future", "asyncio"]
        ):
            click.echo(handle_async_error(e, verbose))
        # Generic error handling
        elif verbose:
            click.echo(f"❌ Error in {error_context or 'operation'}: {e!s}")
            click.echo("Stack trace:")
            click.echo(traceback.format_exc())
        else:
            click.echo(f"❌ Error in {error_context or 'operation'}: {e!s}")
            click.echo("Use --verbose flag for detailed error information")

        sys.exit(1)
