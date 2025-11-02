#!/usr/bin/env python3
"""
Markdown report generator for test results
"""

from pathlib import Path
from typing import Any

# Maximum message length before truncation in conversation transcripts
MAX_MESSAGE_LENGTH = 1000  # Increased to show more context


def generate_markdown_report(test_run_data: dict[str, Any], output_path: Path) -> None:
    """
    Generate a concise markdown report from test run data.

    Uses top-down communication: summary → test list → detailed results
    Ensures no information duplication and progressive disclosure.

    Args:
        test_run_data: Serialized test run data (same as JSON output)
        output_path: Path where markdown file should be written
    """
    sections = [
        _generate_header(test_run_data),
        _generate_executive_summary(test_run_data),
        _generate_test_results_overview(test_run_data),
        _generate_detailed_results(test_run_data),
    ]

    markdown_content = "\n\n".join(sections)

    output_path.write_text(markdown_content, encoding="utf-8")


def _generate_header(data: dict) -> str:
    """Generate report header with run metadata"""
    timestamp = data.get("timestamp", "Unknown")
    run_id = data.get("run_id", "Unknown")
    suite_name = data.get("test_suite", {}).get("name", "Unknown")
    server_name = data.get("server_config", {}).get("name", "Unknown")

    return f"""# Test Report: {suite_name}

**Run ID**: `{run_id}`
**Timestamp**: {timestamp}
**Server**: {server_name}
**Report Type**: MCP Test Execution"""


def _generate_executive_summary(data: dict) -> str:
    """Generate high-level summary with key metrics"""
    summary = data.get("summary", {})

    total = summary.get("total_tests", 0)
    pass_rate = summary.get("pass_rate", 0.0)
    passed = int(total * pass_rate)
    failed = total - passed
    duration = summary.get("duration_seconds", 0.0)

    lines = [
        "## Executive Summary",
        "",
        f"**Total Tests**: {total}  ",
        f"**Passed**: {passed} ({pass_rate * 100:.1f}%)  ",
        f"**Failed**: {failed}  ",
        f"**Duration**: {duration:.2f}s  ",
    ]

    return "\n".join(lines)


def _generate_test_results_overview(data: dict) -> str:
    """Generate compact list of all test results"""
    results = data.get("results", [])

    if not results:
        return "## Test Results\n\nNo tests executed."

    lines = [
        "## Test Results Overview",
        "",
        "| Status | Test ID | Duration | Score |",
        "|--------|---------|----------|-------|",
    ]

    for result in results:
        test_id = result.get("test_id", "Unknown")
        # Always use judge evaluation when available, fall back to execution success
        evaluation = result.get("evaluation", {})
        if evaluation:  # Judge evaluation available
            success = evaluation.get("success", False)
            overall_score = evaluation.get("overall_score", 0.0)
        else:  # No judge evaluation (security/compliance), use execution success
            success = result.get("success", False)
            overall_score = 0.0  # No score available for non-judged tests
        duration = result.get("execution_time", 0.0)

        status = "✅ PASS" if success else "❌ FAIL"
        score_display = f"{overall_score:.1f}/10" if evaluation else "N/A"
        lines.append(f"| {status} | `{test_id}` | {duration:.2f}s | {score_display} |")

    return "\n".join(lines)


def _generate_detailed_results(data: dict) -> str:
    """Generate detailed information for each test"""
    results = data.get("results", [])

    if not results:
        return ""

    sections = ["## Detailed Test Results"]

    for result in results:
        section = _generate_single_test_detail(result)
        sections.append(section)

    return "\n\n".join(sections)


def _generate_single_test_detail(result: dict) -> str:
    """Generate detailed section for a single test"""
    test_id = result.get("test_id", "Unknown")
    # Use evaluation success instead of conversation success
    evaluation = result.get("evaluation", {})
    success = evaluation.get("success", False)
    message = result.get("message", "")
    duration = result.get("execution_time", 0.0)

    status = "✅ PASSED" if success else "❌ FAILED"

    lines = [
        f"### {test_id}",
        "",
        f"**Status**: {status}  ",
        f"**Duration**: {duration:.2f}s  ",
    ]

    # Wrap message in code block if it exists to prevent markdown injection
    if message:
        lines.append("**Message**:")
        lines.append("```")
        lines.append(message)
        lines.append("```")
        lines.append("")

    # Add evaluation details if available
    if evaluation:
        lines.extend(_generate_evaluation_details(evaluation))

    # Add conversation details if available
    details = result.get("details", {})
    conv_result = details.get("conversation_result")

    if conv_result:
        lines.extend(_generate_conversation_details(conv_result))

    # Add compliance/security details if available
    if "compliance_results" in details:
        lines.extend(_generate_compliance_details(details["compliance_results"]))

    if "security_result" in details:
        lines.extend(_generate_security_details(details["security_result"]))

    return "\n".join(lines)


def _generate_evaluation_details(evaluation: dict) -> list[str]:
    """Generate LLM judge evaluation details"""
    if not evaluation:
        return []

    lines = [
        "",
        "#### LLM Judge Evaluation",
        "",
        f"**Overall Score**: {evaluation.get('overall_score', 0):.1f}/10  ",
        f"**Success**: {'✅ PASSED' if evaluation.get('success', False) else '❌ FAILED'}  ",
        "",
    ]

    # Criteria scores breakdown
    criteria_scores = evaluation.get("criteria_scores", {})
    if criteria_scores:
        lines.extend(
            [
                "**Criteria Scores**:",
            ]
        )
        for criterion, score in criteria_scores.items():
            # Format criterion name (goal_achieved -> Goal Achieved)
            formatted_name = criterion.replace("_", " ").title()
            lines.append(f"- {formatted_name}: {score:.1f}/1.0")
        lines.append("")

    # Judge reasoning
    reasoning = evaluation.get("reasoning", "")
    if reasoning:
        lines.extend(
            [
                "**Judge Reasoning**:",
                "```",
                reasoning,
                "```",
                "",
            ]
        )

    return lines


def _extract_tool_results_from_raw_data(raw_data: list) -> dict:
    """Extract tool results from raw conversation data and map them to tool use IDs"""
    tool_results = {}

    for entry in raw_data:
        if entry.get("role") == "user" and isinstance(entry.get("content"), list):
            for content_item in entry["content"]:
                if content_item.get("type") == "tool_result":
                    tool_use_id = content_item.get("tool_use_id")
                    result_content = content_item.get("content")
                    if tool_use_id and result_content:
                        tool_results[tool_use_id] = result_content

    return tool_results


def _generate_conversation_details(conv: dict) -> list[str]:
    """Generate conversation-specific details"""
    lines = [
        "",
        "#### Conversation Details",
        "",
        f"**Total Turns**: {conv.get('total_turns', 0)}  ",
        f"**Status**: {conv.get('status', 'Unknown')}  ",
        f"**Goal Achieved**: {conv.get('goal_achieved', False)}  ",
    ]

    # Tool usage summary
    tools_used = conv.get("tools_used", [])
    if tools_used:
        lines.append(f"**Tools Used**: {', '.join(set(tools_used))}  ")

    # Extract tool results from raw conversation data
    raw_data = conv.get("raw_conversation_data", [])
    tool_results_map = _extract_tool_results_from_raw_data(raw_data) if raw_data else {}

    # Conversation turns
    turns = conv.get("turns", [])
    if turns:
        lines.extend(
            [
                "",
                "#### Conversation Transcript",
                "",
            ]
        )

        for turn in turns:
            speaker = turn.get("speaker", "Unknown")
            message = turn.get("message", "")
            tool_calls = turn.get("tool_calls", [])

            # Truncate long messages but preserve more context
            if len(message) > MAX_MESSAGE_LENGTH:
                message = message[: MAX_MESSAGE_LENGTH - 3] + "..."

            # Wrap message in code block to prevent markdown injection
            lines.append(f"**{speaker.upper()}**:")
            lines.append("```")
            lines.append(message)
            lines.append("```")

            if tool_calls:
                lines.append("**Tool Calls:**")
                for tool_call in tool_calls:
                    # ToolCall model uses 'tool_name' field, not 'name'
                    tool_name = tool_call.get(
                        "tool_name", tool_call.get("name", "Unknown")
                    )
                    input_params = tool_call.get("input_params", {})
                    result = tool_call.get("result")
                    error = tool_call.get("error")
                    execution_time = tool_call.get("execution_time_ms")

                    lines.append(f"- 🔧 **{tool_name}**")

                    # Show input parameters
                    if input_params:
                        params_str = ", ".join(
                            [f"{k}={v}" for k, v in input_params.items()]
                        )
                        lines.append(f"  - Input: `{params_str}`")

                    # Show execution time if available
                    if execution_time is not None:
                        lines.append(f"  - Duration: {execution_time}ms")

                    # Try to get result from tool results map first (from raw data)
                    # This is where the actual API responses are stored
                    tool_result_from_raw = None

                    # Look for tool results using various possible IDs
                    # The raw conversation data might have tool_use_id that matches call_id
                    for raw_turn in raw_data:
                        if (
                            raw_turn.get("role") == "assistant"
                            and "_tool_calls" in raw_turn
                        ):
                            for raw_tool_call in raw_turn["_tool_calls"]:
                                if raw_tool_call.get("tool_name") == tool_name:
                                    call_id = raw_tool_call.get("call_id")
                                    if call_id and call_id in tool_results_map:
                                        tool_result_from_raw = tool_results_map[call_id]
                                        break

                    # Show result or error
                    if error:
                        lines.append(f"  - ❌ Error: `{error}`")
                    elif tool_result_from_raw:
                        # Parse the actual tool result from raw data
                        result_str = str(tool_result_from_raw)
                        if len(result_str) > 300:
                            result_str = result_str[:300] + "..."
                        lines.append(f"  - ✅ Result: `{result_str}`")
                    elif result is not None:
                        # Fallback to result field if available
                        result_str = str(result)
                        if len(result_str) > 300:
                            result_str = result_str[:300] + "..."
                        lines.append(f"  - ✅ Result: `{result_str}`")
                    else:
                        lines.append(f"  - ⚠️ No result data available")

            lines.append("")

    return lines


def _generate_compliance_details(compliance_results: list[dict]) -> list[str]:
    """Generate compliance test details"""
    if not compliance_results:
        return []

    lines = [
        "",
        "#### Compliance Results",
        "",
    ]

    for result in compliance_results:
        check_name = result.get("check_name", "Unknown")
        passed = result.get("compliance_passed", False)
        severity = result.get("severity", "Unknown")
        message = result.get("message", "")

        status = "✅" if passed else "❌"
        lines.append(f"{status} **{check_name}** ({severity}):")
        if message:
            lines.append("```")
            lines.append(message)
            lines.append("```")
        lines.append("")

    return lines


def _generate_security_details(security_result: dict) -> list[str]:
    """Generate security test details"""
    lines = [
        "",
        "#### Security Assessment",
        "",
        f"**Overall Score**: {security_result.get('overall_security_score', 0)}/100  ",
    ]

    # Vulnerability counts
    critical = security_result.get("critical_vulnerabilities", 0)
    high = security_result.get("high_vulnerabilities", 0)
    medium = security_result.get("medium_vulnerabilities", 0)
    low = security_result.get("low_vulnerabilities", 0)

    if any([critical, high, medium, low]):
        lines.extend(
            [
                "",
                "**Vulnerabilities Found**:",
                f"- Critical: {critical}",
                f"- High: {high}",
                f"- Medium: {medium}",
                f"- Low: {low}",
            ]
        )

    # Individual test results
    test_results = security_result.get("test_results", [])
    if test_results:
        lines.extend(
            [
                "",
                "**Security Checks**:",
            ]
        )

        for test in test_results:
            name = test.get("name", "Unknown")
            vuln_detected = test.get("vulnerability_detected", False)
            severity = test.get("severity", "Unknown")

            status = "❌" if vuln_detected else "✅"
            lines.append(f"{status} {name} ({severity})")

    return lines
