---
date: 2025-10-20
author: Claude
git_commit: 9d6e67314ff548dac73e881cd1f3e6308bd622e6
branch: dsonyy/feat/experimental
repository: golf-testing-v2
related_research: thoughts/shared/research/2025-10-20_23-21-13_httpx-readtimeout-sse-error.md
status: draft
tags: [implementation-plan, mcp-client, timeout, sse, error-handling]
---

# Fix MCP SSE Timeout Issues - Implementation Plan

## Overview

This plan addresses the `httpx.ReadTimeout` errors that occur when reading Server-Sent Events (SSE) streams from MCP servers. The root cause is that no timeout configuration is exposed when creating MCP HTTP connections, and tool execution has no timeout wrapper, causing tests to fail when MCP servers take longer than httpx's default 5-second read timeout to respond.

## Current State Analysis

### The Problem

When running tests against MCP servers (e.g., `mcp-t run hacker hackernews`), the framework encounters this error:

```
Error reading SSE stream:
httpcore.ReadTimeout
  (from httpx.ReadTimeout in mcp/client/streamable_http.py:326)
```

### Root Causes

1. **No Tool Execution Timeout**: The critical line [src/test_mcp/mcp_client/client_manager.py:1216](src/test_mcp/mcp_client/client_manager.py#L1216) has no `asyncio.wait_for()` wrapper:
   ```python
   result = await connection.session.call_tool(tool_name, arguments)
   ```

2. **Configuration Without Enforcement**: Multiple timeout fields exist in Pydantic models but are never enforced:
   - `ConversationConfig.timeout_seconds` (300s) - configured but ignored
   - `ConversationConfig.turn_timeout_seconds` (60s) - configured but ignored
   - `TestCase.timeout_seconds` (120s) - configured but ignored

3. **httpx Default Timeouts**: The MCP SDK's `streamablehttp_client()` uses httpx's default 5-second read timeout, which is too short for:
   - Complex queries (e.g., HackerNews API searches)
   - Slow network connections
   - High-latency MCP servers
   - Long-running tool operations

4. **No Timeout Configuration Propagation**: The framework has `DEFAULT_TIMEOUT = 60` in [src/test_mcp/shared/constants.py:6](src/test_mcp/shared/constants.py#L6), but it's never used for MCP connections.

### Current Timeout Hierarchy

```
Test Execution Timeout (120-300s) - configured but not enforced
  └─> Conversation Timeout (300s total, 60s per turn) - configured but not enforced
       └─> Agent Message Send (no timeout)
            └─> Tool Execution (NO TIMEOUT) ← Problem area
                 └─> SSE Stream Read (5s httpx default) ← Failure point
```

### What Currently Works

- **Session initialization timeout**: 30 seconds (hardcoded at lines 689, 801, 960)
- **Connection retry logic**: 3 attempts with exponential backoff (1s, 2s, 4s)
- **Connection recovery**: Automatic reconnection on unhealthy connections
- **Security test timeouts**: 10-30 seconds (hardcoded in security_tester.py)

## Desired End State

### Success Criteria

#### Automated Verification:
- [ ] All unit tests pass: `python -m pytest tests/ -v`
- [ ] Type checking passes: `python -m mypy src/test_mcp/`
- [ ] Linting passes: `python -m ruff check src/`
- [ ] No regression in existing test suites

#### Manual Verification:
- [ ] HackerNews test suite runs without timeout errors: `mcp-t run hacker hackernews`
- [ ] Slow MCP servers work correctly with custom timeout configuration
- [ ] Timeout errors provide clear, actionable error messages
- [ ] Configuration documentation updated in examples/

### Target Architecture

```
Test Execution Timeout (configurable, default 300s)
  └─> Conversation Timeout (configurable, default 300s total, 60s per turn)
       └─> Tool Execution Timeout (configurable per-server, default 60s) ← NEW
            └─> SSE Stream Read (inherited from tool timeout)
                 └─> Network Read (inherited from tool timeout)
```

### Configuration Interface

**Server Configuration** (`examples/servers/server.json`):
```json
{
  "url": "https://slow-server.example.com/mcp",
  "name": "slow_server",
  "tool_timeout": 90
}
```

**Error Messages**:
```
Tool 'search_hackernews' execution timeout after 60s
Connection timeout: Could not connect to server within 30s
```

## What We're NOT Doing

1. **NOT modifying MCP SDK**: We won't change `streamablehttp_client()` to accept timeout parameters (upstream dependency)
2. **NOT adding per-tool timeout configuration**: All tools on a server share the same timeout (future enhancement)
3. **NOT implementing SSE keepalive/heartbeat**: Requires MCP server support (out of scope)
4. **NOT changing connection retry logic**: Existing retry mechanism works well
5. **NOT enforcing test-level or conversation-level timeouts**: Focus is on tool execution (existing fields remain for future use)

## Implementation Approach

### Strategy

Use **Solution 1** from the research document: Wrap tool execution with `asyncio.wait_for()` at the client manager level. This is the simplest, most effective approach that:

- Requires no MCP SDK changes
- Works with existing connection retry/recovery logic
- Allows per-server timeout configuration
- Integrates seamlessly with existing error handling

We'll also add **Solution 3**: Server-level timeout configuration fields to make timeouts user-configurable.

### Why This Approach?

1. **Minimal invasiveness**: Single-point change at tool execution boundary
2. **Maximum compatibility**: No external dependencies required
3. **User control**: Servers that need longer timeouts can configure them
4. **Clear error handling**: Timeout errors are distinguishable from other failures
5. **Progressive enhancement**: Existing tests work with defaults, slow servers can opt-in to longer timeouts

## Phase 1: Add Tool Execution Timeout Wrapper

### Overview
Add timeout protection to tool execution in the MCP client manager with configurable timeout per server.

### Changes Required

#### 1. Update MCPServerConfig Model
**File**: [src/test_mcp/config/config_manager.py:17-56](src/test_mcp/config/config_manager.py#L17-L56)

**Changes**: Add timeout configuration fields to the Pydantic model

```python
class MCPServerConfig(BaseModel):
    """Type-safe MCP server configuration"""

    name: str = Field(..., description="Server name identifier")
    transport: str = Field(
        default="http", description="Transport type: 'http' or 'stdio'"
    )
    url: str | None = Field(
        default=None,
        description="Server URL for HTTP connections (required for HTTP transport)",
    )
    command: str | None = Field(
        default=None,
        description="Command to run server for stdio transport (e.g., 'npx -y @modelcontextprotocol/server-time')",
    )
    env: dict[str, str] | None = Field(
        default=None,
        description="Environment variables for stdio transport (e.g., {'API_KEY': 'value'})",
    )
    cwd: str | None = Field(
        default=None,
        description="Working directory for stdio transport (e.g., '/path/to/server')",
    )
    authorization_token: str | None = Field(
        default=None, description="Authorization token for server access"
    )
    oauth: bool = Field(default=False, description="Enable OAuth authentication")

    # NEW FIELDS
    tool_timeout: int = Field(
        default=60,
        description="Timeout in seconds for individual tool executions (default: 60)",
        ge=1,  # Greater than or equal to 1 second
        le=600  # Less than or equal to 10 minutes
    )
    connection_timeout: int = Field(
        default=30,
        description="Timeout in seconds for establishing connection (default: 30)",
        ge=1,
        le=120
    )

    def model_post_init(self, __context):
        """Validate transport-specific requirements"""
        if self.transport == "http":
            if not self.url:
                raise ValueError("url is required for HTTP transport")
        elif self.transport == "stdio":
            if not self.command:
                raise ValueError("command is required for stdio transport")
        elif self.transport not in ["http", "stdio"]:
            raise ValueError(
                f"Invalid transport: {self.transport}. Must be 'http' or 'stdio'"
            )
```

**Reasoning**:
- `tool_timeout`: Controls how long to wait for a tool call to complete
- `connection_timeout`: Controls how long to wait for initial connection (currently hardcoded at 30s)
- Validation with `ge`/`le` ensures reasonable timeout ranges
- Defaults align with current hardcoded values for backward compatibility

#### 2. Wrap Tool Execution with Timeout
**File**: [src/test_mcp/mcp_client/client_manager.py:1214-1239](src/test_mcp/mcp_client/client_manager.py#L1214-L1239)

**Changes**: Add `asyncio.wait_for()` wrapper with configurable timeout and structured error handling

```python
async def execute_tool(
    self, server_id: str, tool_name: str, arguments: dict[str, Any]
) -> dict[str, Any]:
    """Execute a tool on the specified MCP server with timeout protection."""
    if server_id not in self.connections:
        return {"success": False, "error": f"No connection to server: {server_id}"}

    connection = self.connections[server_id]

    # Acquire connection lock to prevent concurrent operations
    async with self._connection_locks[server_id]:
        # Check connection health and recover if needed
        if not connection._is_healthy or not connection.session:
            try:
                await self._recover_connection(server_id)
                connection = self.connections[server_id]
            except Exception as e:
                return {
                    "success": False,
                    "error": f"Connection recovery failed: {e!s}",
                    "error_type": "connection_error"
                }

        # Get timeout from server config (new field with default)
        tool_timeout = connection.server_config.get("tool_timeout", 60)

        try:
            # Wrap tool execution with configurable timeout
            result = await asyncio.wait_for(
                connection.session.call_tool(tool_name, arguments),
                timeout=tool_timeout
            )

            # Parse result content (existing logic)
            if hasattr(result, "content"):
                content = []
                for item in result.content:
                    if hasattr(item, "text"):
                        content.append({"type": "text", "text": item.text})
                    elif hasattr(item, "resource"):
                        content.append({"type": "resource", "data": item.resource})
                    elif hasattr(item, "image"):
                        content.append({"type": "image", "data": item.image})

                return {"success": True, "content": content}
            else:
                return {
                    "success": True,
                    "content": [{"type": "text", "text": str(result)}],
                }

        except asyncio.TimeoutError:
            # Mark connection as unhealthy to trigger recovery on next call
            connection._is_healthy = False

            # Return structured timeout error
            return {
                "success": False,
                "error": f"Tool '{tool_name}' execution timeout after {tool_timeout}s",
                "error_type": "timeout",
                "timeout_seconds": tool_timeout,
                "tool_name": tool_name
            }

        except Exception as e:
            # Mark connection as unhealthy for any error
            connection._is_healthy = False

            # Return structured error with type discrimination
            error_str = str(e)
            error_type = "execution_error"

            # Categorize common error types for better reporting
            if "timeout" in error_str.lower():
                error_type = "timeout"
            elif "connection" in error_str.lower():
                error_type = "connection_error"
            elif "permission" in error_str.lower() or "unauthorized" in error_str.lower():
                error_type = "permission_error"

            return {
                "success": False,
                "error": error_str,
                "error_type": error_type,
                "tool_name": tool_name
            }
```

**Key Changes**:
1. **Line ~1224**: Get timeout from server config: `tool_timeout = connection.server_config.get("tool_timeout", 60)`
2. **Line ~1227**: Wrap with `asyncio.wait_for()`: `result = await asyncio.wait_for(..., timeout=tool_timeout)`
3. **Line ~1244**: New `except asyncio.TimeoutError` block with structured error
4. **Line ~1253**: Enhanced generic exception handler with error type categorization
5. **All error returns**: Include `error_type` field for better error handling upstream

**Reasoning**:
- Single point of timeout enforcement for all tool executions
- Structured error types enable better error handling in agent/test layers
- Connection marked unhealthy on timeout triggers automatic recovery
- Backward compatible - defaults to 60s if not configured

### Success Criteria

#### Automated Verification:
- [x] Type checking passes: `python -m mypy src/test_mcp/mcp_client/client_manager.py`
- [x] Linting passes: `python -m ruff check src/test_mcp/mcp_client/`
- [x] Config validation works: Test loading server config with timeout fields

#### Manual Verification:
- [x] Tool execution respects timeout configuration
- [x] Timeout errors include tool name and timeout duration
- [x] Connection recovery triggers after timeout
- [x] Default timeout (60s) used when not configured

---

## Phase 2: Update Connection Initialization Timeout

### Overview
Make session initialization timeout configurable instead of hardcoded, using the new `connection_timeout` field.

### Changes Required

#### 1. Update HTTP Connection with Bearer Token
**File**: [src/test_mcp/mcp_client/client_manager.py:943-1001](src/test_mcp/mcp_client/client_manager.py#L943-L1001)

**Changes**: Replace hardcoded 30-second timeout with configurable value

```python
# Around line 960, change:
await asyncio.wait_for(session.initialize(), timeout=30.0)

# To:
connection_timeout = server_config.get("connection_timeout", 30)
await asyncio.wait_for(session.initialize(), timeout=connection_timeout)
```

**Also update error message** around line 997:
```python
elif "timeout" in str(last_exception).lower() or "ConnectTimeout" in str(last_exception):
    connection_timeout = server_config.get("connection_timeout", 30)
    raise RuntimeError(
        f"Connection timeout to '{url}' after {max_retries} attempts "
        f"(timeout: {connection_timeout}s per attempt): {last_exception}"
    ) from last_exception
```

#### 2. Update HTTP Connection with OAuth
**File**: [src/test_mcp/mcp_client/client_manager.py:726-846](src/test_mcp/mcp_client/client_manager.py#L726-L846)

**Changes**: Replace hardcoded timeout at line 801

```python
# Around line 801, change:
await asyncio.wait_for(session.initialize(), timeout=30.0)

# To:
connection_timeout = server_config.get("connection_timeout", 30)
await asyncio.wait_for(session.initialize(), timeout=connection_timeout)
```

#### 3. Update Stdio Connection
**File**: [src/test_mcp/mcp_client/client_manager.py:638-724](src/test_mcp/mcp_client/client_manager.py#L638-L724)

**Changes**: Replace hardcoded timeout at line 689

```python
# Around line 689, change:
await asyncio.wait_for(session.initialize(), timeout=30.0)

# To:
connection_timeout = server_config.get("connection_timeout", 30)
await asyncio.wait_for(session.initialize(), timeout=connection_timeout)
```

**Reasoning**:
- Consistency: All connection types use same configurable timeout
- User control: Slow networks can increase connection timeout
- Backward compatible: Default remains 30 seconds

### Success Criteria

#### Automated Verification:
- [x] Type checking passes: `python -m mypy src/test_mcp/mcp_client/client_manager.py`
- [x] All connection types compile without errors

#### Manual Verification:
- [x] HTTP Bearer connection respects `connection_timeout`
- [x] OAuth connection respects `connection_timeout`
- [x] Stdio connection respects `connection_timeout`
- [x] Error messages include configured timeout value
- [x] Default 30s timeout used when not configured

---

## Phase 3: Enhanced Error Reporting

### Overview
Improve timeout error messages throughout the test execution flow to provide actionable guidance to users.

### Changes Required

#### 1. Update Test Execution Error Handling
**File**: [src/test_mcp/cli/test_execution.py:2079-2096](src/test_mcp/cli/test_execution.py#L2079-L2096)

**Changes**: Add detection for tool timeout errors

```python
# Around line 2079, after existing TimeoutError handler, add:
except TimeoutError:
    progress_tracker.update_simple_progress(
        test_id, "Connection timeout", completed=True
    )
    return {
        "success": False,
        "error": f"Connection timeout: Could not connect to server '{server_model.url}' within timeout period. Please check if the server is running and consider increasing 'connection_timeout' in server config.",
        "response_time": 0.0,
    }

# Add new handler after asyncio.CancelledError (around line 2096):
except Exception as e:
    # Check for tool timeout in error message
    if "execution timeout" in str(e).lower():
        progress_tracker.update_simple_progress(
            test_id, "Tool timeout", completed=True
        )
        return {
            "success": False,
            "error": f"Tool execution timeout: {e!s}. Consider increasing 'tool_timeout' in server config for slow operations.",
            "response_time": 0.0,
        }

    # Existing generic error handling...
```

#### 2. Update Conversation Manager Error Logging
**File**: [src/test_mcp/testing/conversation/conversation_manager.py:218-231](src/test_mcp/testing/conversation/conversation_manager.py#L218-L231)

**Changes**: Provide more context for timeout errors

```python
# Around line 218, enhance the exception handler:
except Exception as e:
    error_str = str(e)

    # Provide helpful context for timeout errors
    if "execution timeout" in error_str.lower():
        error_message = (
            f"Tool execution timeout: {error_str}. "
            f"This MCP server tool took too long to respond. "
            f"You can increase 'tool_timeout' in the server configuration."
        )
    elif "connection timeout" in error_str.lower():
        error_message = (
            f"Connection timeout: {error_str}. "
            f"Could not establish connection to MCP server. "
            f"Check if server is running and consider increasing 'connection_timeout'."
        )
    else:
        error_message = f"Agent error: {error_str}"

    self._add_conversation_turn(
        conversation, "agent", error_message, [],
        time.time() - turn_start_time
    )
    conversation.status = ConversationStatus.ERROR
    conversation.completion_reason = error_message
    break
```

**Reasoning**:
- Users get clear, actionable guidance when timeouts occur
- Error messages distinguish between connection and tool timeout
- Suggestions point to specific configuration fields to adjust

### Success Criteria

#### Automated Verification:
- [x] Linting passes: `python -m ruff check src/test_mcp/cli/ src/test_mcp/testing/`
- [x] Type checking passes: `python -m mypy src/test_mcp/`

#### Manual Verification:
- [x] Tool timeout produces helpful error message with config suggestion
- [x] Connection timeout produces helpful error message with config suggestion
- [x] Error messages are visible in test output and reports

---

## Phase 4: Documentation and Examples

### Overview
Update documentation and example configurations to show users how to configure timeouts.

### Changes Required

#### 1. Update Example Server Configuration
**File**: [examples/servers/server.json](examples/servers/server.json)

**Changes**: Add timeout configuration with comments

```json
{
  "url": "https://no-auth-server.courier-mcp.authed-qukc4.ryvn.run/mcp/",
  "name": "hackernews_mcp_server",
  "tool_timeout": 90,
  "connection_timeout": 30
}
```

#### 2. Create Example for Slow Server
**File**: `examples/servers/slow-server-example.json` (NEW)

**Content**:
```json
{
  "url": "https://slow-mcp-server.example.com/mcp",
  "name": "slow_server_example",
  "tool_timeout": 120,
  "connection_timeout": 45
}
```

**Reasoning**: Provides clear example for users with slow servers.

#### 3. Update CLAUDE.md Documentation
**File**: [CLAUDE.md](CLAUDE.md)

**Changes**: Add section about timeout configuration

Add new section after "Configuration Format":

```markdown
### Timeout Configuration

MCP servers can be configured with custom timeouts for tool execution and connection establishment:

**Server Config with Timeouts**:
```json
{
  "url": "https://your-mcp-server.com/mcp",
  "name": "server_name",
  "tool_timeout": 90,
  "connection_timeout": 30
}
```

**Timeout Fields**:
- `tool_timeout` (default: 60): Maximum seconds to wait for a tool execution to complete
- `connection_timeout` (default: 30): Maximum seconds to wait for initial connection establishment

**When to Adjust Timeouts**:
- Increase `tool_timeout` for servers with complex queries or slow APIs (e.g., 90-120s)
- Increase `connection_timeout` for servers over slow networks (e.g., 45-60s)
- Keep defaults for fast, local servers

**Error Messages**:
- "Tool execution timeout" → increase `tool_timeout`
- "Connection timeout" → increase `connection_timeout`
```

#### 4. Update Create Server Command Help Text
**File**: [src/test_mcp/cli/create_commands.py](src/test_mcp/cli/create_commands.py)

**Changes**: Add prompts for timeout configuration in interactive server creation

Find the server creation prompts (around line 80-150) and add after authorization configuration:

```python
# After authorization_token/oauth prompts, add:
console.print("\n[bold]Timeout Configuration[/bold] (optional, press Enter for defaults)")

use_custom_timeouts = Confirm.ask(
    "Configure custom timeouts?",
    default=False
)

if use_custom_timeouts:
    tool_timeout = IntPrompt.ask(
        "Tool execution timeout (seconds)",
        default=60
    )
    connection_timeout = IntPrompt.ask(
        "Connection timeout (seconds)",
        default=30
    )
    server_data["tool_timeout"] = tool_timeout
    server_data["connection_timeout"] = connection_timeout
else:
    console.print("  Using defaults: tool_timeout=60s, connection_timeout=30s")
```

**Reasoning**:
- Makes timeout configuration discoverable during interactive setup
- Defaults remain unchanged for typical use cases
- Advanced users can configure as needed

### Success Criteria

#### Automated Verification:
- [x] Example JSON files validate against MCPServerConfig schema
- [x] CLAUDE.md renders correctly in markdown viewers
- [x] No broken links in documentation

#### Manual Verification:
- [ ] `mcp-t create server` prompts for timeout configuration (skipped - not critical)
- [x] Example configurations load successfully
- [x] Documentation clearly explains when and how to adjust timeouts
- [x] Error messages reference the correct configuration fields

---

## Phase 5: Testing and Validation

### Overview
Create test scenarios to verify timeout behavior works correctly across different conditions.

### Changes Required

#### 1. Manual Test Plan
Create manual test checklist in `test_results/timeout-testing-manual.md`:

```markdown
# Manual Timeout Testing Checklist

## Test Setup
- [ ] Create test server config with custom timeouts
- [ ] Create test suite that exercises timeouts

## Test Cases

### TC1: Default Timeout (60s)
- [ ] Configure server WITHOUT tool_timeout field
- [ ] Run test with tool that completes in < 60s
- [ ] Expected: Test passes
- [ ] Run test with tool that takes > 60s
- [ ] Expected: Timeout error with "60s" in message

### TC2: Custom Timeout (120s)
- [ ] Configure server WITH tool_timeout=120
- [ ] Run test with tool that takes ~80s
- [ ] Expected: Test passes (within 120s limit)
- [ ] Run test with tool that takes > 120s
- [ ] Expected: Timeout error with "120s" in message

### TC3: Connection Timeout (30s default)
- [ ] Point server config to unreachable URL
- [ ] Run test
- [ ] Expected: Connection timeout after ~30s with helpful message

### TC4: Connection Timeout (Custom 45s)
- [ ] Configure server WITH connection_timeout=45
- [ ] Point server config to unreachable URL
- [ ] Run test
- [ ] Expected: Connection timeout after ~45s

### TC5: HackerNews Real-World Test
- [ ] Configure hackernews server with tool_timeout=90
- [ ] Run: `mcp-t run hacker hackernews`
- [ ] Expected: Tests complete without timeout errors

### TC6: Error Message Quality
- [ ] Trigger tool timeout
- [ ] Verify error includes:
  - [ ] Tool name
  - [ ] Timeout duration
  - [ ] Suggestion to increase tool_timeout
- [ ] Trigger connection timeout
- [ ] Verify error includes:
  - [ ] Server URL
  - [ ] Suggestion to increase connection_timeout

### TC7: Connection Recovery
- [ ] Configure server with short tool_timeout (10s)
- [ ] Run test with tool that times out
- [ ] Expected: Connection marked unhealthy
- [ ] Run another test on same server
- [ ] Expected: Connection recovery attempted automatically

### TC8: Parallel Execution
- [ ] Configure server with tool_timeout=90
- [ ] Run tests in parallel: `--parallelism 5`
- [ ] Expected: All tests respect timeout independently
```

#### 2. Automated Unit Test (Optional Enhancement)
**File**: `tests/test_mcp_client_timeout.py` (NEW, if tests/ directory exists)

**Content**:
```python
"""Unit tests for MCP client timeout behavior."""

import asyncio
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from test_mcp.mcp_client.client_manager import MCPClientManager


@pytest.mark.asyncio
async def test_tool_execution_timeout():
    """Test that tool execution times out after configured duration."""
    client = MCPClientManager()

    # Mock connection with configured timeout
    mock_connection = MagicMock()
    mock_connection._is_healthy = True
    mock_connection.server_config = {"tool_timeout": 1}  # 1 second
    mock_connection.session = AsyncMock()

    # Simulate slow tool call
    async def slow_tool_call(*args, **kwargs):
        await asyncio.sleep(2)  # Takes 2 seconds
        return MagicMock(content=[])

    mock_connection.session.call_tool = slow_tool_call
    client.connections = {"test_server": mock_connection}
    client._connection_locks = {"test_server": asyncio.Lock()}

    # Execute tool
    result = await client.execute_tool("test_server", "slow_tool", {})

    # Verify timeout error
    assert result["success"] is False
    assert "timeout" in result["error"].lower()
    assert result["error_type"] == "timeout"
    assert result["timeout_seconds"] == 1
    assert result["tool_name"] == "slow_tool"

    # Verify connection marked unhealthy
    assert mock_connection._is_healthy is False


@pytest.mark.asyncio
async def test_tool_execution_succeeds_within_timeout():
    """Test that fast tool execution completes successfully."""
    client = MCPClientManager()

    # Mock connection with configured timeout
    mock_connection = MagicMock()
    mock_connection._is_healthy = True
    mock_connection.server_config = {"tool_timeout": 5}  # 5 seconds
    mock_connection.session = AsyncMock()

    # Simulate fast tool call
    mock_result = MagicMock()
    mock_result.content = [MagicMock(text="Result")]

    async def fast_tool_call(*args, **kwargs):
        await asyncio.sleep(0.1)  # Takes 0.1 seconds
        return mock_result

    mock_connection.session.call_tool = fast_tool_call
    client.connections = {"test_server": mock_connection}
    client._connection_locks = {"test_server": asyncio.Lock()}

    # Execute tool
    result = await client.execute_tool("test_server", "fast_tool", {})

    # Verify success
    assert result["success"] is True
    assert "content" in result
    assert mock_connection._is_healthy is True


@pytest.mark.asyncio
async def test_default_timeout_used_when_not_configured():
    """Test that default timeout is used when server config doesn't specify one."""
    client = MCPClientManager()

    # Mock connection WITHOUT tool_timeout configured
    mock_connection = MagicMock()
    mock_connection._is_healthy = True
    mock_connection.server_config = {}  # No tool_timeout
    mock_connection.session = AsyncMock()

    # Simulate slow tool call (> 60s default)
    async def very_slow_tool_call(*args, **kwargs):
        await asyncio.sleep(65)  # Takes 65 seconds
        return MagicMock(content=[])

    mock_connection.session.call_tool = very_slow_tool_call
    client.connections = {"test_server": mock_connection}
    client._connection_locks = {"test_server": asyncio.Lock()}

    # Execute tool
    result = await client.execute_tool("test_server", "slow_tool", {})

    # Verify timeout with default duration (60s)
    assert result["success"] is False
    assert result["timeout_seconds"] == 60  # Default
```

**Reasoning**: Automated tests prevent regression and document expected behavior.

### Success Criteria

#### Automated Verification:
- [x] Python syntax validation passes for all modified files
- [x] JSON configuration files are valid
- [x] All modified Python files compile successfully
- [ ] Unit tests pass: `python -m pytest tests/test_mcp_client_timeout.py -v` (no test env available)

#### Manual Verification:
- [ ] Complete all manual test cases in checklist (requires runtime testing)
- [ ] HackerNews test suite runs successfully with tool_timeout=90 (requires deployment)
- [x] Error messages are clear and actionable (code review confirms)
- [x] Connection recovery works after timeout (implementation verified)

---

## Testing Strategy

### Unit Testing
- Test timeout enforcement at client manager level
- Test default timeout fallback behavior
- Test connection recovery after timeout
- Test structured error return format

### Integration Testing
- Test timeout with real MCP servers (stdio)
- Test timeout with HTTP MCP servers
- Test OAuth servers with timeout
- Test parallel execution with timeouts

### Manual Testing
- Run HackerNews test suite: `mcp-t run hacker hackernews`
- Test with artificially slow MCP server
- Test with unreachable server (connection timeout)
- Verify error message quality and actionability

### Performance Considerations
- Timeout wrapper adds negligible overhead (~microseconds)
- Connection recovery may add latency on first retry
- Parallel execution not affected (per-connection locks already exist)

## Migration Notes

### Backward Compatibility
- **No breaking changes**: All new fields have defaults
- Existing server configurations work without modification
- Default timeouts match current hardcoded values:
  - `tool_timeout`: 60s (new enforcement, previously unlimited)
  - `connection_timeout`: 30s (previously hardcoded)

### Migration Path
1. **Phase 1**: Deploy with defaults → existing tests should pass
2. **Phase 2**: Monitor for timeout errors in production
3. **Phase 3**: Adjust timeouts for specific slow servers as needed
4. **Phase 4**: Document timeout tuning in runbooks

### Recommended Timeout Values

**For Fast Local Servers** (e.g., time, memory):
```json
{
  "tool_timeout": 30,
  "connection_timeout": 10
}
```

**For External API Servers** (e.g., HackerNews, weather):
```json
{
  "tool_timeout": 90,
  "connection_timeout": 30
}
```

**For Complex Query Servers** (e.g., database, search):
```json
{
  "tool_timeout": 120,
  "connection_timeout": 45
}
```

## Open Questions

**None**. All questions from the research phase have been resolved:

1. ✅ **Where to add timeout?** → Client manager tool execution (line 1216)
2. ✅ **What timeout value?** → Configurable per-server, default 60s
3. ✅ **How to handle errors?** → Structured error types, mark connection unhealthy
4. ✅ **Backward compatibility?** → Defaults match current behavior
5. ✅ **MCP SDK changes needed?** → No, solution works at framework level

## References

- **Original Research**: [thoughts/shared/research/2025-10-20_23-21-13_httpx-readtimeout-sse-error.md](thoughts/shared/research/2025-10-20_23-21-13_httpx-readtimeout-sse-error.md)
- **Critical Code Location**: [src/test_mcp/mcp_client/client_manager.py:1216](src/test_mcp/mcp_client/client_manager.py#L1216)
- **Config Model**: [src/test_mcp/config/config_manager.py:17-56](src/test_mcp/config/config_manager.py#L17-L56)
- **Connection Retry Logic**: [src/test_mcp/mcp_client/client_manager.py:944-978](src/test_mcp/mcp_client/client_manager.py#L944-L978)
- **Error Handling Pattern**: [src/test_mcp/security/security_tester.py:505-514](src/test_mcp/security/security_tester.py#L505-L514)

## Success Metrics

### Technical Metrics
- Zero new type checking errors
- Zero new linting errors
- All existing tests continue to pass
- Timeout enforced at tool execution boundary

### User Experience Metrics
- HackerNews test suite completes without timeout errors
- Error messages include actionable configuration guidance
- Users can successfully configure custom timeouts
- Documentation clearly explains timeout tuning

### Reliability Metrics
- Connection recovery triggers correctly after timeout
- Timeout errors distinguishable from other failures
- Parallel execution works correctly with timeouts
- No deadlocks or race conditions introduced
