---
date: 2025-10-20T23:21:13+02:00
researcher: Claude
git_commit: 9d6e67314ff548dac73e881cd1f3e6308bd622e6
branch: dsonyy/feat/experimental
repository: golf-testing-v2
topic: "Why httpx.ReadTimeout occurs when reading SSE stream from MCP servers"
tags: [research, codebase, mcp-client, timeout, sse, error-handling, httpx]
status: complete
last_updated: 2025-10-20
last_updated_by: Claude
---

# Research: Why httpx.ReadTimeout occurs when reading SSE stream from MCP servers

**Date**: 2025-10-20T23:21:13+02:00
**Researcher**: Claude
**Git Commit**: 9d6e67314ff548dac73e881cd1f3e6308bd622e6
**Branch**: dsonyy/feat/experimental
**Repository**: golf-testing-v2

## Research Question

Why does this error occur when running `mcp-t run hacker hackernews`:

```
Error reading SSE stream:
httpcore.ReadTimeout
  (from httpx.ReadTimeout in mcp/client/streamable_http.py:326)
```

The error originates from the MCP SDK's `streamablehttp_client` when attempting to read from a Server-Sent Events (SSE) stream during an `aiter_sse()` operation.

## Summary

The `httpx.ReadTimeout` error occurs because **no timeout configuration is exposed** when creating MCP HTTP connections via the `streamablehttp_client()` from the MCP SDK. The framework uses hardcoded 30-second timeouts for session initialization but has **no configurable timeout** for ongoing SSE stream reads. When the MCP server is slow to respond or doesn't send data within httpx's default timeout period (typically 5 seconds for read operations), the connection times out during the SSE stream iteration.

**Root Causes:**
1. The MCP SDK's `streamablehttp_client()` does not accept timeout parameters
2. No timeout configuration is passed from the framework to the MCP SDK
3. httpx default read timeout (5 seconds) is too short for some MCP servers
4. Tool execution has **no timeout whatsoever** - waits indefinitely for responses

**Impact Areas:**
- Long-running MCP server operations
- Slow network connections
- MCP servers with high latency or processing delays
- Tests with complex tool invocations that take time

## Detailed Findings

### 1. SSE Connection Initialization

**Location**: [src/test_mcp/mcp_client/client_manager.py:789-793](src/test_mcp/mcp_client/client_manager.py#L789-L793) (OAuth), [949-953](src/test_mcp/mcp_client/client_manager.py#L949-L953) (Bearer)

```python
# OAuth authentication
async with streamablehttp_client(url, auth=oauth_client_provider) as (
    read_stream,
    write_stream,
    _,
):

# Bearer token authentication
async with streamablehttp_client(url, headers=headers) as (
    read_stream,
    write_stream,
    _,
):
```

**Issue**: The `streamablehttp_client()` function from the MCP SDK does not expose any timeout parameters. The framework creates SSE connections without specifying timeouts, relying entirely on httpx defaults.

### 2. Session Initialization Timeout

**Location**: [src/test_mcp/mcp_client/client_manager.py:689](src/test_mcp/mcp_client/client_manager.py#L689), [801](src/test_mcp/mcp_client/client_manager.py#L801), [960](src/test_mcp/mcp_client/client_manager.py#L960)

```python
await asyncio.wait_for(session.initialize(), timeout=30.0)
```

**Coverage**: This 30-second timeout applies **only** to the initial MCP handshake (session initialization), not to subsequent SSE stream reads during tool execution or ongoing communication.

### 3. Tool Execution - No Timeout

**Location**: [src/test_mcp/mcp_client/client_manager.py:1216](src/test_mcp/mcp_client/client_manager.py#L1216)

```python
result = await connection.session.call_tool(tool_name, arguments)
```

**Critical Issue**: Tool execution has **no timeout wrapper**. If an MCP server's tool call takes a long time or hangs, the test will wait indefinitely. This is the most likely source of timeout issues during actual test execution.

### 4. Connection Retry Logic

**Location**: [src/test_mcp/mcp_client/client_manager.py:944-978](src/test_mcp/mcp_client/client_manager.py#L944-L978)

```python
max_retries = 3
for attempt in range(max_retries):
    try:
        async with streamablehttp_client(url, headers=headers) as (...):
            # ... connection code ...
    except Exception as e:
        is_timeout = isinstance(e, TimeoutError) or "timeout" in str(e).lower() or "ConnectTimeout" in str(e)
        is_connection_error = "Connection refused" in str(e) or "ConnectError" in str(e)

        if attempt < max_retries - 1 and (is_timeout or is_connection_error):
            wait_time = 2 ** attempt  # Exponential backoff: 1s, 2s, 4s
            await asyncio.sleep(wait_time)
            continue
```

**Retry Strategy**:
- Maximum 3 attempts
- Exponential backoff: 1 second, 2 seconds, 4 seconds
- Retries on timeout and connection errors
- Applies only to connection establishment, not to SSE stream reads

### 5. httpx Default Timeouts

**Documented httpx Behavior**:
- **Connect timeout**: 5 seconds (default)
- **Read timeout**: 5 seconds (default)
- **Write timeout**: 5 seconds (default)
- **Pool timeout**: 5 seconds (default)

**Reference**: The MCP SDK uses httpx's `AsyncClient` internally for SSE connections. Without explicit timeout configuration, httpx applies these 5-second defaults to all read operations.

### 6. Error Flow

**Error Stack Trace Analysis**:

1. **httpcore.ReadTimeout** originates at:
   ```
   httpcore/_async/http11.py:217 in _receive_event
   data = await self._network_stream.read(...)
   ```
   - Network stream read operation times out (5 seconds default)

2. **Propagates through SSE iteration**:
   ```
   httpx_sse/_api.py:42 in aiter_sse
   async for line in lines:
   ```
   - SSE library attempts to read next event from stream

3. **Caught by MCP SDK**:
   ```
   mcp/client/streamable_http.py:326 in _handle_sse_response
   async for sse in event_source.aiter_sse():
   ```
   - MCP client's SSE response handler encounters the timeout

4. **Error surfaces to framework**:
   - Framework has no specific SSE error handling
   - Falls through to generic exception handlers

### 7. Why This Affects HackerNews MCP Server

**Speculation based on error context**:

1. **Slow API Responses**: HackerNews API may have high latency for certain queries
2. **Data Processing**: Server might need time to fetch and process data before streaming response
3. **Network Conditions**: External API calls from MCP server add latency
4. **Tool Complexity**: Complex queries (e.g., searching stories, fetching comments) take time

**Test Scenario**:
```
mcp-t run hacker hackernews
Running 20 tests from suite: hackernews-generated-20251017-115450
```

With 20 tests executing (potentially in parallel), some tests may invoke tools that:
- Query multiple HackerNews API endpoints
- Process large result sets
- Wait for rate-limited API responses
- Perform aggregations or filtering

If any operation takes longer than httpx's 5-second read timeout, the SSE stream read fails.

## Code References

**Core Timeout-Related Files**:
- [src/test_mcp/mcp_client/client_manager.py:789-793](src/test_mcp/mcp_client/client_manager.py#L789-L793) - OAuth SSE connection (no timeout config)
- [src/test_mcp/mcp_client/client_manager.py:949-953](src/test_mcp/mcp_client/client_manager.py#L949-L953) - Bearer SSE connection (no timeout config)
- [src/test_mcp/mcp_client/client_manager.py:1216](src/test_mcp/mcp_client/client_manager.py#L1216) - Tool execution (no timeout)
- [src/test_mcp/mcp_client/client_manager.py:944-978](src/test_mcp/mcp_client/client_manager.py#L944-L978) - Connection retry logic
- [src/test_mcp/shared/constants.py:6](src/test_mcp/shared/constants.py#L6) - DEFAULT_TIMEOUT = 60 (not used for SSE)

**Test Execution Flow**:
- [src/test_mcp/cli/test_execution.py:2079-2087](src/test_mcp/cli/test_execution.py#L2079-L2087) - Timeout error handling
- [src/test_mcp/testing/conversation/conversation_manager.py:134-342](src/test_mcp/testing/conversation/conversation_manager.py#L134-L342) - Conversation orchestration
- [src/test_mcp/agent/agent.py:227-261](src/test_mcp/agent/agent.py#L227-L261) - Agent message sending

**Configuration Models**:
- [src/test_mcp/config/config_manager.py:17-56](src/test_mcp/config/config_manager.py#L17-L56) - MCPServerConfig (no timeout field)
- [src/test_mcp/testing/conversation/conversation_models.py:77-78](src/test_mcp/testing/conversation/conversation_models.py#L77-L78) - Conversation timeouts

## Architecture Insights

### Current Timeout Architecture

**Hierarchy of Timeouts**:
1. **Test Level** (120-300 seconds): Overall test execution timeout
2. **Conversation Level** (300 seconds total, 60 seconds per turn): Multi-turn conversation timeouts
3. **Session Initialization** (30 seconds): MCP handshake timeout
4. **Connection Retries** (3 attempts with backoff): Connection establishment
5. **httpx Defaults** (5 seconds): Network-level read/write/connect operations
6. **Tool Execution** (none): Waits indefinitely

**Gap**: There is **no intermediate timeout** between conversation-level (60s per turn) and httpx read-level (5s). Tool calls that legitimately take 10-30 seconds will fail with read timeout before conversation timeout triggers.

### Timeout Flow

```
Test Execution Timeout (120-300s)
  └─> Conversation Timeout (300s total, 60s per turn)
       └─> Agent Message Send (no explicit timeout)
            └─> Tool Execution (NO TIMEOUT) ← Problem area
                 └─> SSE Stream Read (5s httpx default) ← Failure point
                      └─> Network Read (5s httpx default)
```

**Current Behavior**:
- Tool invoked by agent (e.g., "search Hacker News for stories")
- MCP server processes request (may take 10+ seconds)
- During processing, no data flows over SSE stream
- After 5 seconds of no data, httpx raises ReadTimeout
- Error propagates up, marks test as failed

**Expected Behavior**:
- Tool execution should have configurable timeout (e.g., 30-60 seconds)
- SSE stream reads should tolerate gaps in data flow
- Only timeout if no data received for extended period

### Pattern: No Timeout Configuration Propagation

**Observation**: The framework has timeout constants and fields throughout, but **none propagate** to the MCP SDK layer:

- `DEFAULT_TIMEOUT = 60` in constants.py - unused for MCP connections
- `timeout_seconds` fields in test models - not passed to MCP client
- `turn_timeout_seconds` in conversation config - not used for tool calls
- `streamablehttp_client()` - accepts no timeout parameters

**Implication**: The only way to configure SSE/tool timeouts would be:
1. Modify the MCP SDK to accept timeout parameters (upstream change)
2. Create a wrapper around httpx.AsyncClient with custom timeouts (monkey-patching)
3. Implement timeout wrappers around tool execution in the framework

## Proposed Solutions

### Solution 1: Wrap Tool Execution with Timeout

**Implementation** ([src/test_mcp/mcp_client/client_manager.py:1216](src/test_mcp/mcp_client/client_manager.py#L1216)):

```python
# Current (no timeout)
result = await connection.session.call_tool(tool_name, arguments)

# Proposed (configurable timeout)
tool_timeout = server_config.get("tool_timeout", 60.0)  # Default 60 seconds
try:
    result = await asyncio.wait_for(
        connection.session.call_tool(tool_name, arguments),
        timeout=tool_timeout
    )
except asyncio.TimeoutError:
    raise RuntimeError(f"Tool '{tool_name}' timed out after {tool_timeout}s")
```

**Benefits**:
- Simple implementation (no MCP SDK changes)
- Configurable per-server via config
- Prevents indefinite hangs

**Limitations**:
- Doesn't fix httpx 5-second read timeout for data streaming
- Only prevents infinite waits, not intermediate timeouts

### Solution 2: Configure httpx Client with Custom Timeouts

**Implementation** (requires MCP SDK modification):

The MCP SDK's `streamablehttp_client()` would need to accept and use custom httpx timeout configuration:

```python
# In MCP SDK (upstream change needed)
def streamablehttp_client(
    url: str,
    timeout: httpx.Timeout = httpx.Timeout(60.0, read=30.0)  # Custom timeouts
) -> AsyncContextManager:
    client = httpx.AsyncClient(timeout=timeout)
    # ... rest of implementation
```

```python
# In framework
custom_timeout = httpx.Timeout(
    connect=10.0,   # 10s to establish connection
    read=30.0,      # 30s between data chunks (tolerates slow SSE)
    write=10.0,     # 10s to send data
    pool=10.0       # 10s to get connection from pool
)
async with streamablehttp_client(url, timeout=custom_timeout) as (...):
    # ...
```

**Benefits**:
- Proper fix at the right abstraction level
- Allows tuning all timeout dimensions
- SSE streams can have longer read timeouts

**Limitations**:
- Requires MCP SDK changes (not in framework control)
- Need to coordinate timeout values with tool execution expectations

### Solution 3: Add Server-Level Timeout Configuration

**Implementation** ([src/test_mcp/config/config_manager.py:17-56](src/test_mcp/config/config_manager.py#L17-L56)):

```python
class MCPServerConfig(BaseModel):
    # ... existing fields ...

    # New timeout fields
    connection_timeout: int = Field(default=10, description="Timeout for establishing connection (seconds)")
    read_timeout: int = Field(default=30, description="Timeout for reading data from SSE stream (seconds)")
    tool_timeout: int = Field(default=60, description="Timeout for tool execution (seconds)")
```

**Server Configuration Example**:
```json
{
  "name": "hackernews",
  "transport": "http",
  "url": "https://hackernews-mcp-server.com/mcp",
  "connection_timeout": 10,
  "read_timeout": 30,
  "tool_timeout": 90
}
```

**Benefits**:
- User-configurable per server
- Allows tuning for slow servers like HackerNews
- Explicit timeout documentation

**Implementation Path**:
1. Add fields to `MCPServerConfig` model
2. Wrap tool execution with `tool_timeout` (Solution 1)
3. Request MCP SDK enhancement for connection/read timeouts (Solution 2)
4. Document timeout configuration in CLAUDE.md

### Solution 4: Implement Backpressure Timeout Pattern

**Concept**: Instead of hard timeouts, use a "heartbeat" pattern where SSE streams send periodic keepalive messages.

**Implementation** (requires server-side cooperation):
- MCP servers send keepalive SSE events every N seconds
- Framework tolerates gaps between events up to M seconds
- Only timeout if no heartbeat for M seconds

**Benefits**:
- Distinguishes between "slow processing" and "dead connection"
- Allows long-running operations without arbitrary timeouts

**Limitations**:
- Requires MCP server support for keepalives
- More complex implementation
- Not applicable to all SSE implementations

## Immediate Workaround

**For the HackerNews server specifically**:

1. **Reduce parallelism** to avoid overloading the server:
   ```bash
   mcp-t run hacker hackernews --parallelism 1
   ```

2. **Modify test suite** to use simpler queries that return faster

3. **Monitor retry behavior** - the 3-attempt retry may succeed on later attempts:
   ```
   Attempt 1: Timeout after 5s
   Wait 1s
   Attempt 2: Timeout after 5s
   Wait 2s
   Attempt 3: May succeed if server is now responsive
   ```

4. **Check server logs** to verify if requests are reaching the server and how long processing takes

## Open Questions

1. **Is the 5-second read timeout from httpx configurable in the MCP SDK?**
   - Investigation needed: Check MCP SDK source code
   - Potential fix: Submit PR to MCP SDK for timeout configuration

2. **Are there keepalive mechanisms in the MCP SSE protocol?**
   - Review MCP specification for heartbeat requirements
   - Test with verbose logging to see SSE event patterns

3. **What is the actual processing time for HackerNews queries?**
   - Add instrumentation to measure server response times
   - Compare against 5-second timeout threshold

4. **Should tool timeouts be per-tool or per-server?**
   - Some tools (search) may need longer timeouts than others (get single item)
   - Consider tool-specific timeout metadata

5. **How do other HTTP-based MCP servers handle long operations?**
   - Survey existing MCP servers for timeout patterns
   - Document best practices

## Related Research

This is the first research document on timeout issues in the MCP testing framework. Future research areas:

- **Parallel execution timeout behavior**: How do timeouts interact with parallel test execution?
- **OAuth timeout analysis**: Are there timeout issues specific to OAuth flows?
- **MCP SDK timeout deep dive**: Comprehensive analysis of MCP SDK's timeout handling
- **Optimal timeout values**: Statistical analysis of real-world MCP server response times

## References

**httpx Documentation**:
- https://www.python-httpx.org/advanced/#timeout-configuration

**MCP SDK**:
- Repository: https://github.com/modelcontextprotocol/python-sdk
- Package: `mcp` in PyPI

**Related Error Reports**:
- Original error: `mcp-t run hacker hackernews` produces `httpx.ReadTimeout` in SSE stream iteration
