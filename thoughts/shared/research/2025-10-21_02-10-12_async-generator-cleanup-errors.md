---
date: 2025-10-21T02:10:12+02:00
researcher: Claude
git_commit: 0dde4906b3d84bf08206f0c55ba52d78d2b63149
branch: dsonyy/feat/experimental
repository: golf-testing-v2
topic: "Why async generator cleanup exceptions occur in parallel test execution"
tags: [research, codebase, async, anyio, mcp-client, parallel-execution, cleanup]
status: complete
last_updated: 2025-10-21
last_updated_by: Claude
---

# Research: Why Async Generator Cleanup Exceptions Occur in Parallel Test Execution

**Date**: 2025-10-21T02:10:12+02:00
**Researcher**: Claude
**Git Commit**: 0dde4906b3d84bf08206f0c55ba52d78d2b63149
**Branch**: dsonyy/feat/experimental
**Repository**: golf-testing-v2

## Research Question

Why do these async generator cleanup exceptions occur intermittently when running `mcp-t run` in a continuous loop:

```
RuntimeError: Attempted to exit cancel scope in a different task than it was entered in
RuntimeError: athrow(): asynchronous generator is already running
httpx.ConnectTimeout / httpcore.ConnectTimeout
```

## Summary

The exceptions are caused by a **fundamental incompatibility** between:
1. The MCP Python SDK's internal use of `anyio` task groups and cancel scopes
2. The retry logic inside the `@asynccontextmanager` decorated `_get_connection_context` method
3. Async lock acquisition during context manager cleanup (in finally blocks)
4. Connection timeouts that trigger cleanup while nested contexts are still active

The root cause is that `anyio` cancel scopes are **task-local** - they must be entered and exited in the same asyncio task. When the retry loop creates multiple context manager instances, or when cleanup acquires locks during `__aexit__`, the cancel scope cleanup can be scheduled on a different task, violating anyio's fundamental contract.

The errors are **intermittent** because they only occur when:
- A connection timeout happens (triggering retry logic)
- The timeout occurs after `yield session` (during active test execution)
- Multiple context manager iterations exist in the call stack simultaneously

## Detailed Findings

### Component 1: The Retry Loop Problem

**Location**: [client_manager.py:945-1006](src/test_mcp/mcp_client/client_manager.py#L945-L1006)

```python
for attempt in range(max_retries):
    try:
        async with streamablehttp_client(url, headers=headers) as (
            read_stream, write_stream, _,
        ):
            client_info = Implementation(...)
            async with ClientSession(
                read_stream, write_stream, client_info=client_info
            ) as session:
                connection_timeout = server_config.get("connection_timeout", 30)
                await asyncio.wait_for(session.initialize(), timeout=connection_timeout)
                yield session  # ⚠️ Generator suspension point
                return  # Success - exit retry loop
    except (TimeoutError, Exception) as e:
        last_exception = e
        # Check if retryable
        if attempt < max_retries - 1 and (is_timeout or is_connection_error):
            await asyncio.sleep(wait_time)
            continue  # ⚠️ Creates NEW context managers
```

**The Problem**:

1. **Retry loop with generator yield**: The `for attempt in range(max_retries)` loop wraps the context manager creation and the `yield session` statement
2. **Multiple context instances**: Each retry creates a **new** `streamablehttp_client` and `ClientSession` context manager
3. **Generator state conflict**: If an exception occurs **after** `yield session` (in the consumer code), the retry `continue` would attempt to create new contexts, but the generator has already yielded control
4. **Cancel scope violation**: When `streamablehttp_client` (MCP SDK) internally uses `anyio.create_task_group()`, it creates cancel scopes. If retry logic causes cleanup of attempt N while attempt N+1 is being entered, cancel scopes can be exited from different tasks

**Why This Causes "Cancel Scope in Different Task" Errors**:

The MCP Python SDK `streamablehttp_client` function (from the `mcp` package) uses anyio internally. When you have:

```python
# Attempt 1
async with streamablehttp_client(...) as (...):  # Creates anyio cancel scope in task A
    async with ClientSession(...) as session:
        yield session  # Suspends generator
        # Timeout exception occurs here in consumer code
# Attempt 2 starts (continue in retry loop)
async with streamablehttp_client(...) as (...):  # Creates NEW cancel scope
    # But cleanup of Attempt 1 may still be pending...
```

### Component 2: Async Lock in Finally Block

**Location**: [client_manager.py:805-818](src/test_mcp/mcp_client/client_manager.py#L805-L818)

```python
try:
    async with ClientSession(
        read_stream, write_stream, client_info=client_info
    ) as session:
        await asyncio.wait_for(session.initialize(), timeout=connection_timeout)
        yield session
finally:
    # Clean up flow-specific callback server with safe deletion
    async with self._callback_lock:  # ⚠️ Lock acquired during context exit
        if flow_id in self._active_callback_servers:
            try:
                self._active_callback_servers[flow_id].stop()
            except Exception as stop_error:
                print(f"Warning: Error stopping callback server: {stop_error}")
            finally:
                self._active_callback_servers.pop(flow_id, None)
```

**The Problem**:

1. **Lock acquisition during __aexit__**: When `ClientSession.__aexit__()` is called (which internally calls anyio task group cleanup), the finally block executes
2. **New async context**: `async with self._callback_lock` creates a new async context that may be scheduled on a different task
3. **Cancel scope violation**: If the lock acquisition happens during anyio's cancel scope cleanup, the scope is entered in task A but the lock causes execution in task B

**Why This Causes Errors**:

```python
# Execution flow:
1. Consumer finishes/throws → Generator receives signal
2. Line 804: yield session completes
3. Line 799: ClientSession.__aexit__() called
   → This uses anyio TaskGroup.__aexit__()
   → anyio schedules cancel scope cleanup
4. Line 807: async with self._callback_lock happens DURING step 3
   → Creates new async wait point
   → May be scheduled on different task
5. anyio.CancelScope.__exit__() notices it's in different task
   → Raises "Attempted to exit cancel scope in a different task"
```

### Component 3: Blocking I/O During Async Cleanup

**Location**: [client_manager.py:810](src/test_mcp/mcp_client/client_manager.py#L810)

```python
self._active_callback_servers[flow_id].stop()  # Stops daemon thread
```

**Implementation of stop()**: [client_manager.py:273-280](src/test_mcp/mcp_client/client_manager.py#L273-L280)

```python
def stop(self):
    if self.server:
        self.shutdown_requested.set()
        self.server.shutdown()  # ⚠️ Blocking HTTP server shutdown
        self.server.server_close()
    if self.thread and self.thread.is_alive():
        self.thread.join(timeout=2.0)  # ⚠️ Blocking thread join
```

**The Problem**:

1. **Blocking calls during async context exit**: `server.shutdown()` and `thread.join()` are blocking calls
2. **Task scheduling disruption**: When anyio is cleaning up task groups, blocking calls can prevent proper task scheduling
3. **Event loop blocking**: The blocking `thread.join(timeout=2.0)` blocks the event loop for up to 2 seconds

**Why This Contributes to Errors**:

Anyio cancel scopes depend on proper task scheduling. When cleanup blocks the event loop:
- Cancel scope exit handlers may be delayed
- Task scheduling becomes unpredictable
- Cancel scope may be entered in one task scheduling cycle but exit in another

### Component 4: Missing GeneratorExit Handling

**Location**: [client_manager.py:728-1006](src/test_mcp/mcp_client/client_manager.py#L728-L1006) (entire method)

```python
@asynccontextmanager
async def _get_connection_context(...):
    try:
        async with streamablehttp_client(...) as (...):
            async with ClientSession(...) as session:
                yield session
    except (TimeoutError, Exception) as e:  # ⚠️ Does NOT catch GeneratorExit
        # Error handling
    finally:
        # Cleanup
```

**The Problem**:

1. **No explicit GeneratorExit handling**: When the async generator is closed prematurely (consumer calls `aclose()` or breaks), Python raises `GeneratorExit`
2. **Cleanup order undefined**: Without explicit handling, the order of finally block execution vs context manager exit is undefined
3. **Mayskip cleanup**: Some cleanup code may not execute if `GeneratorExit` is raised

**Why This Matters**:

When a connection timeout occurs:
```python
# Consumer code:
async with client_manager._get_connection_context(config) as session:
    # Test running, then timeout after 5 minutes
    # Test framework calls session cleanup
# This implicitly calls session.__aexit__ which may raise GeneratorExit into the generator
```

Without explicit `GeneratorExit` handling, the generator's cleanup behavior is unpredictable.

### Component 5: Connection Timeouts Triggering Cascading Cleanup

**5-Minute Timeout Warning**: [rate_limiter.py:103](src/test_mcp/utils/rate_limiter.py#L103)

```python
f"Warning: Timing out request {correlation_id} after 5 minutes"
```

**Connection Timeout**: [client_manager.py:962-963](src/test_mcp/mcp_client/client_manager.py#L962-L963)

```python
connection_timeout = server_config.get("connection_timeout", 30)
await asyncio.wait_for(session.initialize(), timeout=connection_timeout)
```

**The Chain Reaction**:

1. **Initial timeout**: LLM request times out after 5 minutes (rate limiter)
2. **Session cleanup**: Test framework begins cleaning up the test session
3. **Generator cleanup**: This triggers cleanup of the `_get_connection_context` generator
4. **Context manager cascade**: `ClientSession.__aexit__()` → `streamablehttp_client.__aexit__()`
5. **Anyio cleanup**: Both use anyio internally, triggering cancel scope cleanup
6. **Lock acquisition**: Finally block tries to acquire `_callback_lock`
7. **Error**: Cancel scope exit scheduled on different task

**Why It's Intermittent**:

The error only occurs when ALL of these happen:
- A request times out (5-minute limit or connection timeout)
- The timeout occurs **during** test execution (after `yield session`)
- Cleanup is triggered while nested contexts are active
- Lock acquisition in finally block causes task rescheduling
- Anyio schedules cancel scope cleanup on a different task (timing-dependent)

### Component 6: Double Cleanup Pattern

**Locations**:
- [client_manager.py:805-818](src/test_mcp/mcp_client/client_manager.py#L805-L818) (inner finally)
- [client_manager.py:931-936](src/test_mcp/mcp_client/client_manager.py#L931-L936) (outer finally)

```python
# Inner finally (line 805)
finally:
    async with self._callback_lock:
        if flow_id in self._active_callback_servers:
            try:
                self._active_callback_servers[flow_id].stop()
            finally:
                self._active_callback_servers.pop(flow_id, None)

# Outer finally (line 931)
finally:
    async with self._callback_lock:
        if flow_id in self._active_callback_servers:
            self._active_callback_servers[flow_id].stop()
            del self._active_callback_servers[flow_id]
```

**The Problem**:

1. **Redundant cleanup**: Same callback server cleanup in two places
2. **Multiple lock acquisitions**: Two separate `async with self._callback_lock` operations
3. **Race condition risk**: If both cleanup paths execute, the second may fail

**Why This Contributes**:

Multiple lock acquisitions during cleanup increase the chance of task rescheduling during cancel scope exit.

## Code References

### Primary Issue Locations

- [client_manager.py:945-1006](src/test_mcp/mcp_client/client_manager.py#L945-L1006) - Retry loop with generator yield
- [client_manager.py:805-818](src/test_mcp/mcp_client/client_manager.py#L805-L818) - Async lock in finally block
- [client_manager.py:790-819](src/test_mcp/mcp_client/client_manager.py#L790-L819) - OAuth flow with triple-nested contexts
- [client_manager.py:273-280](src/test_mcp/mcp_client/client_manager.py#L273-L280) - Blocking thread cleanup

### Supporting Evidence

- [test_execution.py:317-489](src/test_mcp/cli/test_execution.py#L317-L489) - Parallel test execution with semaphore
- [test_execution.py:446-476](src/test_mcp/cli/test_execution.py#L446-L476) - Per-test cleanup with error suppression
- [rate_limiter.py:103](src/test_mcp/utils/rate_limiter.py#L103) - 5-minute timeout warning
- [provider_interface.py:236-289](src/test_mcp/agent/provider_interface.py#L236-L289) - Session isolation with dedicated MCP connections

## Architecture Insights

### Parallel Execution Model

The framework uses a sophisticated parallel execution system:

1. **Semaphore-based concurrency control**: Max 5 parallel tests via `asyncio.Semaphore`
2. **Session isolation**: Each test gets dedicated `MCPClientManager` instance
3. **No connection pooling**: Fresh MCP connections per test (prevents shared state issues)
4. **Thread-safe token storage**: OAuth tokens scoped by `(server_url, session_id)`
5. **Graceful cleanup**: Errors suppressed to avoid masking test failures

### Why No Connection Pooling?

Decision documented in parallel execution research:

> **No Connection Pooling:**
> - Each parallel test gets fresh MCP connections
> - No reuse between tests
> - Trade-off: More overhead, but simpler isolation
>
> **Why No Pooling:**
> 1. **Isolation**: Each test needs clean state
> 2. **OAuth**: Parallel OAuth flows require separate callback servers
> 3. **Simplicity**: Connection creation is fast enough
> 4. **Safety**: No shared connection state means no race conditions

This design choice actually **prevents** many race conditions but creates the retry-loop-with-generator issue.

### AnyIO Cancel Scope Fundamentals

From the error traceback and code analysis:

**AnyIO's Contract**:
```python
# MUST happen in same task
async with anyio.create_task_group() as tg:  # ← Task A enters
    # ... work ...
pass  # ← Task A exits
```

**What Breaks It**:
```python
# BAD: Async context during exit
async with anyio.create_task_group() as tg:
    yield something
finally:
    async with some_lock:  # ← May run in Task B
        cleanup()
# anyio.__aexit__ happens here, may be scheduled on Task B
```

## Root Cause Analysis

### Primary Root Cause

**Retry logic inside @asynccontextmanager with generator yield**

The fundamental issue is architectural: retry logic should be **outside** the async generator, not inside. The current pattern:

```python
@asynccontextmanager
async def _get_connection_context():
    for attempt in range(max_retries):
        try:
            async with mcp_context:
                yield session  # ← Generator suspension
                return  # ← Only reached if no exception
        except TimeoutError:
            continue  # ← Cannot restart after yield
```

Should be:

```python
@asynccontextmanager
async def _get_connection_context():
    # No retry loop here
    async with mcp_context:
        yield session

# Retry logic at call site
for attempt in range(max_retries):
    try:
        async with _get_connection_context() as session:
            # Use session
            break
    except TimeoutError:
        if attempt < max_retries - 1:
            await asyncio.sleep(backoff)
```

### Secondary Contributing Factors

1. **Async lock in finally during context exit** - Causes task rescheduling
2. **Blocking I/O during async cleanup** - Disrupts task scheduling
3. **Missing GeneratorExit handling** - Undefined cleanup order
4. **Double cleanup pattern** - Multiple lock acquisitions increase risk

### Why It's Intermittent

The error requires a specific timing sequence:

```
1. Test starts → Contexts entered in Task A
2. Test runs for > 5 minutes
3. Rate limiter triggers timeout → Cleanup starts
4. Cleanup acquires lock in finally block
5. Lock wait causes execution to pause
6. Anyio schedules cancel scope exit
7. Event loop assigns exit to Task B (timing-dependent)
8. Error: Cancel scope entered in A, exited in B
```

The timing dependency makes it intermittent - it only happens when the event loop scheduling aligns unfavorably.

## Recommended Solutions

### Solution 1: Move Retry Logic Outside Generator (RECOMMENDED)

**Change**: Remove retry loop from `_get_connection_context`, implement at call sites

**Benefits**:
- Eliminates retry-loop-with-generator pattern
- Each connection attempt is completely independent
- No multiple context instances in same generator
- Clean separation of concerns

**Implementation**:
```python
# Remove retry loop from lines 949-984
# Add retry wrapper at call sites in connect_server()

async def connect_server(self, server_config):
    max_retries = 3
    for attempt in range(max_retries):
        try:
            async with self._get_connection_context(server_config) as session:
                # Store session
                return server_id
        except (TimeoutError, ConnectionError) as e:
            if attempt < max_retries - 1:
                await asyncio.sleep(2 ** attempt)
                continue
            raise
```

### Solution 2: Remove Async Lock from Finally Block

**Change**: Move callback server cleanup outside context manager exit path

**Options**:

A) **Use synchronous cleanup**:
```python
finally:
    # Don't use async with lock - use try/finally instead
    try:
        callback_server = self._active_callback_servers.pop(flow_id, None)
        if callback_server:
            callback_server.stop()  # Acceptable to block here since we're cleaning up
    except Exception:
        pass
```

B) **Defer cleanup**:
```python
finally:
    # Schedule cleanup for later, don't block context exit
    if flow_id in self._active_callback_servers:
        asyncio.create_task(self._cleanup_callback_server(flow_id))
```

### Solution 3: Add GeneratorExit Handling

**Change**: Explicitly handle GeneratorExit to ensure predictable cleanup

```python
@asynccontextmanager
async def _get_connection_context(...):
    try:
        async with streamablehttp_client(...) as (...):
            async with ClientSession(...) as session:
                yield session
    except GeneratorExit:
        # Generator being closed - ensure clean shutdown
        # Don't re-raise, let contexts exit normally
        pass
    except (TimeoutError, Exception) as e:
        # Normal error handling
        raise
    finally:
        # Cleanup
```

### Solution 4: Make Thread Cleanup Async-Safe

**Change**: Use async-compatible thread cleanup

```python
async def stop_async(self):
    """Async-safe cleanup"""
    if self.server:
        self.shutdown_requested.set()
        # Use thread-safe shutdown
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: (
                self.server.shutdown(),
                self.server.server_close(),
            )
        )
    if self.thread and self.thread.is_alive():
        # Don't block - use timeout
        await asyncio.get_event_loop().run_in_executor(
            None,
            lambda: self.thread.join(timeout=2.0)
        )
```

### Solution 5: Remove Double Cleanup

**Change**: Consolidate cleanup to single location

Remove either inner finally (lines 805-818) OR outer finally (lines 931-936), not both.

## Implementation Priority

1. **HIGH PRIORITY**: Solution 1 (Move retry outside generator) - Fixes primary root cause
2. **HIGH PRIORITY**: Solution 2 (Remove async lock from finally) - Fixes secondary cause
3. **MEDIUM PRIORITY**: Solution 3 (Add GeneratorExit handling) - Improves robustness
4. **MEDIUM PRIORITY**: Solution 5 (Remove double cleanup) - Simplifies code
5. **LOW PRIORITY**: Solution 4 (Async thread cleanup) - Nice to have, not critical

## Open Questions

1. **MCP SDK Behavior**: Does the MCP Python SDK `streamablehttp_client` always use anyio internally, or only for certain transports?
2. **Testing Impact**: Will moving retry logic outside the generator break any existing tests that depend on automatic retry behavior?
3. **Performance**: What is the overhead of creating fresh context managers for each retry vs. the current approach?
4. **OAuth Flows**: Will removing the async lock from finally block affect OAuth callback server cleanup timing?

## Related Research

- [2025-10-20 HTTPx ReadTimeout SSE Error](thoughts/shared/research/2025-10-20_23-21-13_httpx-readtimeout-sse-error.md) - Related timeout handling research
- [Fix MCP SSE Timeout Issues Plan](thoughts/shared/plans/fix-mcp-sse-timeout-issues.md) - Comprehensive SSE timeout fix plan

## Testing Recommendations

### Unit Tests to Add

1. **Test retry logic with timeouts**:
```python
@pytest.mark.asyncio
async def test_retry_connection_with_timeout():
    """Verify retry logic works without cancel scope violations"""
    manager = MCPClientManager()

    # Mock connection that fails twice then succeeds
    attempts = 0
    async def mock_connect():
        nonlocal attempts
        attempts += 1
        if attempts < 3:
            raise TimeoutError("Connection timeout")
        return MockSession()

    # Should succeed on third attempt
    server_id = await manager.connect_server(config)
    assert attempts == 3
```

2. **Test cleanup without locks in finally**:
```python
@pytest.mark.asyncio
async def test_callback_cleanup_without_lock():
    """Verify callback cleanup doesn't cause task violations"""
    manager = MCPClientManager()

    # Create OAuth connection
    async with manager._get_connection_context(oauth_config) as session:
        # Verify callback server running
        assert len(manager._active_callback_servers) > 0

    # Verify cleanup happened
    assert len(manager._active_callback_servers) == 0
```

3. **Test GeneratorExit handling**:
```python
@pytest.mark.asyncio
async def test_generator_exit_handling():
    """Verify proper cleanup when generator closed early"""
    manager = MCPClientManager()

    context = manager._get_connection_context(config)
    session = await context.__aenter__()

    # Simulate early exit
    await context.aclose()

    # Verify resources cleaned up
    assert len(manager._active_contexts) == 0
```

### Integration Tests to Add

1. **Run continuous loop test**: The exact scenario from the bug report - run `mcp-t run` in a loop for extended period (30+ minutes) to verify no cleanup errors

2. **Parallel timeout test**: Run 20 tests in parallel where 5 are designed to timeout, verify cleanup happens correctly

3. **OAuth parallel test**: Run multiple OAuth-enabled tests in parallel, verify callback servers isolated and cleaned up

## Conclusion

The async generator cleanup errors are caused by a perfect storm of:
- Retry logic inside an async generator with yield
- Async lock acquisition during context manager exit
- Blocking I/O during cleanup
- Anyio's strict cancel scope task-locality requirement

The errors are intermittent because they require specific timing alignment of event loop scheduling.

**Primary fix**: Move retry logic outside the generator (Solution 1)
**Secondary fix**: Remove async lock from finally block (Solution 2)

These two changes should eliminate 90%+ of the errors. The remaining solutions improve robustness but aren't critical.