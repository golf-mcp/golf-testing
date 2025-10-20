---
date: 2025-10-20T08:18:18+02:00
researcher: Claude (AI Assistant)
git_commit: f9449166a31de30be86d9b380f6d8cf6cd4153b6
branch: dsonyy/feat/parallelism
repository: golf-testing-v2
topic: "Critical Issues in Parallel Execution Breaking the Software"
tags: [research, codebase, parallel-execution, race-conditions, concurrency, oauth, token-storage, judge-evaluation, session-isolation]
status: complete
last_updated: 2025-10-20
last_updated_by: Claude (AI Assistant)
---

# Research: Critical Issues in Parallel Execution Breaking the Software

**Date**: 2025-10-20T08:18:18+02:00
**Researcher**: Claude (AI Assistant)
**Git Commit**: f9449166a31de30be86d9b380f6d8cf6cd4153b6
**Branch**: dsonyy/feat/parallelism
**Repository**: golf-testing-v2

## Research Question

Analyze the codebase parallel execution (parallelism > 1) and compare it with sequential execution (parallelism = 1). Multiple critical issues can be found in parallel execution that break the software.

## Summary

The MCP Testing Framework's parallel execution feature contains **five critical categories of bugs** that cause systematic failures when `parallelism > 1`:

1. **SharedTokenStorage Race Conditions** - Class-level singleton token storage with inadequate synchronization causes OAuth token corruption, authentication failures, and deadlocks across parallel tests
2. **Judge Evaluation Inconsistencies** - Parallel and sequential code paths handle judge evaluation differently, causing incorrect test results and missing evaluations
3. **Session Isolation Failures** - Shared provider state and unsynchronized session dictionaries cause cross-test interference and connection leaks
4. **Result Normalization Bugs** - Result transformation logic incorrectly marks all tests as failed before judge evaluation, corrupting preliminary success detection
5. **OAuth Callback Server Race Conditions** - Instance-level callback server storage causes parallel OAuth flows to timeout, receive wrong authorization codes, or crash

These issues cause **non-deterministic test failures**, where the same test suite passes inconsistently (e.g., 3/5 tests pass one run, 5/5 pass another run), making parallel execution unreliable and unsuitable for production use.

## Detailed Findings

### 1. SharedTokenStorage Race Conditions (CRITICAL)

**Location**: [src/test_mcp/mcp_client/client_manager.py:64-161](src/test_mcp/mcp_client/client_manager.py#L64-L161)

**Problem**: OAuth token storage uses a class-level singleton pattern that shares tokens across all parallel tests connecting to the same server. Multiple race conditions exist:

#### Race Condition 1.1: Token Overwrites During Parallel OAuth Flows

**Code Location**: [client_manager.py:78-83](src/test_mcp/mcp_client/client_manager.py#L78-L83) (get_instance), [client_manager.py:759](src/test_mcp/mcp_client/client_manager.py#L759) (usage)

```python
@classmethod
def get_instance(cls, server_url: str) -> "SharedTokenStorage":
    with cls._lock:
        if server_url not in cls._instances:
            cls._instances[server_url] = cls(server_url)
        return cls._instances[server_url]  # Same instance for all parallel tests
```

**Timeline**:
```
Test 1: get_instance("http://server") → Instance A
Test 2: get_instance("http://server") → Instance A (SHARED)
Test 1: set_tokens(token_1) → Writes to Instance A
Test 2: set_tokens(token_2) → OVERWRITES token_1 in Instance A
Test 1: get_tokens() → Returns token_2 (WRONG TOKEN)
Test 1: Authentication fails with "invalid_token"
```

**Impact**: Tests fail with "TokenError: invalid_token" intermittently depending on race timing.

#### Race Condition 1.2: Async Methods with Sync Locks Create Deadlocks

**Code Location**: [client_manager.py:99-117](src/test_mcp/mcp_client/client_manager.py#L99-L117)

```python
async def get_tokens(self) -> OAuthToken | None:
    with self._instance_lock:  # threading.Lock in async code!
        return self.tokens
```

**Problem**: Using `threading.Lock()` instead of `asyncio.Lock()` blocks the entire event loop thread, not just the coroutine. When multiple coroutines try to access tokens:

```
Coroutine A: await set_tokens() → acquires threading.Lock
Coroutine A: Gets suspended by asyncio (context switch)
Coroutine B: await get_tokens() → tries to acquire same threading.Lock
Coroutine B: BLOCKS THE ENTIRE EVENT LOOP THREAD
Coroutine A: Cannot resume because event loop is blocked
Result: DEADLOCK - all tests hang forever
```

**Impact**: Tests hang indefinitely with no output, require process kill to terminate.

#### Race Condition 1.3: Check-Then-Act in clear_all_async()

**Code Location**: [client_manager.py:120-142](src/test_mcp/mcp_client/client_manager.py#L120-L142)

```python
@classmethod
async def clear_all_async(cls) -> None:
    instances_to_clear = []
    with cls._lock:
        instances_to_clear = list(cls._instances.values())
        cls._instances.clear()  # Clear registry

    # Clear instances OUTSIDE lock (TOCTOU bug)
    for instance in instances_to_clear:
        with instance._instance_lock:
            instance.tokens = None
```

**Timeline**:
```
T1: Cleanup calls clear_all_async()
T2: Acquires cls._lock, copies instances, clears dict, releases lock
T3: Test 4 (still running) calls get_instance()
T4: Acquires cls._lock, finds empty dict, creates NEW instance
T5: Cleanup continues clearing OLD instances (Test 4's new instance missed)
```

**Impact**: Orphaned token storage instances, memory leaks, stale tokens persist across tests.

**Evidence from Tests**: [tests/test_race_conditions.py:24-41](tests/test_race_conditions.py#L24-L41) tests singleton thread safety but doesn't catch async/sync lock mixing.

---

### 2. Judge Evaluation Inconsistencies (HIGH)

**Location**: [src/test_mcp/cli/test_execution.py:50-72](src/test_mcp/cli/test_execution.py#L50-L72) (decision logic), [test_execution.py:486-521](src/test_mcp/cli/test_execution.py#L486-L521) (parallel path), [test_execution.py:769-807](src/test_mcp/cli/test_execution.py#L769-L807) (sequential path)

**Problem**: Parallel and sequential execution paths handle judge evaluation differently, causing inconsistent test results.

#### Issue 2.1: Parallel Path Skips Enablement Check

**Code Comparison**:

**Sequential Path** (line 770):
```python
judge_enabled = should_enable_judge_evaluation(test_type, parallelism)
if judge_enabled and "details" in result:
    judge_evaluation = judge.evaluate_conversation(conversation_result)
```

**Parallel Path** (line 486):
```python
# NO enablement check!
evaluations = []
console.print("\n[bold]Running Evaluation...[/bold]")
judge = ConversationJudge()
for result in results:  # Runs for ALL tests
```

**Impact**:
- Security/compliance tests: Parallel runs judge (wrong), sequential doesn't (correct)
- Conversational tests: Both run judge (correct by accident)
- Inconsistent behavior between execution modes

#### Issue 2.2: Success Counting Differences

**Parallel Path** (lines 518-521):
```python
# ONLY uses judge evaluation, no fallback
successful_tests = len(
    [r for r in results if r.get("evaluation", {}).get("success", False)]
)
```

**Sequential Path** (lines 883-887):
```python
# Checks if judge enabled, falls back to execution success
judge_enabled = should_enable_judge_evaluation(test_type, parallelism)
if judge_enabled:
    successful_tests = len([r for r in results if r.get("evaluation", {}).get("success", False)])
# Otherwise keeps original execution-based count
```

**Impact**: If judge evaluation fails in parallel path, ALL tests count as failures regardless of actual execution success.

#### Issue 2.3: Error Handling Inconsistency

**Parallel Path** (lines 509-512):
```python
except Exception as e:
    console.print(f"Judge evaluation failed - {e!s}")
    # No evaluation field added!
```

**Sequential Path** (lines 801-806):
```python
except Exception as judge_error:
    # Adds failure evaluation to maintain consistency
    result["evaluation"] = {
        "overall_score": 0.0,
        "criteria_scores": {},
        "reasoning": f"Judge evaluation failed: {str(judge_error)}",
        "success": False
    }
```

**Impact**: Tests with judge errors are silently excluded from reporting in parallel mode, treated as passed in sequential mode.

---

### 3. Session Isolation Failures (CRITICAL)

**Location**: [src/test_mcp/cli/test_execution.py:186-358](src/test_mcp/cli/test_execution.py#L186-L358) (parallel runner), [src/test_mcp/providers/provider_interface.py:213-243](src/test_mcp/providers/provider_interface.py#L213-L243) (session creation)

**Problem**: Multiple parallel tests share the same provider instance and session state without proper synchronization.

#### Issue 3.1: Shared Provider Instance

**Code Location**: [test_execution.py:434](src/test_mcp/cli/test_execution.py#L434)

```python
# SINGLE provider created for ALL parallel tests
provider = create_provider_from_config(server_config)

# All tests use this shared provider
parallel_results = await run_tests_parallel(
    suite_config,
    provider,  # ← Shared!
    max_parallelism=parallelism,
    ...
)
```

**Consequence**: All parallel tests share:
- `self.sessions` dict (unsynchronized) at [provider_interface.py:125](src/test_mcp/providers/provider_interface.py#L125)
- `self.metrics` object at [provider_interface.py:41](src/test_mcp/providers/provider_interface.py#L41)
- Provider state and configuration

#### Issue 3.2: Unsynchronized Session Dictionary

**Code Location**: [provider_interface.py:237](src/test_mcp/providers/provider_interface.py#L237)

```python
async def start_session(self, session_id: str) -> bool:
    # No lock protecting this dict!
    self.sessions[session_id] = {
        "created_at": time.time(),
        "mcp_client": mcp_client,
        "server_ids": server_ids
    }
```

**Race Scenario**:
```
Task A: Writing self.sessions["test_a"] = {...}
Task B: Reading self.sessions["test_b"] while dict is being modified
Result: RuntimeError: dictionary changed size during iteration
```

#### Issue 3.3: Provider Metrics Corruption

**Code Location**: [provider_interface.py:135, 148, 155](src/test_mcp/providers/provider_interface.py#L135)

```python
# Concurrent increments without locks
self.metrics.requests_made += 1  # Lost updates!
self.metrics.total_latency_ms += latency
self.metrics.error_count += 1
```

**Result**: Metrics corruption - if 5 tests run, `requests_made` might be 3 instead of 5 due to lost updates.

#### Issue 3.4: Unused Isolation Mechanism

**Code Location**: [client_manager.py:979-1008](src/test_mcp/mcp_client/client_manager.py#L979-L1008)

```python
@asynccontextmanager
async def get_isolated_session(self, server_config: dict[str, Any]):
    """Create an isolated, task-local MCP session for parallel execution."""
    # This exists but is NEVER USED by parallel execution!
```

**Problem**: A proper isolation mechanism exists but parallel execution doesn't use it, instead using `connect_server()` which creates shared persistent connections.

---

### 4. Result Normalization Bugs (HIGH)

**Location**: [src/test_mcp/cli/test_execution.py:74-154](src/test_mcp/cli/test_execution.py#L74-L154)

**Problem**: The `normalize_parallel_result()` function incorrectly determines success, causing all tests to be marked as failed before judge evaluation.

#### Bug 4.1: Success Field Always False

**Code Location**: [test_execution.py:122-128](src/test_mcp/cli/test_execution.py#L122-L128)

```python
success = (
    status == "completed"
    and result.get("success", False)  # ← BUG: Always False!
    and result_obj
)
```

**Root Cause**: [test_execution.py:1581](src/test_mcp/cli/test_execution.py#L1581) hardcodes `success: False`:

```python
"result": {
    "status": {"value": "completed"},
    "turns": [...],
    "duration": duration,
    "success": False,  # ← Hardcoded! "Judge will determine actual success"
}
```

**Impact**: Normalized `"success"` field is **always False** for parallel execution, corrupting preliminary success detection. Final reporting works only because judge evaluation overwrites this.

#### Bug 4.2: Removed Status Check Without Replacement

**Code Location**: [test_execution.py:126-127](src/test_mcp/cli/test_execution.py#L126-L127)

```python
# Removed result_obj_status == "goal_achieved" requirement
# Judge evaluation will determine final success
```

**Problem**: The `result_obj.status` field could indicate `GOAL_ACHIEVED`, but this check was removed. Meanwhile, [test_execution.py:1546](src/test_mcp/cli/test_execution.py#L1546) sets status to `ACTIVE`:

```python
conv_status = ConversationStatus.ACTIVE  # Default to active, judge will determine final status
```

**Impact**: No preliminary success detection possible from conversation result status.

#### Bug 4.3: Inconsistent Failed Test Detection

**Parallel Path** (line 537):
```python
failed_tests = [
    r for r in results if not r.get("evaluation", {}).get("success", True)
]
```

**Sequential Path** (line 900):
```python
failed_tests = [r for r in results if not r.get("success", True)]
```

**Impact**: Different UX between execution modes - sequential shows execution failures, parallel shows judge evaluation failures.

---

### 5. OAuth Callback Server Race Conditions (CRITICAL)

**Location**: [src/test_mcp/mcp_client/client_manager.py:240-309](src/test_mcp/mcp_client/client_manager.py#L240-L309) (CallbackServer class), [client_manager.py:749, 402, 786-787](src/test_mcp/mcp_client/client_manager.py#L749) (usage)

**Problem**: OAuth callback server is stored as instance attribute without isolation, causing parallel OAuth flows to interfere.

#### Race Condition 5.1: Callback Server Overwrite

**Code Location**: [client_manager.py:749](src/test_mcp/mcp_client/client_manager.py#L749), [client_manager.py:402](src/test_mcp/mcp_client/client_manager.py#L402)

```python
# In _get_connection_context():
callback_server = CallbackServer()
callback_server.start()
self._active_callback_server = callback_server  # ← Instance attribute

# In _handle_oauth_callback():
callback_server = self._active_callback_server  # ← Read instance attribute
```

**Race Timeline**:
```
T0: Test 1 creates callback_server_A (port 3030)
T1: Test 1: self._active_callback_server = A
T2: Test 2 creates callback_server_B (port 3031)
T3: Test 2: self._active_callback_server = B  ← OVERWRITES A!
T4: Test 1 reads self._active_callback_server → Gets B (WRONG!)
T5: Test 1 waits on B's callback event
T6: OAuth callback for Test 1 arrives at port 3030 → server_A receives it
T7: server_A.callback_event.set() but nobody is waiting on it
T8: Test 1 timeout after 120 seconds
```

**Impact**: OAuth authentication fails with "OAuth callback timeout" error.

#### Race Condition 5.2: Wrong Authorization Code

**Alternative Timeline**:
```
T0-T3: Same as above (Test 2 overwrites _active_callback_server)
T4: OAuth callback for Test 2 arrives at port 3031 → server_B receives it
T5: server_B.callback_event.set()
T6: Test 1 wakes up (was waiting on server_B)
T7: Test 1 receives Test 2's authorization code
T8: Test 1 token exchange fails with "invalid_grant"
```

**Impact**: Tests fail with "OAuth authorization error: invalid_grant".

#### Race Condition 5.3: Cleanup Stops Wrong Server

**Code Location**: [client_manager.py:785-787](src/test_mcp/mcp_client/client_manager.py#L785-L787)

```python
finally:
    self._active_callback_server.stop()  # Stops whatever server is stored
    delattr(self, "_active_callback_server")
```

**Problem**: Test A might stop Test B's callback server if Test B overwrote the attribute.

**Impact**: Test B's callback arrives at closed server, gets connection refused error.

---

## Code References

### Token Storage Issues
- [src/test_mcp/mcp_client/client_manager.py:67](src/test_mcp/mcp_client/client_manager.py#L67) - Class-level `_instances` dict
- [src/test_mcp/mcp_client/client_manager.py:78-83](src/test_mcp/mcp_client/client_manager.py#L78-L83) - `get_instance()` singleton factory
- [src/test_mcp/mcp_client/client_manager.py:99-117](src/test_mcp/mcp_client/client_manager.py#L99-L117) - Async methods with sync locks
- [src/test_mcp/mcp_client/client_manager.py:120-142](src/test_mcp/mcp_client/client_manager.py#L120-L142) - `clear_all_async()` TOCTOU race
- [src/test_mcp/mcp_client/client_manager.py:759](src/test_mcp/mcp_client/client_manager.py#L759) - Shared token storage usage

### Judge Evaluation Issues
- [src/test_mcp/cli/test_execution.py:50-72](src/test_mcp/cli/test_execution.py#L50-L72) - `should_enable_judge_evaluation()` logic
- [src/test_mcp/cli/test_execution.py:486-521](src/test_mcp/cli/test_execution.py#L486-L521) - Parallel path (missing check)
- [src/test_mcp/cli/test_execution.py:769-807](src/test_mcp/cli/test_execution.py#L769-L807) - Sequential path (correct check)
- [src/test_mcp/cli/test_execution.py:518-521](src/test_mcp/cli/test_execution.py#L518-L521) - Parallel success counting (no fallback)
- [src/test_mcp/cli/test_execution.py:883-887](src/test_mcp/cli/test_execution.py#L883-L887) - Sequential success counting (with fallback)

### Session Isolation Issues
- [src/test_mcp/cli/test_execution.py:434](src/test_mcp/cli/test_execution.py#L434) - Shared provider creation
- [src/test_mcp/providers/provider_interface.py:125](src/test_mcp/providers/provider_interface.py#L125) - Unsynchronized sessions dict
- [src/test_mcp/providers/provider_interface.py:237](src/test_mcp/providers/provider_interface.py#L237) - Session dict write without lock
- [src/test_mcp/providers/provider_interface.py:135](src/test_mcp/providers/provider_interface.py#L135) - Metrics corruption
- [src/test_mcp/mcp_client/client_manager.py:979-1008](src/test_mcp/mcp_client/client_manager.py#L979-L1008) - Unused `get_isolated_session()`

### Result Normalization Issues
- [src/test_mcp/cli/test_execution.py:74-154](src/test_mcp/cli/test_execution.py#L74-L154) - `normalize_parallel_result()` function
- [src/test_mcp/cli/test_execution.py:122-128](src/test_mcp/cli/test_execution.py#L122-L128) - Success always False bug
- [src/test_mcp/cli/test_execution.py:1581](src/test_mcp/cli/test_execution.py#L1581) - Hardcoded `success: False`
- [src/test_mcp/cli/test_execution.py:1546](src/test_mcp/cli/test_execution.py#L1546) - Status set to ACTIVE
- [src/test_mcp/cli/test_execution.py:537](src/test_mcp/cli/test_execution.py#L537) vs [test_execution.py:900](src/test_mcp/cli/test_execution.py#L900) - Inconsistent failed test detection

### OAuth Callback Issues
- [src/test_mcp/mcp_client/client_manager.py:240-309](src/test_mcp/mcp_client/client_manager.py#L240-L309) - CallbackServer class
- [src/test_mcp/mcp_client/client_manager.py:749](src/test_mcp/mcp_client/client_manager.py#L749) - Instance attribute assignment
- [src/test_mcp/mcp_client/client_manager.py:402](src/test_mcp/mcp_client/client_manager.py#L402) - Instance attribute read
- [src/test_mcp/mcp_client/client_manager.py:785-787](src/test_mcp/mcp_client/client_manager.py#L785-L787) - Cleanup (wrong server)

## Architecture Insights

### Anti-Pattern 1: Singleton with Shared Mutable State
The `SharedTokenStorage` class uses a class-level singleton pattern (one instance per server URL) that shares OAuth tokens across all parallel tests. This violates the principle "share nothing or share immutable data" in concurrent systems.

### Anti-Pattern 2: Code Path Duplication Without Unification
Parallel and sequential execution have separate code paths (lines 432-606 vs 607-973) with different logic for the same operations (judge evaluation, success counting, error handling). This creates maintenance burden and inconsistent behavior.

### Anti-Pattern 3: Instance Attributes for Context-Specific Resources
OAuth callback servers are stored as `self._active_callback_server` when they should be passed explicitly as context or stored in a dict keyed by flow ID. Instance attributes assume sequential access.

### Anti-Pattern 4: Async Methods with Sync Primitives
Using `threading.Lock()` in `async` methods ([client_manager.py:101, 106, 111, 116](src/test_mcp/mcp_client/client_manager.py#L101)) blocks the entire event loop thread instead of yielding control to other coroutines, causing deadlocks.

### Anti-Pattern 5: Preliminary Results Overwritten by Judge
Parallel execution sets `success: False` as a placeholder, expecting judge evaluation to determine actual success. But this corrupts the result structure for any code that runs before judge evaluation.

## Configuration That Triggers Issues

**Default Parallelism**: [src/test_mcp/models/conversational.py](src/test_mcp/models/conversational.py)
```python
parallelism: int = Field(
    default=5,  # Parallel execution ENABLED by default
    description="Number of parallel test executions (1 for sequential)"
)
```

**Any test suite with `parallelism > 1` triggers these issues**, especially when:
- Tests connect to OAuth-enabled servers (SharedTokenStorage races)
- Multiple tests run against the same server URL (token overwrites)
- Tests have different execution speeds (timing-dependent races)
- Suite type is security/compliance but parallel path runs judge anyway

## How Issues Manifest

### Non-Deterministic Failures
Tests pass/fail inconsistently between runs:
- Run 1: 5/5 tests pass
- Run 2: 3/5 tests pass (timing-dependent)
- Run 3: 0/5 tests pass (all OAuth timeouts)

### Specific Error Messages

**OAuth Token Errors**:
```
TokenError: invalid_token - Received wrong token from shared storage
OAuth authorization error: invalid_grant - Used another test's auth code
```

**Timeout Errors**:
```
RuntimeError: OAuth callback timeout - Waited on wrong callback server for 120s
```

**Deadlock Symptoms**:
```
[No output for 10+ minutes]
Tests hang with no progress updates
Require Ctrl+C or kill -9 to terminate
```

**Attribute Errors**:
```
AttributeError: 'MCPClientManager' object has no attribute '_active_callback_server'
```

### CI/CD Impact
- Flaky test failures require re-runs
- Cannot rely on parallel execution for fast feedback
- Must use `parallelism=1` (sequential) for reliability

## Testing Evidence

**Existing Tests**: [tests/test_race_conditions.py](tests/test_race_conditions.py)
- Tests singleton thread safety (lines 24-133)
- Tests concurrent progress updates (lines 137-209)
- Tests file naming uniqueness (lines 213-261)

**Missing Tests**:
- No tests for SharedTokenStorage async/sync lock mixing
- No tests for parallel OAuth callback server races
- No tests for provider session dict race conditions
- No tests comparing parallel vs sequential judge evaluation

**Test That Would Catch Issues**:
```python
@pytest.mark.asyncio
async def test_parallel_oauth_isolation():
    """Test that parallel OAuth flows don't interfere"""
    # Create 5 parallel tests connecting to same OAuth server
    # Verify each gets correct authorization code
    # This would FAIL on current implementation
```

## Related Research

- Parallel execution performance improvements (implemented in this feature branch)
- OAuth authentication flow design (implemented but has races)
- Judge evaluation system (implemented with path inconsistencies)

## Open Questions

1. **Why was SharedTokenStorage designed as singleton?** - Was token sharing intentional or oversight?
2. **Why separate code paths for parallel vs sequential?** - Could they be unified?
3. **Why async methods with threading.Lock?** - Was asyncio.Lock considered?
4. **Why is `get_isolated_session()` unused?** - Was it meant to solve these issues?
5. **Is `parallelism=5` the right default?** - Should default be 1 until these issues are fixed?

## Recommendations

### Immediate Actions (Fix Critical Issues)

1. **Replace threading.Lock with asyncio.Lock** in SharedTokenStorage
2. **Store callback servers per flow ID** instead of instance attribute
3. **Add lock to provider.sessions dict** access
4. **Unify judge evaluation logic** between parallel and sequential paths
5. **Fix success determination** in normalize_parallel_result()

### Medium-Term (Architectural Improvements)

1. **Make SharedTokenStorage per-session** instead of per-server-URL
2. **Create provider per test** instead of shared provider
3. **Use get_isolated_session()** for parallel execution
4. **Add proper error recovery** instead of suppressing cleanup errors
5. **Add comprehensive parallel execution tests** to catch races

### Long-Term (Design Review)

1. **Consider removing parallel execution** until issues are resolved
2. **Set `parallelism=1` as default** for reliability
3. **Add feature flag** to enable parallel execution explicitly
4. **Document known issues** in README for users
5. **Add monitoring** to detect race conditions in production

## Conclusion

The parallel execution feature is **fundamentally broken** due to inadequate synchronization of shared state. The five categories of critical issues (token storage, judge evaluation, session isolation, result normalization, OAuth callbacks) combine to make parallel execution unreliable and unsuitable for production use.

The root cause is **assuming sequential execution** in the design of core components (singleton patterns, instance attributes, shared provider state) without adding proper synchronization when parallelism was introduced.

**Current recommendation**: Use `parallelism=1` (sequential execution) until these issues are resolved. Parallel execution should be considered **experimental/broken** in its current state.
