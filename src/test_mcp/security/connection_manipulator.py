import asyncio
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, Field

from ..mcp_client.client_manager import MCPClientManager
from ..shared.result_models import TestStatus, TestType
from .session_manager import SessionCapture


class SecurityResult(BaseModel):
    """Security test result for connection manipulation tests"""

    test_id: str
    test_name: str
    test_type: TestType = Field(default=TestType.SECURITY)
    attack_type: str
    vulnerability_detected: bool
    success: bool
    severity: str = Field(default="medium")  # low, medium, high, critical
    evidence: list[str] = Field(default_factory=list)
    start_time: datetime
    end_time: datetime
    duration: float
    status: TestStatus
    error_message: str | None = None


class ConnectionManipulator:
    """Manipulate MCP connection states for security testing"""

    def __init__(self):
        self.active_connections: dict[str, MCPClientManager] = {}

    async def test_connection_hijacking(
        self, server_id: str, server_config: dict[str, Any]
    ) -> SecurityResult:
        """Test if connection state can be hijacked between sessions"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False

        try:
            # Create first connection (victim)
            victim_manager = MCPClientManager()
            victim_server_id = await victim_manager.connect_server(server_config)
            victim_connection = victim_manager.connections.get(victim_server_id)

            if not victim_connection:
                raise Exception("Failed to establish victim connection")

            evidence.append(f"Victim connection established: {victim_server_id}")

            # Create second connection (attacker)
            attacker_manager = MCPClientManager()
            attacker_server_id = await attacker_manager.connect_server(server_config)
            attacker_connection = attacker_manager.connections.get(attacker_server_id)

            if not attacker_connection:
                raise Exception("Failed to establish attacker connection")

            evidence.append(f"Attacker connection established: {attacker_server_id}")

            # Test 1: Check if connections share the same underlying session
            if (
                victim_connection.session
                and attacker_connection.session
                and victim_connection.session is attacker_connection.session
            ):
                vulnerability_detected = True
                evidence.append("CRITICAL: Connections share the same session object")

            # Test 2: Check if server IDs can be confused/hijacked
            if victim_server_id == attacker_server_id:
                vulnerability_detected = True
                evidence.append(
                    "CRITICAL: Same server ID assigned to different connections"
                )

            # Test 3: Attempt state manipulation through connection pool
            # Try to access victim's connection through attacker's client manager
            try:
                # This should fail - attacker shouldn't access victim's connection
                hijacked_connection = attacker_manager.connections.get(victim_server_id)
                if hijacked_connection:
                    vulnerability_detected = True
                    evidence.append("Connection pool allows cross-client access")
                else:
                    evidence.append("Connection pool properly isolated")
            except Exception:
                evidence.append("Connection pool access control working")

            # Test 4: Session state isolation test
            if victim_connection.session and attacker_connection.session:
                try:
                    # Perform operations on both connections simultaneously
                    victim_tools = await victim_connection.session.list_tools()
                    attacker_tools = await attacker_connection.session.list_tools()

                    # Both should succeed independently
                    victim_tool_count = (
                        len(victim_tools.tools) if hasattr(victim_tools, "tools") else 0
                    )
                    attacker_tool_count = (
                        len(attacker_tools.tools)
                        if hasattr(attacker_tools, "tools")
                        else 0
                    )

                    evidence.append(f"Victim discovered {victim_tool_count} tools")
                    evidence.append(f"Attacker discovered {attacker_tool_count} tools")

                    # Tools should be the same count (same server) but accessed independently
                    if victim_tool_count != attacker_tool_count:
                        evidence.append(
                            "WARNING: Tool discovery inconsistent between connections"
                        )

                except Exception as e:
                    evidence.append(f"Session isolation test failed: {str(e)[:100]}")
            # Test 5: Connection metadata isolation
            if (
                hasattr(victim_connection, "_context_stack")
                and hasattr(attacker_connection, "_context_stack")
                and victim_connection._context_stack
                is attacker_connection._context_stack
            ):
                vulnerability_detected = True
                evidence.append("CRITICAL: Connections share context stack")

            # Clean up connections
            await victim_manager.disconnect_server(victim_server_id)
            await attacker_manager.disconnect_server(attacker_server_id)

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="Connection Hijacking Test",
                attack_type="connection_hijacking",
                vulnerability_detected=vulnerability_detected,
                success=not vulnerability_detected,
                severity="critical" if vulnerability_detected else "low",
                evidence=evidence,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                status=TestStatus.COMPLETED,
            )

        except Exception as e:
            end_time = datetime.now()
            return SecurityResult(
                test_id=test_id,
                test_name="Connection Hijacking Test",
                attack_type="connection_hijacking",
                vulnerability_detected=False,
                success=False,
                severity="medium",
                evidence=[*evidence, f"Test failed: {e!s}"],
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                status=TestStatus.FAILED,
                error_message=str(e),
            )

    async def test_session_fixation(
        self, session_capture: SessionCapture
    ) -> SecurityResult:
        """Test session fixation using real session establishment patterns"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False

        try:
            # Test if we can force a specific session ID or manipulate session creation
            original_config = session_capture.server_config

            # Test 1: Attempt to reuse the captured session ID
            evidence.append(
                f"Testing fixation with session ID: {session_capture.session_id}"
            )

            # Create connection with modified configuration that might influence session ID
            modified_config = original_config.copy()

            # Test various session fixation attack vectors
            fixation_attempts = [
                # Attempt to influence session through headers or config
                {"test_session_id": session_capture.session_id},
                {"X-Session-ID": session_capture.session_id},
                {"preferred_session": session_capture.session_id},
                # Test with custom client metadata that might influence session
                {"client_name": f"FixedClient_{session_capture.session_id[:8]}"},
            ]

            for i, fixation_data in enumerate(fixation_attempts):
                try:
                    # Merge fixation attempt into config
                    test_config = {**modified_config, **fixation_data}

                    client_manager = MCPClientManager()
                    server_id = await client_manager.connect_server(test_config)
                    connection = client_manager.connections.get(server_id)

                    if connection:
                        # Check if the server ID or any session identifier matches our fixation attempt
                        if server_id == session_capture.session_id:
                            vulnerability_detected = True
                            evidence.append(
                                f"Session fixation successful with attempt {i + 1}: {server_id}"
                            )

                        # Check for any correlation with our fixation attempt
                        if any(
                            str(value) in server_id for value in fixation_data.values()
                        ):
                            vulnerability_detected = True
                            evidence.append(
                                f"Session influenced by fixation attempt {i + 1}"
                            )

                        # Proper behavior: server should generate independent session IDs
                        evidence.append(
                            f"Fixation attempt {i + 1} generated session: {server_id[:12]}..."
                        )

                        # Clean up
                        await client_manager.disconnect_server(server_id)
                    else:
                        evidence.append(
                            f"Fixation attempt {i + 1} failed to establish connection"
                        )

                except Exception as e:
                    evidence.append(f"Fixation attempt {i + 1} failed: {str(e)[:50]}")

            # Test 2: Rapid connection attempts to test for session ID predictability
            recent_session_ids = []
            for _attempt in range(3):
                try:
                    client_manager = MCPClientManager()
                    server_id = await client_manager.connect_server(original_config)
                    recent_session_ids.append(server_id)
                    await client_manager.disconnect_server(server_id)

                    # Small delay between attempts
                    await asyncio.sleep(0.1)

                except Exception:
                    pass

            # Check for session ID predictability patterns
            if len(set(recent_session_ids)) < len(recent_session_ids):
                vulnerability_detected = True
                evidence.append("Session ID reuse detected in rapid connections")

            # Check for sequential or predictable patterns
            if len(recent_session_ids) >= 2:
                # Simple check for incremental session IDs
                session_similarity = sum(
                    1
                    for i in range(len(recent_session_ids) - 1)
                    if recent_session_ids[i][:8] == recent_session_ids[i + 1][:8]
                )
                if session_similarity > 0:
                    evidence.append(
                        f"Session ID patterns detected: {session_similarity} similarities"
                    )
                else:
                    evidence.append("Session IDs appear properly randomized")

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="Session Fixation Test",
                attack_type="session_fixation",
                vulnerability_detected=vulnerability_detected,
                success=not vulnerability_detected,
                severity="high" if vulnerability_detected else "low",
                evidence=evidence,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                status=TestStatus.COMPLETED,
            )

        except Exception as e:
            end_time = datetime.now()
            return SecurityResult(
                test_id=test_id,
                test_name="Session Fixation Test",
                attack_type="session_fixation",
                vulnerability_detected=False,
                success=False,
                severity="medium",
                evidence=[*evidence, f"Test failed: {e!s}"],
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                status=TestStatus.FAILED,
                error_message=str(e),
            )

    async def test_connection_state_persistence(
        self, server_config: dict[str, Any]
    ) -> SecurityResult:
        """Test connection state persistence and cleanup"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False

        try:
            # Create and destroy connections to test state cleanup
            client_manager = MCPClientManager()

            # Establish connection
            server_id = await client_manager.connect_server(server_config)
            connection = client_manager.connections.get(server_id)

            if not connection:
                raise Exception("Failed to establish connection")

            # Record initial state
            initial_tools = len(connection.tools) if connection.tools else 0
            evidence.append(
                f"Initial connection established with {initial_tools} tools"
            )

            # Perform some operations to establish state
            if connection.session:
                try:
                    await connection.session.list_tools()
                    evidence.append("Performed operation: list_tools")
                except Exception as e:
                    evidence.append(f"Operation failed: {str(e)[:50]}")

            # Disconnect and check cleanup
            await client_manager.disconnect_server(server_id)
            evidence.append("Connection disconnected")

            # Verify connection is cleaned up
            remaining_connection = client_manager.connections.get(server_id)
            if remaining_connection:
                vulnerability_detected = True
                evidence.append(
                    "CRITICAL: Connection not properly cleaned up after disconnect"
                )
            else:
                evidence.append("Connection properly cleaned up")

            # Test reconnection with same configuration
            new_server_id = await client_manager.connect_server(server_config)
            new_connection = client_manager.connections.get(new_server_id)

            if new_connection:
                # Check if new connection has any state from previous connection
                if new_server_id == server_id:
                    vulnerability_detected = True
                    evidence.append("CRITICAL: Same server ID reused after disconnect")

                new_tools = len(new_connection.tools) if new_connection.tools else 0
                if new_tools == initial_tools:
                    evidence.append("Tool count consistent across reconnection")
                else:
                    evidence.append(
                        f"Tool count changed: {initial_tools} -> {new_tools}"
                    )

                # Clean up
                await client_manager.disconnect_server(new_server_id)

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="Connection State Persistence Test",
                attack_type="state_persistence",
                vulnerability_detected=vulnerability_detected,
                success=not vulnerability_detected,
                severity="medium" if vulnerability_detected else "low",
                evidence=evidence,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                status=TestStatus.COMPLETED,
            )

        except Exception as e:
            end_time = datetime.now()
            return SecurityResult(
                test_id=test_id,
                test_name="Connection State Persistence Test",
                attack_type="state_persistence",
                vulnerability_detected=False,
                success=False,
                severity="medium",
                evidence=[*evidence, f"Test failed: {e!s}"],
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                status=TestStatus.FAILED,
                error_message=str(e),
            )

    async def test_connection_pool_exhaustion(
        self, server_config: dict[str, Any], max_connections: int = 20
    ) -> SecurityResult:
        """Test connection pool limits and exhaustion vulnerabilities"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False
        active_managers = []

        try:
            # Attempt to create many connections to test pool limits
            for i in range(max_connections):
                try:
                    client_manager = MCPClientManager()
                    server_id = await client_manager.connect_server(server_config)
                    active_managers.append((client_manager, server_id))

                    # Small delay to avoid overwhelming
                    await asyncio.sleep(0.05)

                except Exception as e:
                    evidence.append(f"Connection {i + 1} failed: {str(e)[:50]}")
                    break

            successful_connections = len(active_managers)
            evidence.append(
                f"Successfully created {successful_connections}/{max_connections} connections"
            )

            # Check for resource exhaustion vulnerability
            if successful_connections >= max_connections * 0.8:  # 80% success rate
                if max_connections >= 10:
                    vulnerability_detected = True
                    evidence.append(
                        "Server may be vulnerable to connection exhaustion DoS"
                    )
                else:
                    evidence.append("Server accepted reasonable number of connections")

            # Test connection quality under load
            if len(active_managers) >= 3:
                # Test first few connections for responsiveness
                responsive_connections = 0
                for i, (manager, server_id) in enumerate(active_managers[:3]):
                    try:
                        connection = manager.connections.get(server_id)
                        if connection and connection.session:
                            # Quick operation test
                            await asyncio.wait_for(
                                connection.session.list_tools(), timeout=5.0
                            )
                            responsive_connections += 1

                    except TimeoutError:
                        evidence.append(
                            f"Connection {i + 1} became unresponsive under load"
                        )
                    except Exception:
                        evidence.append(f"Connection {i + 1} failed under load")

                if responsive_connections < 2:
                    vulnerability_detected = True
                    evidence.append(
                        "Connections become unresponsive under moderate load"
                    )
                else:
                    evidence.append(
                        f"{responsive_connections}/3 connections remained responsive"
                    )

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="Connection Pool Exhaustion Test",
                attack_type="pool_exhaustion",
                vulnerability_detected=vulnerability_detected,
                success=not vulnerability_detected,
                severity="high" if vulnerability_detected else "low",
                evidence=evidence,
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                status=TestStatus.COMPLETED,
            )

        except Exception as e:
            end_time = datetime.now()
            return SecurityResult(
                test_id=test_id,
                test_name="Connection Pool Exhaustion Test",
                attack_type="pool_exhaustion",
                vulnerability_detected=False,
                success=False,
                severity="medium",
                evidence=[*evidence, f"Test failed: {e!s}"],
                start_time=start_time,
                end_time=end_time,
                duration=(end_time - start_time).total_seconds(),
                status=TestStatus.FAILED,
                error_message=str(e),
            )

        finally:
            # Clean up all active connections
            for manager, server_id in active_managers:
                try:
                    await manager.disconnect_server(server_id)
                except Exception:
                    pass  # Ignore cleanup errors

    async def cleanup_connections(self) -> None:
        """Clean up any remaining active connections"""
        for client_manager in self.active_connections.values():
            try:
                await client_manager.disconnect_all()
            except Exception:
                pass  # Ignore cleanup errors
        self.active_connections.clear()
