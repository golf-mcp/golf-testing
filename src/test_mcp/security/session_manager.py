import asyncio
import uuid
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from pydantic import BaseModel

from ..mcp_client.client_manager import MCPClientManager


@dataclass
class SessionCapture:
    """Captured MCP session establishment sequence"""

    session_id: str
    server_id: str
    server_config: dict[str, Any]
    establishment_timestamp: datetime
    capabilities: list[dict[str, Any]]
    tools: list[dict[str, Any]]
    resources: list[dict[str, Any]]
    connection_metadata: dict[str, Any]


class ReplayResult(BaseModel):
    """Result of session replay attack testing"""

    test_id: str
    attack_type: str
    original_session_id: str
    replayed_session_id: str
    success: bool
    vulnerability_detected: bool
    evidence: list[str]
    timestamp: datetime


class SessionLifecycleManager:
    """Capture and replay MCP session establishment sequences for security testing"""

    def __init__(self):
        self.captured_sessions: dict[str, SessionCapture] = {}

    async def capture_session_establishment(
        self, server_config: dict[str, Any]
    ) -> SessionCapture:
        """Record actual MCP session establishment sequence"""
        client_manager = MCPClientManager()

        # Generate unique session identifier for tracking
        session_id = str(uuid.uuid4())
        establishment_timestamp = datetime.now()

        try:
            # Establish connection and capture the process
            server_id = await client_manager.connect_server(server_config)
            connection = client_manager.connections.get(server_id)

            if not connection:
                raise RuntimeError(
                    "Failed to establish MCP connection for session capture"
                )

            # Extract connection details and capabilities
            tools = connection.tools if connection.tools else []
            resources = connection.resources if connection.resources else []

            # Combine all capabilities for comprehensive capture
            capabilities = tools + resources
            if hasattr(connection, "prompts") and connection.prompts:
                capabilities.extend(connection.prompts)

            # Capture connection metadata
            connection_metadata = {
                "server_id": server_id,
                "session_healthy": connection._is_healthy,
                "has_session": connection.session is not None,
                "tools_count": len(tools),
                "resources_count": len(resources),
                "server_url": server_config.get("url", "unknown"),
                "transport": server_config.get("transport", "http"),
                "oauth_enabled": server_config.get("oauth", False),
            }

            # Create session capture record
            session_capture = SessionCapture(
                session_id=session_id,
                server_id=server_id,
                server_config=server_config.copy(),
                establishment_timestamp=establishment_timestamp,
                capabilities=capabilities,
                tools=tools,
                resources=resources,
                connection_metadata=connection_metadata,
            )

            # Store for later replay attacks
            self.captured_sessions[session_id] = session_capture

            # Clean up the test connection
            await client_manager.disconnect_server(server_id)

            return session_capture

        except Exception as e:
            raise RuntimeError(f"Failed to capture session establishment: {e}") from e

    async def replay_session_attack(self, capture: SessionCapture) -> ReplayResult:
        """Test session ID reuse and replay attacks using captured session"""
        test_id = str(uuid.uuid4())
        evidence = []
        vulnerability_detected = False

        try:
            # Test 1: Attempt to reuse the original session ID
            replayed_session_id = capture.session_id

            # Create new connection with same configuration
            client_manager = MCPClientManager()
            new_server_id = await client_manager.connect_server(capture.server_config)
            new_connection = client_manager.connections.get(new_server_id)

            if new_connection:
                # Check if new connection can access old session data
                # This tests session isolation between different connection instances

                # Test session ID collision/reuse
                if new_connection.server_id == capture.server_id:
                    vulnerability_detected = True
                    evidence.append(
                        "Server reused same server ID across different connections"
                    )

                # Test capability discovery consistency
                new_tools = new_connection.tools if new_connection.tools else []
                if len(new_tools) != len(capture.tools):
                    evidence.append(
                        f"Tool count mismatch: original {len(capture.tools)}, new {len(new_tools)}"
                    )

                # Test session state isolation
                try:
                    # Attempt to use captured session context in new connection
                    if new_connection.session:
                        # Try to list tools to verify session independence
                        await new_connection.session.list_tools()
                        evidence.append(
                            "New connection established independent session successfully"
                        )
                    else:
                        evidence.append("New connection failed to establish session")
                except Exception as e:
                    evidence.append(f"Session isolation test error: {str(e)[:100]}")

                # Clean up test connection
                await client_manager.disconnect_server(new_server_id)

            else:
                evidence.append("Failed to establish new connection for replay test")

            return ReplayResult(
                test_id=test_id,
                attack_type="session_id_replay",
                original_session_id=capture.session_id,
                replayed_session_id=replayed_session_id,
                success=not vulnerability_detected,
                vulnerability_detected=vulnerability_detected,
                evidence=evidence,
                timestamp=datetime.now(),
            )

        except Exception as e:
            evidence.append(f"Session replay attack failed: {e!s}")
            return ReplayResult(
                test_id=test_id,
                attack_type="session_id_replay",
                original_session_id=capture.session_id,
                replayed_session_id="",
                success=False,
                vulnerability_detected=False,
                evidence=evidence,
                timestamp=datetime.now(),
            )

    async def test_session_contamination(self, capture: SessionCapture) -> ReplayResult:
        """Test cross-client session contamination attacks"""
        test_id = str(uuid.uuid4())
        evidence = []
        vulnerability_detected = False

        try:
            # Create two simultaneous connections to test session isolation
            client_manager_1 = MCPClientManager()
            client_manager_2 = MCPClientManager()

            # Establish first connection
            server_id_1 = await client_manager_1.connect_server(capture.server_config)
            connection_1 = client_manager_1.connections.get(server_id_1)

            # Establish second connection
            server_id_2 = await client_manager_2.connect_server(capture.server_config)
            connection_2 = client_manager_2.connections.get(server_id_2)

            if connection_1 and connection_2:
                # Test for session state leakage between connections

                # Check if connections share the same underlying session
                if (
                    hasattr(connection_1, "session")
                    and hasattr(connection_2, "session")
                    and connection_1.session is connection_2.session
                ):
                    vulnerability_detected = True
                    evidence.append(
                        "Connections share the same session object (critical vulnerability)"
                    )

                # Test server ID uniqueness
                if server_id_1 == server_id_2:
                    vulnerability_detected = True
                    evidence.append("Same server ID assigned to different connections")

                # Test connection independence by performing operations
                try:
                    if connection_1.session and connection_2.session:
                        # Perform operation on first connection
                        tools_1 = await connection_1.session.list_tools()

                        # Check if second connection sees any state changes
                        tools_2 = await connection_2.session.list_tools()

                        # Both should get consistent results independently
                        if hasattr(tools_1, "tools") and hasattr(tools_2, "tools"):
                            if len(tools_1.tools) != len(tools_2.tools):
                                evidence.append(
                                    "Tool discovery inconsistent between sessions"
                                )
                            else:
                                evidence.append(
                                    "Connections maintain independent session state"
                                )

                except Exception as e:
                    evidence.append(
                        f"Cross-session contamination test error: {str(e)[:100]}"
                    )

                # Clean up connections
                await client_manager_1.disconnect_server(server_id_1)
                await client_manager_2.disconnect_server(server_id_2)

            else:
                evidence.append(
                    "Failed to establish dual connections for contamination test"
                )

            return ReplayResult(
                test_id=test_id,
                attack_type="session_contamination",
                original_session_id=capture.session_id,
                replayed_session_id=f"{server_id_1}+{server_id_2}",
                success=not vulnerability_detected,
                vulnerability_detected=vulnerability_detected,
                evidence=evidence,
                timestamp=datetime.now(),
            )

        except Exception as e:
            evidence.append(f"Session contamination test failed: {e!s}")
            return ReplayResult(
                test_id=test_id,
                attack_type="session_contamination",
                original_session_id=capture.session_id,
                replayed_session_id="",
                success=False,
                vulnerability_detected=False,
                evidence=evidence,
                timestamp=datetime.now(),
            )

    async def test_concurrent_session_limits(
        self, capture: SessionCapture, max_connections: int = 10
    ) -> ReplayResult:
        """Test server behavior under concurrent session pressure"""
        test_id = str(uuid.uuid4())
        evidence = []
        vulnerability_detected = False
        active_connections = []

        try:
            # Attempt to create multiple concurrent connections
            for i in range(max_connections):
                try:
                    client_manager = MCPClientManager()
                    server_id = await client_manager.connect_server(
                        capture.server_config
                    )
                    active_connections.append((client_manager, server_id))
                    evidence.append(f"Connection {i + 1} established successfully")

                    # Small delay to avoid overwhelming the server
                    await asyncio.sleep(0.1)

                except Exception as e:
                    evidence.append(f"Connection {i + 1} failed: {str(e)[:50]}")
                    break

            # Check if server handled concurrent connections properly
            successful_connections = len(active_connections)

            if successful_connections == max_connections:
                # All connections successful - check for resource exhaustion
                evidence.append(
                    f"Server accepted all {max_connections} concurrent connections"
                )

                # This could indicate lack of connection limits (potential DoS vulnerability)
                if max_connections >= 5:
                    vulnerability_detected = True
                    evidence.append(
                        "Server may be vulnerable to connection exhaustion DoS"
                    )

            elif successful_connections == 0:
                evidence.append("Server rejected all connection attempts")

            else:
                evidence.append(
                    f"Server accepted {successful_connections}/{max_connections} connections"
                )

            # Test session independence across concurrent connections
            if len(active_connections) >= 2:
                try:
                    # Test first two connections for independence
                    conn_1_session = active_connections[0][1]
                    conn_2_session = active_connections[1][1]

                    if conn_1_session == conn_2_session:
                        vulnerability_detected = True
                        evidence.append("Concurrent connections share session IDs")

                except Exception as e:
                    evidence.append(
                        f"Concurrent session independence test failed: {str(e)[:50]}"
                    )

            return ReplayResult(
                test_id=test_id,
                attack_type="concurrent_session_limits",
                original_session_id=capture.session_id,
                replayed_session_id=f"concurrent_{successful_connections}",
                success=not vulnerability_detected,
                vulnerability_detected=vulnerability_detected,
                evidence=evidence,
                timestamp=datetime.now(),
            )

        except Exception as e:
            evidence.append(f"Concurrent session test failed: {e!s}")
            vulnerability_detected = False

        finally:
            # Clean up all active connections
            for client_manager, server_id in active_connections:
                try:
                    await client_manager.disconnect_server(server_id)
                except Exception:
                    pass  # Ignore cleanup errors

            return ReplayResult(
                test_id=test_id,
                attack_type="concurrent_session_limits",
                original_session_id=capture.session_id,
                replayed_session_id="",
                success=not vulnerability_detected,
                vulnerability_detected=vulnerability_detected,
                evidence=evidence,
                timestamp=datetime.now(),
            )

    def get_captured_session(self, session_id: str) -> SessionCapture | None:
        """Retrieve a captured session by ID"""
        return self.captured_sessions.get(session_id)

    def list_captured_sessions(self) -> list[SessionCapture]:
        """Get all captured sessions"""
        return list(self.captured_sessions.values())

    def clear_captured_sessions(self) -> None:
        """Clear all captured session data"""
        self.captured_sessions.clear()
