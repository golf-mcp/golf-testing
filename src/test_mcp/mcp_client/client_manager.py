import asyncio
import json
import os
import signal
import socket
import sys
import threading
import traceback
import uuid
import webbrowser
from collections.abc import AsyncGenerator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Any
from urllib.parse import parse_qs, urljoin, urlparse

import httpx
from rich.console import Console
from rich.panel import Panel

try:
    from mcp import ClientSession
    from mcp.client.auth import OAuthClientProvider, TokenStorage
    from mcp.client.stdio import StdioServerParameters, stdio_client
    from mcp.client.streamable_http import streamablehttp_client
    from mcp.shared.auth import (
        OAuthClientInformationFull,
        OAuthClientMetadata,
        OAuthToken,
    )
    from mcp.types import Implementation
    from pydantic import AnyUrl
except ImportError:
    raise ImportError(
        "MCP SDK with OAuth support required. Install with: pip install mcp"
    ) from None


class InMemoryTokenStorage(TokenStorage):
    """In-memory token storage implementation for OAuth."""

    def __init__(self):
        self.tokens: OAuthToken | None = None
        self.client_info: OAuthClientInformationFull | None = None

    async def get_tokens(self) -> OAuthToken | None:
        """Get stored tokens."""
        return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Store tokens."""
        self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        """Get stored client information."""
        return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store client information."""
        self.client_info = client_info


class SharedTokenStorage(TokenStorage):
    """Shared token storage that persists across multiple MCP client instances."""

    _instances: dict[str, "SharedTokenStorage"] = {}
    _lock = asyncio.Lock()  # Class-level lock for async safety

    def __init__(self, server_url: str):
        self.server_url = server_url
        self.tokens: OAuthToken | None = None
        self.client_info: OAuthClientInformationFull | None = None
        self._instance_lock = asyncio.Lock()  # Use asyncio.Lock for async methods
        self._cleanup_event = asyncio.Event()  # Use asyncio.Event

    @classmethod
    async def get_instance(cls, server_url: str, session_id: str = None) -> "SharedTokenStorage":
        """Get or create token storage, optionally scoped to session

        Args:
            server_url: Server URL for token storage
            session_id: Optional session ID to isolate parallel tests

        Returns:
            SharedTokenStorage instance
        """
        # Create per-session key to isolate parallel tests
        storage_key = f"{server_url}_{session_id}" if session_id else server_url

        async with cls._lock:
            if storage_key not in cls._instances:
                cls._instances[storage_key] = cls(storage_key)
            return cls._instances[storage_key]

    @classmethod
    def clear_all(cls) -> None:
        """Clear all shared token storage instances and their data."""
        with cls._lock:
            # First, clear token data from all existing instances
            for instance in cls._instances.values():
                with instance._instance_lock:
                    instance.tokens = None
                    instance.client_info = None
                    instance._cleanup_event.set()  # Signal cleanup completed

            # Then clear the instance registry
            cls._instances.clear()

    async def get_tokens(self) -> OAuthToken | None:
        """Get stored tokens."""
        async with self._instance_lock:
            return self.tokens

    async def set_tokens(self, tokens: OAuthToken) -> None:
        """Store tokens."""
        async with self._instance_lock:
            self.tokens = tokens

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        """Get stored client information."""
        async with self._instance_lock:
            return self.client_info

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        """Store client information."""
        async with self._instance_lock:
            self.client_info = client_info

    @classmethod
    async def clear_all_async(cls) -> None:
        """Async cleanup with proper synchronization"""
        async with cls._lock:
            # Copy AND clear inside lock (atomic) - fixes TOCTOU race
            instances_to_clear = list(cls._instances.values())
            cls._instances.clear()

        # Clear instances outside lock (no TOCTOU issue)
        await asyncio.gather(
            *[instance._clear_data() for instance in instances_to_clear],
            return_exceptions=True  # Don't fail if one fails
        )

    async def _clear_data(self):
        """Instance-level cleanup"""
        async with self._instance_lock:
            self.tokens = None
            self.client_info = None
            self._cleanup_event.set()

    async def get_valid_token(self) -> OAuthToken | None:
        """Get valid token with cleanup synchronization."""
        async with self._instance_lock:
            if self._cleanup_event.is_set():
                return None  # Instance was cleaned up
            return self.tokens

    async def save_token(self, token: OAuthToken) -> None:
        """Save token with cleanup synchronization."""
        async with self._instance_lock:
            if not self._cleanup_event.is_set():
                self.tokens = token

    async def has_valid_tokens(self) -> bool:
        """Check if we have valid tokens stored."""
        async with self._instance_lock:
            return self.tokens is not None


class CallbackHandler(BaseHTTPRequestHandler):
    """HTTP request handler for OAuth callback."""

    def do_GET(self):
        """Handle GET requests to the callback endpoint."""
        parsed_path = urlparse(self.path)

        if parsed_path.path == "/callback":
            # Parse callback parameters
            query_params = parse_qs(parsed_path.query)
            callback_data = {}

            # Extract OAuth parameters
            if "code" in query_params:
                callback_data["code"] = query_params["code"][0]
            if "state" in query_params:
                callback_data["state"] = query_params["state"][0]
            if "error" in query_params:
                callback_data["error"] = query_params["error"][0]
            if "error_description" in query_params:
                callback_data["error_description"] = query_params["error_description"][
                    0
                ]

            # Set callback data via server reference (event-based)
            if hasattr(self.server, "callback_server_ref"):
                self.server.callback_server_ref.set_callback_data(callback_data)
            else:
                # Fallback to old method for compatibility
                self.server.callback_data = callback_data

            # Send success response
            self.send_response(200)
            self.send_header("Content-type", "text/html")
            self.end_headers()

            success_message = """<html><body>
                <h2>Authorization successful</h2>
                <p>You can close this window and return to the MCP Testing Framework.</p>
            </body></html>"""
            self.wfile.write(success_message.encode())
        else:
            # 404 for other paths
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        """Suppress default HTTP server logs."""
        pass


def find_free_port(start_port: int = 3030, max_attempts: int = 100) -> int:
    """Find an available port starting from start_port.

    Args:
        start_port: Port to start searching from
        max_attempts: Maximum number of ports to try

    Returns:
        Available port number

    Raises:
        RuntimeError: If no free ports found
    """
    for port in range(start_port, start_port + max_attempts):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.bind(("localhost", port))
                return port
        except OSError:
            continue  # Port in use, try next one

    raise RuntimeError(
        f"No free ports found in range {start_port}-{start_port + max_attempts}"
    )


class CallbackServer:
    """Local HTTP server to handle OAuth callbacks."""

    def __init__(self, port: int = None):
        self.port = port or find_free_port()
        self.server = None
        self.thread = None
        self.callback_data = None
        # Improved synchronization
        self.callback_event = threading.Event()
        self.callback_lock = threading.Lock()
        self.server_ready = threading.Event()  # ← Track server readiness
        self.shutdown_requested = threading.Event()

    def start(self):
        """Start the callback server with proper synchronization."""
        try:
            self.server = HTTPServer(("localhost", self.port), CallbackHandler)
            self.server.callback_data = None
            self.server.callback_server_ref = self

            def server_thread():
                self.server_ready.set()  # Signal server is ready
                self.server.serve_forever()

            self.thread = threading.Thread(target=server_thread, daemon=True)
            self.thread.start()

            # Wait for server to be ready before returning
            if not self.server_ready.wait(timeout=5.0):
                raise RuntimeError("Callback server failed to start within 5 seconds")

        except OSError as e:
            if "Address already in use" in str(e):
                self.port = find_free_port(self.port + 1)
                self.start()  # Retry with new port
            else:
                raise

    def stop(self):
        """Stop the callback server gracefully."""
        if self.server:
            self.shutdown_requested.set()
            self.server.shutdown()
            self.server.server_close()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)

    def wait_for_callback(self, timeout: float = 120.0) -> dict[str, Any] | None:
        """Wait for OAuth callback with improved timeout handling."""
        # Ensure server is ready before waiting
        if not self.server_ready.is_set():
            raise RuntimeError("Callback server not ready")

        # Wait for callback event with timeout
        if self.callback_event.wait(timeout):
            with self.callback_lock:
                return self.callback_data.copy() if self.callback_data else None
        return None  # Timeout

    def set_callback_data(self, data: dict[str, Any]) -> None:
        """Set callback data and signal waiting threads."""
        with self.callback_lock:
            self.callback_data = data
        self.callback_event.set()

    def get_callback_url(self) -> str:
        """Get the callback URL for this server instance."""
        return f"http://localhost:{self.port}/callback"


@dataclass
class MCPServerConnection:
    """Represents a connection to an MCP server"""

    server_id: str
    session: ClientSession | None
    tools: list[dict[str, Any]]
    resources: list[dict[str, Any]]
    prompts: list[dict[str, Any]]
    server_config: dict[str, Any]
    # Store the context manager for proper cleanup
    _context_stack: Any = None
    _is_healthy: bool = True


class MCPClientManager:
    """
    Centralized MCP client manager that handles all server connections.
    This is independent of any LLM provider and can be used by any agent.
    Uses proper async context managers to avoid task group issues.
    """

    def __init__(self):
        self.connections: dict[str, MCPServerConnection] = {}
        self._active_contexts: dict[str, Any] = {}
        self._connection_locks: dict[str, asyncio.Lock] = {}
        self._stdio_processes: dict[str, Any] = {}  # Track stdio subprocesses
        self._current_oauth_url: str | None = None  # Store current OAuth URL
        self._master_lock = asyncio.Lock()  # Master lock for safe lock creation
        self._active_callback_servers: dict[str, CallbackServer] = {}  # Flow ID → server
        self._callback_lock = asyncio.Lock()  # Protect dict access

    def _parse_command(self, command_str: str) -> tuple[str, list[str]]:
        """
        Parse command string into command and args.

        Args:
            command_str: Command string (e.g., "npx -y @modelcontextprotocol/server-time")

        Returns:
            Tuple of (command, args)
        """
        parts = command_str.split()
        if not parts:
            raise ValueError("Command string cannot be empty")
        return parts[0], parts[1:]

    async def _handle_oauth_redirect(self, auth_url: str) -> None:
        """Handle OAuth redirect with enhanced URL presentation."""

        console = Console()

        # Thread-safe storage of auth URL
        with threading.Lock():
            self._current_oauth_url = auth_url
            self._oauth_redirect_completed = threading.Event()
            self._oauth_redirect_completed.set()  # Signal URL is stored

        # Create authorization panel
        auth_panel = Panel(
            f"""[bold green]🌐 Browser Authorization Required[/bold green]

Please visit this URL to authorize the MCP Testing Framework:

[cyan][link={auth_url}]{auth_url}[/link][/cyan]

[dim]• A new browser window should open automatically[/dim]
[dim]• Complete the authorization process[/dim]
[dim]• Return here to continue[/dim]""",
            title="🔐 OAuth Authorization",
            border_style="green",
            padding=(1, 2),
        )

        console.print()
        console.print(auth_panel)
        console.print()

        # Try to open browser automatically
        try:
            webbrowser.open(auth_url)
            console.print(
                "[dim]🔗 Opening authorization URL in your default browser...[/dim]"
            )
        except Exception:
            console.print(
                "[yellow]⚠️  Could not open browser automatically. Please copy the URL above.[/yellow]"
            )

        console.print()

    async def _handle_oauth_callback(self, flow_id: str | None = None) -> tuple[str, str | None]:
        """Handle OAuth callback using flow-specific callback server.

        Args:
            flow_id: Optional flow ID to identify which callback server to use

        Returns:
            Tuple of (authorization_code, state)
        """
        console = Console()

        # Get flow-specific callback server
        if flow_id:
            async with self._callback_lock:
                callback_server = self._active_callback_servers.get(flow_id)

            if not callback_server:
                raise RuntimeError(f"No callback server found for flow {flow_id}")
        else:
            # Fallback to instance attribute for backward compatibility
            callback_server = getattr(self, '_active_callback_server', None)
            if not callback_server:
                raise RuntimeError("No callback server available")

        console.print(
            f"\n📍 Waiting for OAuth callback on: [cyan]{callback_server.get_callback_url()}[/cyan]"
        )

        # Wait for callback with timeout
        callback_data = callback_server.wait_for_callback(timeout=120.0)

        if not callback_data:
            console.print(
                "[red]❌ OAuth callback timeout. Authorization may have failed.[/red]"
            )
            raise RuntimeError("OAuth callback timeout")

        if callback_data.get("error"):
            error_msg = callback_data.get(
                "error_description", callback_data.get("error")
            )
            console.print(f"[red]❌ OAuth authorization failed: {error_msg}[/red]")
            raise RuntimeError(f"OAuth authorization error: {error_msg}")

        if not callback_data.get("code"):
            console.print("[red]❌ No authorization code received in callback[/red]")
            raise RuntimeError("No authorization code in OAuth callback")

        console.print("[green]✅ OAuth authorization successful[/green]")
        return callback_data["code"], callback_data.get("state")

    async def _discover_oauth_metadata(self, server_url: str) -> dict[str, Any]:
        """
        Discover OAuth configuration from server's .well-known endpoints.

        Args:
            server_url: Base URL of the server (e.g., http://localhost:3000)

        Returns:
            Combined metadata from authorization server and resource server
        """
        # Extract base URL (remove /mcp path if present)
        if server_url.endswith("/mcp"):
            base_url = server_url[:-4]  # Remove "/mcp"
        else:
            base_url = server_url.rstrip("/")

        async with httpx.AsyncClient() as client:
            try:
                # Fetch OAuth authorization server metadata
                auth_server_url = urljoin(
                    base_url + "/", ".well-known/oauth-authorization-server"
                )
                auth_response = await client.get(auth_server_url)
                auth_response.raise_for_status()
                auth_metadata = auth_response.json()

                # Fetch OAuth resource server metadata (optional)
                resource_url = urljoin(
                    base_url + "/", ".well-known/oauth-protected-resource"
                )
                try:
                    resource_response = await client.get(resource_url)
                    resource_response.raise_for_status()
                    resource_metadata = resource_response.json()
                except httpx.HTTPError:
                    # Resource server metadata is optional - many OAuth providers don't provide it
                    resource_metadata = {}

                # Combine both metadata sets
                return {
                    **auth_metadata,
                    "resource_metadata": resource_metadata,
                    "scopes_supported": resource_metadata.get(
                        "scopes_supported", auth_metadata.get("scopes_supported", [])
                    ),
                }

            except httpx.HTTPError as e:
                print(f"   ❌ Failed to discover OAuth metadata: {e}")
                raise RuntimeError(
                    f"Cannot discover OAuth metadata from {base_url}: {e}"
                ) from e

    def _build_client_metadata(
        self, oauth_metadata: dict = None, callback_port: int = None
    ) -> OAuthClientMetadata:
        """Build OAuth client metadata using hardcoded testing defaults"""

        # Use provided port or find available one
        port = callback_port or find_free_port()
        redirect_uri = f"http://localhost:{port}/callback"
        client_name = "MCP Testing Framework"
        grant_types = ["authorization_code", "refresh_token"]
        response_types = ["code"]

        # Auto-discover scope or use default
        if oauth_metadata:
            scopes_supported = oauth_metadata.get("scopes_supported", [])
            scope = " ".join(scopes_supported) if scopes_supported else "user"
        else:
            scope = "user"

        return OAuthClientMetadata(
            client_name=client_name,
            redirect_uris=[AnyUrl(redirect_uri)],
            grant_types=grant_types,
            response_types=response_types,
            scope=scope,
        )

    def _extract_oauth_error_details(self, exception: Exception) -> dict[str, str]:
        """Extract specific OAuth error information from exceptions.

        Args:
            exception: Exception caught during OAuth flow

        Returns:
            Dictionary with error, description, and suggested_action fields
        """
        error_info = {
            "error": "unknown_error",
            "description": str(exception),
            "suggested_action": "Try using token-based authentication instead",
        }

        # Check for HTTP response with OAuth error
        if hasattr(exception, "response") and exception.response:
            try:
                if hasattr(exception.response, "json"):
                    error_data = exception.response.json()
                elif hasattr(exception.response, "text"):
                    error_data = json.loads(exception.response.text)
                else:
                    error_data = {}

                if error_data.get("error"):
                    error_info.update(
                        {
                            "error": error_data.get("error", "oauth_error"),
                            "description": error_data.get(
                                "error_description", str(exception)
                            ),
                            "suggested_action": self._get_oauth_error_action(
                                error_data.get("error")
                            ),
                        }
                    )
                    return error_info
            except (json.JSONDecodeError, AttributeError):
                pass

        # Pattern matching for common OAuth errors
        error_msg = str(exception).lower()

        if "invalid_client" in error_msg:
            error_info.update(
                {
                    "error": "invalid_client",
                    "description": "Client authentication failed",
                    "suggested_action": "Verify server OAuth client configuration and metadata discovery",
                }
            )
        elif "invalid_grant" in error_msg or "authorization code" in error_msg:
            error_info.update(
                {
                    "error": "invalid_grant",
                    "description": "Authorization code invalid, expired, or already used",
                    "suggested_action": "Retry OAuth flow - code may have expired",
                }
            )
        elif "invalid_request" in error_msg:
            error_info.update(
                {
                    "error": "invalid_request",
                    "description": "OAuth request parameters are invalid",
                    "suggested_action": "Check OAuth client metadata and server endpoint configuration",
                }
            )
        elif "access_denied" in error_msg:
            error_info.update(
                {
                    "error": "access_denied",
                    "description": "User denied authorization request",
                    "suggested_action": "Complete authorization flow in browser or use different credentials",
                }
            )
        elif "metadata" in error_msg or "well-known" in error_msg:
            error_info.update(
                {
                    "error": "metadata_discovery_failed",
                    "description": "OAuth server metadata discovery failed",
                    "suggested_action": "Verify server supports OAuth and .well-known endpoints are accessible",
                }
            )
        elif "callback" in error_msg or "timeout" in error_msg:
            error_info.update(
                {
                    "error": "callback_timeout",
                    "description": "OAuth callback timeout or failure",
                    "suggested_action": "Complete authorization in browser within 2 minutes",
                }
            )

        return error_info

    def _get_oauth_error_action(self, error_code: str) -> str:
        """Get suggested action for specific OAuth error codes."""
        actions = {
            "invalid_client": "Check client_id and client_secret configuration",
            "invalid_grant": "Retry OAuth flow - authorization code may have expired",
            "invalid_request": "Verify OAuth request parameters and scopes",
            "unauthorized_client": "Check client is registered for authorization_code grant",
            "unsupported_grant_type": "Server may not support authorization code flow",
            "invalid_scope": "Request scopes that are supported by the server",
            "access_denied": "User denied access - retry with different account",
            "server_error": "Check server logs - OAuth server may be experiencing issues",
            "temporarily_unavailable": "Retry OAuth flow after a brief delay",
        }
        return actions.get(
            error_code, "Review OAuth server configuration and try token-based auth"
        )

    @asynccontextmanager
    async def _get_stdio_connection_context(
        self, server_config: dict[str, Any]
    ) -> AsyncGenerator[ClientSession, None]:
        """
        Create async context manager for stdio MCP connections.
        Spawns a subprocess and communicates via stdin/stdout.
        Ensures proper process cleanup including child processes.

        Note: For best results with npm-based servers, consider using the node
        command directly instead of 'npm run start'. This avoids issues with
        child process cleanup when npm spawns node as a subprocess.
        Example: "node dist/index.js" instead of "npm run start"
        """
        command_str = server_config.get("command")
        if not command_str:
            raise ValueError("command is required for stdio transport")

        # Parse command string
        command, args = self._parse_command(command_str)

        # Get optional env and cwd from config
        env = server_config.get("env")
        cwd = server_config.get("cwd")

        # Create stdio server parameters with process group for proper cleanup
        server_params = StdioServerParameters(
            command=command,
            args=args,
            env=env,
            cwd=cwd,
        )

        stdio_context = None
        process_handle = None

        try:
            # Connect via stdio
            stdio_context = stdio_client(server_params)
            read_stream, write_stream = await stdio_context.__aenter__()

            # Try to access the subprocess for cleanup (if available)
            # The stdio_client from MCP SDK should have a process attribute
            if hasattr(stdio_context, "_process"):
                process_handle = stdio_context._process

            client_info = Implementation(name="mcp-testing-framework", version="1.0.0")
            async with ClientSession(
                read_stream, write_stream, client_info=client_info
            ) as session:
                await asyncio.wait_for(session.initialize(), timeout=30.0)
                yield session

        except Exception as e:
            raise RuntimeError(
                f"Failed to connect via stdio with command '{command_str}': {e}"
            ) from e
        finally:
            # Ensure subprocess cleanup
            if stdio_context:
                try:
                    await stdio_context.__aexit__(None, None, None)
                except Exception:
                    pass

            # Additional cleanup: terminate any lingering processes
            # This helps with npm/node scenarios where child processes may persist
            if process_handle and hasattr(process_handle, "pid"):
                try:
                    # Try to terminate the process group (helps with npm -> node)
                    try:
                        os.killpg(os.getpgid(process_handle.pid), signal.SIGTERM)
                        # Give process a moment to terminate gracefully
                        await asyncio.sleep(0.1)
                        # Force kill if still running
                        try:
                            os.killpg(os.getpgid(process_handle.pid), signal.SIGKILL)
                        except (ProcessLookupError, PermissionError):
                            # Process already terminated, which is what we want
                            pass
                    except (ProcessLookupError, PermissionError, AttributeError):
                        # Process already terminated or no permission
                        pass
                except Exception:
                    # Ignore cleanup errors
                    pass

    @asynccontextmanager
    async def _get_connection_context(
        self, server_config: dict[str, Any]
    ) -> AsyncGenerator[ClientSession, None]:
        """
        Create a proper async context manager for MCP connections following the example pattern.
        This ensures transport and session contexts are properly nested.
        Supports both HTTP and stdio transports.
        """
        # Determine transport type
        transport = server_config.get("transport", "http")

        # Route to appropriate transport
        if transport == "stdio":
            async with self._get_stdio_connection_context(server_config) as session:
                yield session
            return

        # HTTP transport (existing code)
        url = server_config.get("url")
        if not url:
            raise ValueError("URL required for HTTP server")

        # Check for OAuth authentication
        use_oauth = server_config.get("oauth", False)

        if use_oauth:
            # Discover OAuth metadata from server
            try:
                oauth_metadata = await self._discover_oauth_metadata(url)
            except Exception:
                oauth_metadata = None

            # Generate unique flow ID for this OAuth attempt
            flow_id = str(uuid.uuid4())

            # Pre-allocate callback server to ensure consistent port
            callback_server = CallbackServer()
            callback_server.start()

            # Store with flow-specific key
            async with self._callback_lock:
                self._active_callback_servers[flow_id] = callback_server

            try:
                # Use callback server's actual port in metadata
                client_metadata = self._build_client_metadata(
                    oauth_metadata,
                    callback_port=callback_server.port,  # ← Use same port
                )

                # Create shared token storage and OAuth provider
                token_storage = await SharedTokenStorage.get_instance(url, session_id=None)

                oauth_auth = OAuthClientProvider(
                    server_url=url,
                    client_metadata=client_metadata,
                    storage=token_storage,
                    redirect_handler=self._handle_oauth_redirect,
                    callback_handler=lambda: self._handle_oauth_callback(flow_id),
                )

                # Use OAuth authentication
                async with streamablehttp_client(url, auth=oauth_auth) as (
                    read_stream,
                    write_stream,
                    _,
                ):
                    client_info = Implementation(
                        name="mcp-testing-framework", version="1.0.0"
                    )
                    try:
                        async with ClientSession(
                            read_stream, write_stream, client_info=client_info
                        ) as session:
                            await asyncio.wait_for(session.initialize(), timeout=30.0)
                            yield session
                    finally:
                        # Clean up flow-specific callback server
                        async with self._callback_lock:
                            if flow_id in self._active_callback_servers:
                                self._active_callback_servers[flow_id].stop()
                                del self._active_callback_servers[flow_id]
                return
            except Exception as e:
                console = Console()

                # Extract specific OAuth error details
                oauth_error = self._extract_oauth_error_details(e)

                # Create detailed error panel based on extracted information
                if oauth_error["error"] != "unknown_error":
                    # Specific OAuth error
                    error_panel = Panel(
                        f"""[red]❌ OAuth Error: {oauth_error["error"].replace("_", " ").title()}[/red]

[yellow]Description:[/yellow]
{oauth_error["description"]}

[yellow]Suggested Solution:[/yellow]
{oauth_error["suggested_action"]}

[dim]Technical Details:[/dim]
• Error Code: {oauth_error["error"]}
• Exception Type: {type(e).__name__}""",
                        title="🔧 OAuth Authentication Failed",
                        border_style="red",
                    )
                else:
                    # Handle TaskGroup/ExceptionGroup specially with enhanced context
                    error_details = str(e)
                    exception_type = type(e).__name__

                    if hasattr(e, "__notes__") and e.__notes__:
                        error_details += (
                            f"\nAdditional details: {'; '.join(e.__notes__)}"
                        )

                    nested_errors = []
                    if hasattr(e, "exceptions"):
                        for nested_e in e.exceptions:
                            # Try to extract OAuth errors from nested exceptions
                            nested_oauth_error = self._extract_oauth_error_details(
                                nested_e
                            )
                            if nested_oauth_error["error"] != "unknown_error":
                                nested_errors.append(
                                    f"OAuth {nested_oauth_error['error']}: {nested_oauth_error['description']}"
                                )
                            else:
                                nested_errors.append(
                                    f"{type(nested_e).__name__}: {nested_e!s}"
                                )

                    if nested_errors:
                        error_details += (
                            f"\nNested exceptions: {'; '.join(nested_errors)}"
                        )

                    if (
                        "TaskGroup" in error_details
                        or "ExceptionGroup" in exception_type
                    ):
                        error_panel = Panel(
                            f"""[red]❌ OAuth Token Exchange Failed[/red]

The OAuth authorization code was received but token exchange failed.

[yellow]Debug Information:[/yellow]
• Exception Type: {exception_type}
• Error Details: {error_details}

[yellow]Common Causes:[/yellow]
• Server OAuth token endpoint is not working correctly
• Client credentials or OAuth configuration is invalid  
• Network connectivity issues during token exchange
• Server-side token validation errors

[yellow]Troubleshooting Steps:[/yellow]
1. Check server OAuth endpoint accessibility
2. Verify client metadata and configuration
3. Review server logs for token validation errors
4. Try using Bearer token authentication as fallback""",
                            title="🔧 Token Exchange Error",
                            border_style="red",
                        )
                    else:
                        # Generic error with enhanced context
                        error_panel = Panel(
                            f"""[red]❌ OAuth Setup Failed[/red]

{oauth_error["description"]}

[yellow]Exception Type:[/yellow] {exception_type}

[yellow]Suggested Solution:[/yellow]
{oauth_error["suggested_action"]}

[yellow]Full Error Details:[/yellow]
{error_details}""",
                            title="🔧 Authentication Error",
                            border_style="red",
                        )

                console.print()
                console.print(error_panel)
                console.print()

                # Log full traceback for debugging (only in verbose mode if available)
                if hasattr(e, "__cause__") or hasattr(e, "__context__"):
                    traceback.print_exc()

                raise RuntimeError(
                    f"OAuth authentication failed: {oauth_error['error']} - {oauth_error['description']}"
                ) from e
            finally:
                # Clean up callback server on authentication failure
                async with self._callback_lock:
                    if flow_id in self._active_callback_servers:
                        self._active_callback_servers[flow_id].stop()
                        del self._active_callback_servers[flow_id]

        # Prepare headers with authentication for basic HTTP
        headers = {}
        if auth_token := server_config.get("authorization_token"):
            if not auth_token.startswith("Bearer "):
                auth_token = f"Bearer {auth_token}"
            headers["Authorization"] = auth_token

        # Follow the example pattern: nested async context managers
        try:
            async with streamablehttp_client(url, headers=headers) as (
                read_stream,
                write_stream,
                _,
            ):
                client_info = Implementation(
                    name="mcp-testing-framework", version="1.0.0"
                )
                async with ClientSession(
                    read_stream, write_stream, client_info=client_info
                ) as session:
                    await asyncio.wait_for(session.initialize(), timeout=30.0)
                    yield session
        except Exception as e:
            # Convert connection errors to more user-friendly messages
            if "SSL" in str(e) or "certificate" in str(e).lower():
                raise RuntimeError(
                    f"SSL/Certificate error connecting to '{url}': {e}"
                ) from e
            elif "Connection refused" in str(e) or "ConnectError" in str(e):
                raise RuntimeError(
                    f"Cannot connect to server '{url}': Connection refused. Please verify the server is running."
                ) from e
            else:
                raise RuntimeError(
                    f"Failed to connect to MCP server '{url}': {e}"
                ) from e

    async def _recover_connection(self, server_id: str) -> None:
        """
        Recover a failed connection by recreating the session context.

        Args:
            server_id: ID of the connection to recover
        """
        connection = self.connections.get(server_id)
        if not connection:
            raise RuntimeError(f"No connection found for server {server_id}")

        # Clean up old context if it exists
        if server_id in self._active_contexts:
            try:
                await self._active_contexts[server_id].__aexit__(None, None, None)
            except Exception:
                pass  # Ignore errors during cleanup

        # Create new connection context
        try:
            context_manager = self._get_connection_context(connection.server_config)
            session = await context_manager.__aenter__()

            # Update connection with new session and context
            connection.session = session
            connection._context_stack = context_manager
            connection._is_healthy = True
            self._active_contexts[server_id] = context_manager

        except Exception as e:
            # If recovery fails, mark as unhealthy
            connection._is_healthy = False
            raise RuntimeError(
                f"Connection recovery failed for server {server_id}: {e}"
            ) from e

    @asynccontextmanager
    async def get_isolated_session(self, server_config: dict[str, Any]):
        """
        Create an isolated, task-local MCP session for parallel execution.

        This context manager creates a fresh connection that is entered and exited
        within the same asyncio task, avoiding the "cancel scope in different task"
        error that occurs when sharing sessions across parallel tasks.

        Args:
            server_config: Server configuration dict with type, url, auth, etc.

        Yields:
            ClientSession: An isolated MCP client session

        Example:
            async with client_manager.get_isolated_session(config) as session:
                result = await session.call_tool("tool_name", {"arg": "value"})
        """
        # Create a new connection context that will be entered/exited in this task
        context_manager = self._get_connection_context(server_config)
        try:
            session = await context_manager.__aenter__()
            yield session
        finally:
            # Always clean up the context in the same task
            try:
                await context_manager.__aexit__(None, None, None)
            except Exception:
                pass  # Suppress cleanup errors

    async def connect_server(self, server_config: dict[str, Any]) -> str:
        """
        Connect to an MCP server and maintain persistent connection.

        Args:
            server_config: Server configuration dict with type, url, auth, etc.

        Returns:
            server_id: Unique identifier for this server connection
        """
        server_id = str(uuid.uuid4())
        # Use master lock to safely create per-server locks
        async with self._master_lock:
            if server_id not in self._connection_locks:
                self._connection_locks[server_id] = asyncio.Lock()

        try:
            # Create persistent connection context
            context_manager = self._get_connection_context(server_config)
            session = await context_manager.__aenter__()

            # Store the context for cleanup
            self._active_contexts[server_id] = context_manager

            # Discover capabilities during the initial connection
            tools = await self._discover_tools(session)
            resources = await self._discover_resources(session)
            prompts = await self._discover_prompts(session)

            # Store connection info with persistent session
            self.connections[server_id] = MCPServerConnection(
                server_id=server_id,
                session=session,  # Store persistent session
                tools=tools,
                resources=resources,
                prompts=prompts,
                server_config=server_config,
                _context_stack=context_manager,
                _is_healthy=True,
            )

            return server_id

        except Exception as e:
            # Cleanup on failure
            if server_id in self._connection_locks:
                del self._connection_locks[server_id]
            if server_id in self._active_contexts:
                try:
                    await self._active_contexts[server_id].__aexit__(None, None, None)
                except Exception:
                    pass
                del self._active_contexts[server_id]
            raise e

    async def _discover_tools(self, session: ClientSession) -> list[dict[str, Any]]:
        """Discover available tools from MCP server"""
        try:
            response = await session.list_tools()
            return (
                [tool.model_dump() for tool in response.tools]
                if hasattr(response, "tools")
                else []
            )
        except Exception:
            return []

    async def _discover_resources(self, session: ClientSession) -> list[dict[str, Any]]:
        """Discover available resources from MCP server"""
        try:
            response = await session.list_resources()
            return (
                [resource.model_dump() for resource in response.resources]
                if hasattr(response, "resources")
                else []
            )
        except Exception:
            return []

    async def _discover_prompts(self, session: ClientSession) -> list[dict[str, Any]]:
        """Discover available prompts from MCP server"""
        try:
            response = await session.list_prompts()
            return (
                [prompt.model_dump() for prompt in response.prompts]
                if hasattr(response, "prompts")
                else []
            )
        except Exception:
            return []

    def get_session(self, server_id: str) -> ClientSession | None:
        """Get the MCP session for a specific server.

        Args:
            server_id: Server identifier from connect_server()

        Returns:
            ClientSession instance if connected, None if not found or unhealthy
        """
        connection = self.connections.get(server_id)
        if not connection:
            return None

        # Return session only if connection is healthy
        if connection._is_healthy and connection.session:
            return connection.session

        return None

    async def execute_tool(
        self, server_id: str, tool_name: str, arguments: dict[str, Any]
    ) -> dict[str, Any]:
        """
        Execute a tool on an MCP server using persistent session.

        Args:
            server_id: ID of the server connection
            tool_name: Name of the tool to execute
            arguments: Tool arguments

        Returns:
            Tool execution result
        """
        connection = self.connections.get(server_id)
        if not connection:
            return {
                "success": False,
                "error": f"No connection found for server {server_id}",
            }

        # Use connection lock to prevent race conditions
        async with self._connection_locks[server_id]:
            # Check if connection needs recovery
            if not connection._is_healthy or not connection.session:
                try:
                    await self._recover_connection(server_id)
                    connection = self.connections[server_id]  # Get updated connection
                except Exception as e:
                    return {
                        "success": False,
                        "error": f"Connection recovery failed: {e!s}",
                    }

            try:
                # Use persistent session
                result = await connection.session.call_tool(tool_name, arguments)

                # Parse result content
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

            except Exception as e:
                # Mark connection as unhealthy for potential recovery
                connection._is_healthy = False
                return {"success": False, "error": str(e)}

    async def read_resource(self, server_id: str, resource_uri: str) -> dict[str, Any]:
        """
        Read a resource from an MCP server using persistent session.

        Args:
            server_id: ID of the server connection
            resource_uri: URI of the resource to read

        Returns:
            Resource content
        """
        connection = self.connections.get(server_id)
        if not connection:
            return {
                "success": False,
                "uri": resource_uri,
                "error": f"No connection found for server {server_id}",
            }

        # Use connection lock to prevent race conditions
        async with self._connection_locks[server_id]:
            # Check if connection needs recovery
            if not connection._is_healthy or not connection.session:
                try:
                    await self._recover_connection(server_id)
                    connection = self.connections[server_id]  # Get updated connection
                except Exception as e:
                    return {
                        "success": False,
                        "uri": resource_uri,
                        "error": f"Connection recovery failed: {e!s}",
                    }

            try:
                # Use persistent session
                result = await connection.session.read_resource(resource_uri)

                # Parse result content
                if hasattr(result, "contents"):
                    contents = []
                    for item in result.contents:
                        if hasattr(item, "text"):
                            contents.append({"type": "text", "text": item.text})
                        elif hasattr(item, "blob"):
                            contents.append({"type": "blob", "data": item.blob})

                    return {"success": True, "uri": resource_uri, "contents": contents}
                else:
                    return {
                        "success": True,
                        "uri": resource_uri,
                        "contents": [{"type": "text", "text": str(result)}],
                    }

            except Exception as e:
                # Mark connection as unhealthy for potential recovery
                connection._is_healthy = False
                return {"success": False, "uri": resource_uri, "error": str(e)}

    async def get_prompt(
        self,
        server_id: str,
        prompt_name: str,
        arguments: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Get a prompt from an MCP server using persistent session.

        Args:
            server_id: ID of the server connection
            prompt_name: Name of the prompt
            arguments: Optional arguments for the prompt

        Returns:
            Prompt content
        """
        connection = self.connections.get(server_id)
        if not connection:
            return {
                "success": False,
                "prompt_name": prompt_name,
                "error": f"No connection found for server {server_id}",
            }

        # Use connection lock to prevent race conditions
        async with self._connection_locks[server_id]:
            # Check if connection needs recovery
            if not connection._is_healthy or not connection.session:
                try:
                    await self._recover_connection(server_id)
                    connection = self.connections[server_id]  # Get updated connection
                except Exception as e:
                    return {
                        "success": False,
                        "prompt_name": prompt_name,
                        "error": f"Connection recovery failed: {e!s}",
                    }

            try:
                # Use persistent session
                result = await connection.session.get_prompt(
                    prompt_name, arguments or {}
                )

                # Parse result messages
                if hasattr(result, "messages"):
                    messages = []
                    for msg in result.messages:
                        message = {"role": msg.role}
                        if hasattr(msg, "content"):
                            if isinstance(msg.content, str):
                                message["content"] = msg.content
                            else:
                                # Handle structured content
                                message["content"] = str(msg.content)
                        messages.append(message)

                    return {
                        "success": True,
                        "prompt_name": prompt_name,
                        "messages": messages,
                    }
                else:
                    return {
                        "success": True,
                        "prompt_name": prompt_name,
                        "messages": [{"role": "user", "content": str(result)}],
                    }

            except Exception as e:
                # Mark connection as unhealthy for potential recovery
                connection._is_healthy = False
                return {"success": False, "prompt_name": prompt_name, "error": str(e)}

    async def get_tools_for_llm(self, server_ids: list[str]) -> list[dict[str, Any]]:
        """
        Get tool definitions formatted for LLM providers.

        Args:
            server_ids: List of server IDs to get tools from

        Returns:
            Combined list of tool definitions for LLM
        """
        tools = []
        for server_id in server_ids:
            connection = self.connections.get(server_id)
            if connection:
                # Add server_id to each tool for routing
                for tool in connection.tools:
                    tool_with_server = tool.copy()
                    tool_with_server["_mcp_server_id"] = server_id
                    tools.append(tool_with_server)
        return tools

    async def get_resources_for_llm(
        self, server_ids: list[str]
    ) -> list[dict[str, Any]]:
        """
        Get resource definitions formatted for LLM providers.

        Args:
            server_ids: List of server IDs to get resources from

        Returns:
            Combined list of resource definitions for LLM
        """
        resources = []
        for server_id in server_ids:
            connection = self.connections.get(server_id)
            if connection:
                # Add server_id to each resource for routing
                for resource in connection.resources:
                    resource_with_server = resource.copy()
                    resource_with_server["_mcp_server_id"] = server_id
                    resources.append(resource_with_server)
        return resources

    async def get_prompts_for_llm(self, server_ids: list[str]) -> list[dict[str, Any]]:
        """
        Get prompt definitions formatted for LLM providers.

        Args:
            server_ids: List of server IDs to get prompts from

        Returns:
            Combined list of prompt definitions for LLM
        """
        prompts = []
        for server_id in server_ids:
            connection = self.connections.get(server_id)
            if connection:
                # Add server_id to each prompt for routing
                for prompt in connection.prompts:
                    prompt_with_server = prompt.copy()
                    prompt_with_server["_mcp_server_id"] = server_id
                    prompts.append(prompt_with_server)
        return prompts

    async def disconnect_server(self, server_id: str):
        """
        Disconnect from an MCP server and clean up persistent connection.
        """
        if server_id in self.connections:
            # Clean up active context if it exists
            if server_id in self._active_contexts:
                try:
                    await self._active_contexts[server_id].__aexit__(None, None, None)
                except Exception as e:
                    print(
                        f"Warning: Error closing connection context for {server_id}: {e}",
                        file=sys.stderr,
                    )
                    print("Full traceback:", file=sys.stderr)
                    traceback.print_exc(file=sys.stderr)
                del self._active_contexts[server_id]

            # Clean up connection lock
            if server_id in self._connection_locks:
                del self._connection_locks[server_id]

            del self.connections[server_id]

    async def disconnect_all(self):
        """Disconnect from all MCP servers and clean up persistent connections"""
        # Clean up all active contexts
        for server_id, context_manager in list(self._active_contexts.items()):
            try:
                await context_manager.__aexit__(None, None, None)
            except Exception as e:
                print(
                    f"Warning: Error closing connection context for {server_id}: {e}",
                    file=sys.stderr,
                )
                print("Full traceback:", file=sys.stderr)
                traceback.print_exc(file=sys.stderr)

        # Clear all registries
        self._active_contexts.clear()
        self._connection_locks.clear()
        self.connections.clear()

    def force_disconnect_all(self):
        """Force disconnect from all MCP servers without awaiting cleanup"""
        # Clear all registries immediately without awaiting context cleanup
        # This is used when async cleanup isn't possible (e.g., in sync cleanup methods)
        self._active_contexts.clear()
        self._connection_locks.clear()
        self.connections.clear()
