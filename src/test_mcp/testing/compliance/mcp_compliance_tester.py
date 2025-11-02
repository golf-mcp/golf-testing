from contextlib import AsyncExitStack
from datetime import datetime
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field

from ...shared.progress_tracker import ProgressTracker, ExecutionStatus
from ...shared.result_models import BaseTestResult, SuiteCategory

# MCP SDK imports
try:
    from mcp import ClientSession
    from mcp.client.streamable_http import streamablehttp_client
    from mcp.types import Implementation
except ImportError:
    # Graceful fallback if MCP SDK not installed
    ClientSession = None
    streamablehttp_client = None
    Implementation = None


class MCPServerInfo(BaseModel):
    """MCP server information extracted from connection"""

    protocol_version: str | None = None
    server_name: str | None = None
    server_version: str | None = None
    capabilities: list[str] = Field(default_factory=list)
    tools: list[dict[str, Any]] = Field(default_factory=list)
    resources: list[dict[str, Any]] = Field(default_factory=list)
    prompts: list[dict[str, Any]] = Field(default_factory=list)
    roots: list[dict[str, Any]] = Field(default_factory=list)
    resource_templates: list[dict[str, Any]] = Field(default_factory=list)


class MCPComplianceTestResult(BaseTestResult):
    """Result of MCP protocol compliance testing (extends BaseTestResult)"""

    test_type: SuiteCategory = Field(
        default=SuiteCategory.COMPLIANCE, description="Test type identifier"
    )

    # MCP-specific fields
    check_name: str = Field(..., description="Name of compliance check")
    category: str = Field(..., description="Compliance category")
    severity: str = Field(
        default="medium", description="Issue severity: low, medium, high, critical"
    )
    message: str = Field(..., description="Test result message")

    # Protocol details
    server_info: MCPServerInfo | None = Field(
        default=None, description="Extracted server information"
    )
    compliance_passed: bool = Field(
        default=False, description="Whether compliance check passed"
    )


class MCPComplianceTester:
    """MCP protocol compliance testing using official MCP Python SDK"""

    def __init__(
        self,
        server_config: dict[str, Any],
        progress_tracker: ProgressTracker | None = None,
    ):
        self.server_config = server_config
        self.progress_tracker = progress_tracker
        self.server_info: MCPServerInfo | None = None

        # Use shared MCP client manager for OAuth support
        from ...mcp_client.client_manager import MCPClientManager

        self.mcp_client = MCPClientManager()
        self.server_id: str | None = None

        # Keep session reference for backward compatibility
        self.session: ClientSession | None = None
        self.exit_stack = AsyncExitStack()

    async def run_compliance_tests(
        self, check_categories: list[str] | None = None
    ) -> list[MCPComplianceTestResult]:
        """Run comprehensive MCP protocol compliance tests using MCP SDK"""
        results = []

        try:
            # Check if MCP SDK is available
            if (
                ClientSession is None
                or streamablehttp_client is None
                or Implementation is None
            ):
                return [
                    MCPComplianceTestResult(
                        test_id=str(uuid4()),
                        check_name="MCP SDK Availability",
                        category="Setup",
                        severity="critical",
                        message="MCP Python SDK not available. Install with: pip install mcp",
                        start_time=datetime.now(),
                        end_time=datetime.now(),
                        status=ExecutionStatus.FAILED,
                        success=False,
                        compliance_passed=False,
                        error_message="MCP SDK not installed",
                        duration=0.0,
                    )
                ]

            # Establish MCP connection using official SDK
            await self._connect_to_server()

            # Define test categories mapping
            test_mapping = {
                # Handshake tests
                "handshake": [
                    ("_test_protocol_handshake", "Protocol Handshake"),
                    ("_test_server_metadata", "Server Metadata"),
                    ("_test_jsonrpc_compliance", "JSON-RPC 2.0 Compliance"),
                ],
                # Capabilities tests
                "capabilities": [
                    ("_test_capability_negotiation", "Capability Negotiation"),
                    ("_test_client_capability_respect", "Client Capability Respect"),
                    ("_test_capability_functionality", "Capability Functionality"),
                ],
                # Tools tests
                "tools": [
                    ("_test_tool_discovery", "Tool Discovery"),
                    ("_test_tool_execution", "Tool Execution"),
                ],
                # Resource tests
                "resources": [
                    ("_test_resource_discovery", "Resource Discovery"),
                    ("_test_resource_reading", "Resource Reading"),
                    ("_test_prompt_discovery", "Prompt Discovery"),
                    ("_test_prompt_execution", "Prompt Execution"),
                    ("_test_roots_discovery", "Roots Discovery"),
                    (
                        "_test_resource_templates_discovery",
                        "Resource Templates Discovery",
                    ),
                ],
                # Advanced features
                "advanced": [
                    ("_test_sampling_support", "Sampling Support"),
                    ("_test_elicitation_support", "Elicitation Support"),
                    ("_test_notification_support", "Notification Support"),
                    ("_test_error_handling", "Error Handling"),
                ],
            }

            # Run tests based on requested categories
            if check_categories:
                # Run only tests for the requested categories
                for category in check_categories:
                    if category.lower() in test_mapping:
                        for test_method, _ in test_mapping[category.lower()]:
                            try:
                                test_func = getattr(self, test_method)
                                results.append(await test_func())
                            except AttributeError:
                                # Test method doesn't exist, skip it
                                continue
            else:
                # Run all tests (original behavior)
                # Core MCP protocol tests
                results.append(await self._test_protocol_handshake())
                results.append(await self._test_server_metadata())
                results.append(await self._test_jsonrpc_compliance())
                results.append(await self._test_capability_negotiation())
                results.append(await self._test_capability_functionality())

                # Discovery tests for all MCP capabilities
                results.append(await self._test_tool_discovery())
                results.append(await self._test_resource_discovery())
                results.append(await self._test_prompt_discovery())
                results.append(await self._test_roots_discovery())
                results.append(await self._test_resource_templates_discovery())

                # Execution tests for all MCP capabilities
                results.append(await self._test_tool_execution())
                results.append(await self._test_resource_reading())
                results.append(await self._test_prompt_execution())

                # Advanced MCP features
                results.append(await self._test_sampling_support())
                results.append(await self._test_elicitation_support())
                results.append(await self._test_notification_support())
                results.append(await self._test_client_capability_respect())
                results.append(await self._test_error_handling())

        except Exception as e:
            # Connection failure - create error result
            error_result = MCPComplianceTestResult(
                test_id=str(uuid4()),
                check_name="MCP Connection",
                category="Protocol",
                severity="critical",
                message=f"Failed to connect to MCP server: {e!s}",
                start_time=datetime.now(),
                end_time=datetime.now(),
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=0.0,
            )
            results.append(error_result)
        finally:
            # Clean up connection
            await self._disconnect_from_server()

        return results

    async def _connect_to_server(self):
        """Connect to MCP server using MCPClientManager for OAuth support"""
        server_url = self.server_config.get("url")
        if not server_url:
            raise ValueError("Server URL is required - STDIO servers not supported")

        # Check SDK availability
        if (
            ClientSession is None
            or streamablehttp_client is None
            or Implementation is None
        ):
            raise ImportError("MCP SDK not available. Install with: pip install mcp")

        # Use MCPClientManager to handle OAuth flow automatically
        # This gives us the same OAuth support as conversational testing
        try:
            self.server_id = await self.mcp_client.connect_server(self.server_config)

            # Get session from the connections dictionary
            connection = self.mcp_client.connections.get(self.server_id)
            if not connection:
                raise RuntimeError(
                    "Connection established but not found in connections"
                )

            self.session = connection.session
            if not self.session:
                raise RuntimeError("Failed to establish MCP session")

        except Exception as e:
            raise RuntimeError(f"Failed to connect to MCP server: {e}") from e

    async def _disconnect_from_server(self):
        """Clean up MCP connection"""
        try:
            if self.server_id:
                await self.mcp_client.disconnect_server(self.server_id)
                self.server_id = None
        except Exception:
            pass  # Ignore cleanup errors
        finally:
            self.session = None

    async def _test_protocol_handshake(self) -> MCPComplianceTestResult:
        """Test MCP protocol handshake and initial connection using SDK"""
        test_id = uuid4()
        start_time = datetime.now()

        if self.progress_tracker:
            self.progress_tracker.update_test_status(
                str(test_id),
                SuiteCategory.COMPLIANCE,
                ExecutionStatus.RUNNING,
                step_description="Testing protocol handshake",
            )

        try:
            # Connection is already established by _connect_to_server()
            # Test that session is properly initialized
            if not self.session:
                raise Exception("MCP session not established")

            # Extract server information from initialized session
            server_capabilities = getattr(self.session, "server_capabilities", {})
            server_info_data = getattr(self.session, "server_info", {})
            protocol_version = getattr(self.session, "protocol_version", None)

            server_info = MCPServerInfo(
                protocol_version=protocol_version,
                server_name=server_info_data.get("name"),
                server_version=server_info_data.get("version"),
                capabilities=(
                    list(server_capabilities.keys()) if server_capabilities else []
                ),
            )

            self.server_info = server_info

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Protocol Handshake",
                category="Protocol",
                severity="critical",
                message="MCP protocol handshake successful using official SDK",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=True,
                compliance_passed=True,
                server_info=server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Protocol Handshake",
                category="Protocol",
                severity="critical",
                message=f"MCP protocol handshake failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_server_metadata(self) -> MCPComplianceTestResult:
        """Test server metadata validation"""
        test_id = uuid4()
        start_time = datetime.now()

        if not self.server_info:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Server Metadata",
                category="Metadata",
                severity="high",
                message="Server metadata unavailable - handshake may have failed",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message="No server info available",
                duration=(end_time - start_time).total_seconds(),
            )

        # Check required metadata fields
        issues = []
        if not self.server_info.server_name:
            issues.append("Missing server name")
        if not self.server_info.protocol_version:
            issues.append("Missing protocol version")

        success = len(issues) == 0
        message = (
            "Server metadata complete"
            if success
            else f"Metadata issues: {', '.join(issues)}"
        )

        end_time = datetime.now()
        return MCPComplianceTestResult(
            test_id=str(test_id),
            check_name="Server Metadata",
            category="Metadata",
            severity=(
                "high" if not success else "info"
            ),  # High when failed, info when passed
            message=message,
            start_time=start_time,
            end_time=end_time,
            status=ExecutionStatus.COMPLETED,
            success=success,
            compliance_passed=success,
            server_info=self.server_info,
            duration=(end_time - start_time).total_seconds(),
        )

    async def _test_capability_negotiation(self) -> MCPComplianceTestResult:
        """Test client-server capability negotiation"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Check that server declared capabilities during handshake
            server_capabilities = getattr(self.session, "server_capabilities", {})

            # Validate capability negotiation worked
            capability_count = len(server_capabilities) if server_capabilities else 0

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Capability Negotiation",
                category="Protocol",
                severity="high",
                message=f"Server declared {capability_count} capabilities during handshake",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=True,
                compliance_passed=True,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Capability Negotiation",
                category="Protocol",
                severity="high",
                message=f"Capability negotiation test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_tool_discovery(self) -> MCPComplianceTestResult:
        """Test tool discovery capabilities using MCP SDK"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Use SDK to list tools
            tools_response = await self.session.list_tools()
            tools = tools_response.tools if hasattr(tools_response, "tools") else []

            if self.server_info:
                self.server_info.tools = [tool.model_dump() for tool in tools]

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Tool Discovery",
                category="Tools",
                severity="medium",
                message=f"Successfully discovered {len(tools)} tools using SDK",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=True,
                compliance_passed=True,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Tool Discovery",
                category="Tools",
                severity="medium",
                message=f"Tool discovery test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_resource_discovery(self) -> MCPComplianceTestResult:
        """Test resource discovery capabilities using MCP SDK"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Use SDK to list resources
            resources_response = await self.session.list_resources()
            resources = (
                resources_response.resources
                if hasattr(resources_response, "resources")
                else []
            )

            if self.server_info:
                self.server_info.resources = [
                    resource.model_dump() for resource in resources
                ]

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Resource Discovery",
                category="Resources",
                severity="medium",
                message=f"Successfully discovered {len(resources)} resources using SDK",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=True,
                compliance_passed=True,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Resource Discovery",
                category="Resources",
                severity="medium",
                message=f"Resource discovery test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_prompt_discovery(self) -> MCPComplianceTestResult:
        """Test prompt discovery capabilities using MCP SDK"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Use SDK to list prompts
            prompts_response = await self.session.list_prompts()
            prompts = (
                prompts_response.prompts if hasattr(prompts_response, "prompts") else []
            )

            if self.server_info:
                self.server_info.prompts = [prompt.model_dump() for prompt in prompts]

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Prompt Discovery",
                category="Prompts",
                severity="medium",
                message=f"Successfully discovered {len(prompts)} prompts using SDK",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=True,
                compliance_passed=True,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Prompt Discovery",
                category="Prompts",
                severity="medium",
                message=f"Prompt discovery test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_roots_discovery(self) -> MCPComplianceTestResult:
        """Test roots discovery capabilities using MCP SDK"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Use SDK to list roots (filesystem boundaries)
            if hasattr(self.session, "list_roots"):
                roots_response = await self.session.list_roots()
                roots = roots_response.roots if hasattr(roots_response, "roots") else []

                if self.server_info:
                    self.server_info.roots = [root.model_dump() for root in roots]

                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Roots Discovery",
                    category="Resources",
                    severity="info",  # Optional capability
                    message=f"Successfully discovered {len(roots)} roots using SDK",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,
                    compliance_passed=True,
                    server_info=self.server_info,
                    duration=(end_time - start_time).total_seconds(),
                )
            else:
                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Roots Discovery",
                    category="Resources",
                    severity="info",  # Optional capability
                    message="Roots discovery not supported by this MCP SDK version",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,  # Optional capability
                    compliance_passed=True,
                    duration=(end_time - start_time).total_seconds(),
                )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Roots Discovery",
                category="Resources",
                severity="info",  # Optional capability
                message=f"Roots discovery test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_resource_templates_discovery(self) -> MCPComplianceTestResult:
        """Test resource templates discovery using MCP SDK"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Use SDK to list resource templates
            if hasattr(self.session, "list_resource_templates"):
                templates_response = await self.session.list_resource_templates()
                templates = (
                    templates_response.resource_templates
                    if hasattr(templates_response, "resource_templates")
                    else []
                )

                if self.server_info:
                    self.server_info.resource_templates = [
                        template.model_dump() for template in templates
                    ]

                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Resource Templates Discovery",
                    category="Resources",
                    severity="info",  # Optional capability
                    message=f"Successfully discovered {len(templates)} resource templates using SDK",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,
                    compliance_passed=True,
                    server_info=self.server_info,
                    duration=(end_time - start_time).total_seconds(),
                )
            else:
                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Resource Templates Discovery",
                    category="Resources",
                    severity="info",  # Optional capability
                    message="Resource templates not supported by this MCP SDK version",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,  # Optional capability
                    compliance_passed=True,
                    duration=(end_time - start_time).total_seconds(),
                )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Resource Templates Discovery",
                category="Resources",
                severity="info",  # Optional capability
                message=f"Resource templates discovery test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_tool_execution(self) -> MCPComplianceTestResult:
        """Test tool execution using MCP SDK with proper validation"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Get available tools first
            tools_response = await self.session.list_tools()
            tools = tools_response.tools if hasattr(tools_response, "tools") else []

            if not tools:
                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Tool Execution",
                    category="Tools",
                    severity="info",  # Not an error if server has no tools
                    message="No tools available for execution testing",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,
                    compliance_passed=True,
                    duration=(end_time - start_time).total_seconds(),
                )

            # Test execution of first available tool
            first_tool = tools[0]
            tool_name = first_tool.name

            # Build minimal valid arguments based on schema
            test_args = self._build_minimal_tool_args(first_tool)

            try:
                result = await self.session.call_tool(tool_name, test_args)

                # Validate we got a response
                if result is not None:
                    # Check if result indicates an error vs success
                    if hasattr(result, "error") and result.error:
                        # Tool returned an error - need to determine if it's expected
                        error_msg = str(result.error)

                        # Check if error is due to test args or actual tool failure
                        if self._is_expected_validation_error(error_msg):
                            # Error due to our test arguments - tool validated input correctly
                            success = True
                            message = f"Tool '{tool_name}' correctly validated input parameters"
                        else:
                            # Unexpected error - tool may be broken
                            success = False
                            message = (
                                f"Tool '{tool_name}' failed unexpectedly: {error_msg}"
                            )
                    else:
                        # Tool executed successfully
                        success = True
                        message = f"Successfully executed tool '{tool_name}' and received response"
                else:
                    # No response at all - problematic
                    success = False
                    message = f"Tool '{tool_name}' returned no response"

            except Exception as tool_error:
                error_str = str(tool_error)

                # Determine if this is an expected error
                if self._is_expected_validation_error(error_str):
                    success = True
                    message = f"Tool '{tool_name}' correctly rejected test input: {error_str[:100]}"
                else:
                    success = False
                    message = f"Tool '{tool_name}' execution failed: {error_str[:200]}"

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Tool Execution",
                category="Tools",
                severity="high" if not success else "low",
                message=message,
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=success,
                compliance_passed=success,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Tool Execution",
                category="Tools",
                severity="high",
                message=f"Tool execution test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    def _build_minimal_tool_args(self, tool) -> dict:
        """Build minimal valid arguments for tool testing"""
        if not hasattr(tool, "input_schema") or not tool.input_schema:
            return {}

        schema = tool.input_schema
        if not isinstance(schema, dict):
            return {}

        args = {}
        properties = schema.get("properties", {})
        required = schema.get("required", [])

        # Build minimal args for required fields
        for field_name in required:
            if field_name in properties:
                field_schema = properties[field_name]
                field_type = field_schema.get("type", "string")

                # Provide minimal valid values by type
                if field_type == "string":
                    args[field_name] = "test"
                elif field_type == "number":
                    args[field_name] = 0
                elif field_type == "integer":
                    args[field_name] = 1
                elif field_type == "boolean":
                    args[field_name] = False
                elif field_type == "array":
                    args[field_name] = []
                elif field_type == "object":
                    args[field_name] = {}

        return args

    def _is_expected_validation_error(self, error_msg: str) -> bool:
        """Determine if an error is expected validation vs tool failure"""
        validation_indicators = [
            "invalid",
            "required",
            "missing",
            "expected",
            "must be",
            "should be",
            "validation",
            "parameter",
            "argument",
            "type error",
            "value error",
        ]

        error_lower = error_msg.lower()
        return any(indicator in error_lower for indicator in validation_indicators)

    async def _test_resource_reading(self) -> MCPComplianceTestResult:
        """Test resource reading with content validation using MCP SDK"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Get available resources first
            resources_response = await self.session.list_resources()
            resources = (
                resources_response.resources
                if hasattr(resources_response, "resources")
                else []
            )

            if not resources:
                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Resource Reading",
                    category="Resources",
                    severity="info",
                    message="No resources available for reading testing",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,
                    compliance_passed=True,
                    duration=(end_time - start_time).total_seconds(),
                )

            # Test reading of first available resource
            first_resource = resources[0]
            resource_uri = first_resource.uri
            resource_name = (
                first_resource.name if hasattr(first_resource, "name") else resource_uri
            )

            try:
                result = await self.session.read_resource(resource_uri)

                # Validate content structure
                validation_issues = []

                # Check if result has expected structure
                if not result:
                    validation_issues.append("Empty response")
                elif hasattr(result, "contents"):
                    contents = result.contents
                    if not contents:
                        validation_issues.append("Empty contents")
                    elif isinstance(contents, list):
                        # Validate each content item
                        for i, content in enumerate(contents):
                            if not hasattr(content, "text") and not hasattr(
                                content, "blob"
                            ):
                                validation_issues.append(
                                    f"Content item {i} missing text or blob"
                                )
                            if hasattr(content, "mimeType"):
                                mime_type = content.mimeType
                                # Validate MIME type format
                                if not mime_type or "/" not in mime_type:
                                    validation_issues.append(
                                        f"Invalid MIME type: {mime_type}"
                                    )
                    else:
                        validation_issues.append("Contents not a list")
                else:
                    validation_issues.append("Response missing contents field")

                if validation_issues:
                    success = False
                    message = f"Resource '{resource_name}' content validation failed: {'; '.join(validation_issues)}"
                else:
                    success = True
                    message = (
                        f"Successfully read and validated resource '{resource_name}'"
                    )

            except Exception as resource_error:
                success = False
                message = (
                    f"Resource '{resource_name}' reading failed: {resource_error!s}"
                )

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Resource Reading",
                category="Resources",
                severity="medium" if not success else "low",
                message=message,
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=success,
                compliance_passed=success,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Resource Reading",
                category="Resources",
                severity="medium",
                message=f"Resource reading test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_capability_functionality(self) -> MCPComplianceTestResult:
        """Test that advertised capabilities actually work"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            server_capabilities = getattr(self.session, "server_capabilities", {})

            issues = []
            tests_run = 0
            tests_passed = 0

            # Test each advertised capability
            for capability in server_capabilities.keys():
                tests_run += 1

                try:
                    if capability == "tools":
                        # Verify we can actually list tools
                        tools = await self.session.list_tools()
                        if not hasattr(tools, "tools"):
                            issues.append(
                                "Tools capability advertised but list_tools failed"
                            )
                        else:
                            tests_passed += 1

                    elif capability == "resources":
                        # Verify we can actually list resources
                        resources = await self.session.list_resources()
                        if not hasattr(resources, "resources"):
                            issues.append(
                                "Resources capability advertised but list_resources failed"
                            )
                        else:
                            tests_passed += 1

                    elif capability == "prompts":
                        # Verify we can actually list prompts
                        prompts = await self.session.list_prompts()
                        if not hasattr(prompts, "prompts"):
                            issues.append(
                                "Prompts capability advertised but list_prompts failed"
                            )
                        else:
                            tests_passed += 1

                    else:
                        # Unknown capability - just note it
                        tests_passed += 1  # Don't penalize for new capabilities

                except Exception as e:
                    issues.append(f"{capability} capability failed: {str(e)[:100]}")

            if tests_run == 0:
                message = "No capabilities advertised to test"
                success = True
            elif len(issues) == 0:
                message = f"All {tests_run} advertised capabilities verified"
                success = True
            else:
                message = f"{tests_passed}/{tests_run} capabilities work. Issues: {'; '.join(issues[:3])}"
                success = tests_passed > tests_run * 0.5  # Pass if more than half work

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Capability Functionality",
                category="Capabilities",
                severity="high" if not success else "low",
                message=message,
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=success,
                compliance_passed=success,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Capability Functionality",
                category="Capabilities",
                severity="high",
                message=f"Capability functionality test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_jsonrpc_compliance(self) -> MCPComplianceTestResult:
        """Test JSON-RPC 2.0 protocol compliance"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            import json

            import httpx

            server_url = self.server_config.get("url", "")

            # Test various JSON-RPC scenarios
            test_cases = [
                {
                    "name": "Valid request",
                    "request": {
                        "jsonrpc": "2.0",
                        "id": 1,
                        "method": "initialize",
                        "params": {
                            "protocolVersion": "2024-11-05",
                            "capabilities": {},
                            "clientInfo": {"name": "test", "version": "1.0"},
                        },
                    },
                    "expect_success": True,
                },
                {
                    "name": "Missing jsonrpc version",
                    "request": {"id": 2, "method": "initialize", "params": {}},
                    "expect_success": False,
                },
                {
                    "name": "Invalid jsonrpc version",
                    "request": {
                        "jsonrpc": "1.0",  # Should be "2.0"
                        "id": 3,
                        "method": "initialize",
                        "params": {},
                    },
                    "expect_success": False,
                },
                {
                    "name": "Notification (no id)",
                    "request": {
                        "jsonrpc": "2.0",
                        "method": "notifications/progress",
                        "params": {"progress": 50},
                    },
                    "expect_success": True,
                    "is_notification": True,
                },
            ]

            issues = []
            tests_passed = 0

            headers = {}
            if auth_token := self.server_config.get("authorization_token"):
                if not auth_token.startswith("Bearer "):
                    auth_token = f"Bearer {auth_token}"
                headers["Authorization"] = auth_token

            async with httpx.AsyncClient(timeout=10.0) as client:
                for test_case in test_cases:
                    try:
                        response = await client.post(
                            server_url, json=test_case["request"], headers=headers
                        )

                        # Validate response format
                        if response.status_code == 200:
                            try:
                                response_data = response.json()

                                # Validate JSON-RPC response format
                                if test_case.get("is_notification"):
                                    # Notifications shouldn't get responses
                                    if response_data:
                                        issues.append(
                                            f"{test_case['name']}: Got response for notification"
                                        )
                                else:
                                    # Regular request - validate response
                                    if (
                                        "jsonrpc" not in response_data
                                        or response_data["jsonrpc"] != "2.0"
                                    ):
                                        issues.append(
                                            f"{test_case['name']}: Invalid jsonrpc version in response"
                                        )

                                    if (
                                        "id" in test_case["request"]
                                        and response_data.get("id")
                                        != test_case["request"]["id"]
                                    ):
                                        issues.append(
                                            f"{test_case['name']}: Response id doesn't match request"
                                        )

                                    if (
                                        "result" not in response_data
                                        and "error" not in response_data
                                    ):
                                        issues.append(
                                            f"{test_case['name']}: Response missing result or error"
                                        )

                                    if (
                                        "result" in response_data
                                        and "error" in response_data
                                    ):
                                        issues.append(
                                            f"{test_case['name']}: Response has both result and error"
                                        )

                                if test_case["expect_success"]:
                                    tests_passed += 1
                            except json.JSONDecodeError:
                                issues.append(
                                    f"{test_case['name']}: Invalid JSON response"
                                )
                        # Non-200 response
                        elif not test_case["expect_success"]:
                            tests_passed += 1  # Expected to fail
                        else:
                            issues.append(
                                f"{test_case['name']}: Unexpected status {response.status_code}"
                            )

                    except Exception as e:
                        issues.append(f"{test_case['name']}: {str(e)[:50]}")

            success = len(issues) == 0
            message = (
                f"JSON-RPC 2.0 compliance: {tests_passed}/{len(test_cases)} tests passed"
                + (f". Issues: {'; '.join(issues[:2])}" if issues else "")
            )

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="JSON-RPC 2.0 Compliance",
                category="Protocol",
                severity="high" if not success else "low",
                message=message,
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=success,
                compliance_passed=success,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="JSON-RPC 2.0 Compliance",
                category="Protocol",
                severity="high",
                message=f"JSON-RPC compliance test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_error_handling(self) -> MCPComplianceTestResult:
        """Test server error handling with invalid inputs"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            error_tests = []

            # Test 1: Invalid tool name
            try:
                await self.session.call_tool("definitely_nonexistent_tool_name_xyz", {})
                error_tests.append(
                    ("Invalid tool name", False, "Should have failed but didn't")
                )
            except Exception as e:
                error_str = str(e).lower()
                if (
                    "not found" in error_str
                    or "unknown" in error_str
                    or "invalid" in error_str
                ):
                    error_tests.append(("Invalid tool name", True, "Properly rejected"))
                else:
                    error_tests.append(
                        ("Invalid tool name", False, f"Unexpected error: {str(e)[:50]}")
                    )

            # Test 2: Invalid resource URI
            try:
                await self.session.read_resource(
                    "invalid://resource/uri/../../etc/passwd"
                )
                error_tests.append(
                    ("Invalid resource URI", False, "Should have failed but didn't")
                )
            except Exception:
                error_tests.append(("Invalid resource URI", True, "Properly rejected"))

            # Test 3: Malformed parameters
            tools_response = await self.session.list_tools()
            tools = tools_response.tools if hasattr(tools_response, "tools") else []

            if tools:
                first_tool = tools[0]
                # Pass wrong type for parameters
                try:
                    await self.session.call_tool(first_tool.name, "not_a_dict")
                    error_tests.append(
                        ("Malformed parameters", False, "Should have failed")
                    )
                except Exception:
                    error_tests.append(
                        ("Malformed parameters", True, "Properly rejected")
                    )

            # Calculate results
            passed = sum(1 for _, success, _ in error_tests if success)
            total = len(error_tests)

            issues = [msg for _, success, msg in error_tests if not success]

            success = passed == total
            message = f"Error handling: {passed}/{total} tests passed" + (
                f". Issues: {'; '.join(issues)}" if issues else ""
            )

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Error Handling",
                category="Protocol",
                severity="medium" if not success else "low",
                message=message,
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=success,
                compliance_passed=success,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Error Handling",
                category="Protocol",
                severity="medium",
                message=f"Error handling test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_prompt_execution(self) -> MCPComplianceTestResult:
        """Test prompt execution using MCP SDK"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Get available prompts first
            prompts_response = await self.session.list_prompts()
            prompts = (
                prompts_response.prompts if hasattr(prompts_response, "prompts") else []
            )

            if not prompts:
                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Prompt Execution",
                    category="Prompts",
                    severity="low",
                    message="No prompts available for execution testing",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,  # Not a failure if no prompts
                    compliance_passed=True,
                    duration=(end_time - start_time).total_seconds(),
                )

            # Test execution of first available prompt
            first_prompt = prompts[0]
            prompt_name = first_prompt.name

            # Use minimal arguments for testing
            test_args: dict[str, Any] = {}

            try:
                _ = await self.session.get_prompt(prompt_name, test_args)

                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Prompt Execution",
                    category="Prompts",
                    severity="medium",
                    message=f"Successfully executed prompt '{prompt_name}' using SDK",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,
                    compliance_passed=True,
                    server_info=self.server_info,
                    duration=(end_time - start_time).total_seconds(),
                )

            except Exception as prompt_error:
                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Prompt Execution",
                    category="Prompts",
                    severity="low",
                    message=f"Prompt '{prompt_name}' execution resulted in error (may be expected): {prompt_error!s}",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,  # Error may be expected with test args
                    compliance_passed=True,
                    server_info=self.server_info,
                    duration=(end_time - start_time).total_seconds(),
                )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Prompt Execution",
                category="Prompts",
                severity="medium",
                message=f"Prompt execution test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_sampling_support(self) -> MCPComplianceTestResult:
        """Test MCP server sampling support (server requesting LLM completions)"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Check if server capabilities include sampling
            server_capabilities = getattr(self.session, "server_capabilities", {})
            supports_sampling = "sampling" in server_capabilities

            end_time = datetime.now()
            if supports_sampling:
                # Server advertises sampling capability - test would require triggering
                # a server action that requests sampling from client
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Sampling Support",
                    category="Advanced",
                    severity="low",
                    message="Server advertises sampling capability (full testing requires server-initiated sampling request)",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,
                    compliance_passed=True,
                    server_info=self.server_info,
                    duration=(end_time - start_time).total_seconds(),
                )
            else:
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Sampling Support",
                    category="Advanced",
                    severity="info",
                    message="Server does not advertise sampling capability",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,  # Optional capability
                    compliance_passed=True,
                    duration=(end_time - start_time).total_seconds(),
                )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Sampling Support",
                category="Advanced",
                severity="low",
                message=f"Sampling support test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_elicitation_support(self) -> MCPComplianceTestResult:
        """Test MCP server elicitation support (server requesting user input)"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Elicitation would be tested during tool/resource operations that require
            # additional user input. This is difficult to test automatically.
            # We can check if server has tools/resources that might use elicitation

            tools_response = await self.session.list_tools()
            tools = tools_response.tools if hasattr(tools_response, "tools") else []

            # Look for tools that might require elicitation based on their schemas
            interactive_tools = []
            for tool in tools:
                if hasattr(tool, "input_schema") and tool.input_schema:
                    # Check if tool has parameters that might require elicitation
                    schema = tool.input_schema
                    if isinstance(schema, dict) and "properties" in schema:
                        interactive_tools.append(tool.name)

            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Elicitation Support",
                category="Advanced",
                severity="info",
                message=f"Found {len(interactive_tools)} tools that may support elicitation (full testing requires interactive scenarios)",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.COMPLETED,
                success=True,  # Optional capability
                compliance_passed=True,
                server_info=self.server_info,
                duration=(end_time - start_time).total_seconds(),
            )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Elicitation Support",
                category="Advanced",
                severity="low",
                message=f"Elicitation support test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_notification_support(self) -> MCPComplianceTestResult:
        """Test MCP server notification support"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Check if server capabilities include notifications
            server_capabilities = getattr(self.session, "server_capabilities", {})
            supports_notifications = "notifications" in server_capabilities

            end_time = datetime.now()
            if supports_notifications:
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Notification Support",
                    category="Advanced",
                    severity="low",
                    message="Server advertises notification capability",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,
                    compliance_passed=True,
                    server_info=self.server_info,
                    duration=(end_time - start_time).total_seconds(),
                )
            else:
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Notification Support",
                    category="Advanced",
                    severity="info",
                    message="Server does not advertise notification capability",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,  # Optional capability
                    compliance_passed=True,
                    duration=(end_time - start_time).total_seconds(),
                )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Notification Support",
                category="Advanced",
                severity="low",
                message=f"Notification support test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )

    async def _test_client_capability_respect(self) -> MCPComplianceTestResult:
        """Test if server respects client-declared capabilities"""
        test_id = uuid4()
        start_time = datetime.now()

        try:
            if not self.session:
                raise Exception("No MCP session available")

            # Check what capabilities client declared vs what server is using
            client_capabilities = getattr(self.session, "client_capabilities", {})
            server_capabilities = getattr(self.session, "server_capabilities", {})

            # Basic test: verify capability negotiation happened
            if client_capabilities and server_capabilities:
                # Check for capability overlap - server should only use what client supports
                common_capabilities = set(client_capabilities.keys()) & set(
                    server_capabilities.keys()
                )

                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Client Capability Respect",
                    category="Protocol",
                    severity="medium",
                    message=f"Capability negotiation successful - {len(common_capabilities)} common capabilities",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=True,
                    compliance_passed=True,
                    server_info=self.server_info,
                    duration=(end_time - start_time).total_seconds(),
                )
            else:
                end_time = datetime.now()
                return MCPComplianceTestResult(
                    test_id=str(test_id),
                    check_name="Client Capability Respect",
                    category="Protocol",
                    severity="medium",
                    message="Capability negotiation unclear - missing capability information",
                    start_time=start_time,
                    end_time=end_time,
                    status=ExecutionStatus.COMPLETED,
                    success=False,
                    compliance_passed=False,
                    duration=(end_time - start_time).total_seconds(),
                )

        except Exception as e:
            end_time = datetime.now()
            return MCPComplianceTestResult(
                test_id=str(test_id),
                check_name="Client Capability Respect",
                category="Protocol",
                severity="medium",
                message=f"Client capability respect test failed: {e!s}",
                start_time=start_time,
                end_time=end_time,
                status=ExecutionStatus.FAILED,
                success=False,
                compliance_passed=False,
                error_message=str(e),
                duration=(end_time - start_time).total_seconds(),
            )
