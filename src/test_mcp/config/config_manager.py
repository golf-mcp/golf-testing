import datetime
import json
import os
from enum import Enum
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

from ..models.compliance import ComplianceTestConfig, ComplianceTestSuite
from ..models.conversational import ConversationalTestConfig, ConversationTestSuite
from ..models.factory import TestSuiteFactory, TestSuiteType
from ..models.security import SecurityTestConfig, SecurityTestSuite
from ..shared.file_utils import ensure_directory, safe_json_dump


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

    # Timeout configuration
    tool_timeout: int = Field(
        default=60,
        description="Timeout in seconds for individual tool executions (default: 60)",
        ge=1,  # Greater than or equal to 1 second
        le=600,  # Less than or equal to 10 minutes
    )
    connection_timeout: int = Field(
        default=30,
        description="Timeout in seconds for establishing connection (default: 30)",
        ge=1,
        le=120,
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


class ConfigTemplate(str, Enum):
    """Available configuration templates"""

    BASIC_SERVER = "basic_server"
    SIMPLE_SUITE = "simple_suite"  # Used for compliance testing
    SECURITY_SUITE = "security_suite"
    WORKFLOW_SUITE = "workflow_suite"  # Renamed to conversational testing


class MCPPaths:
    """Configuration paths with support for local and XDG-compliant system directories"""

    def __init__(self, app_name: str = "mcp-t", use_local: bool = True):
        self.app_name = app_name
        self.use_local = use_local

    def get_local_paths(self) -> dict[str, Path]:
        """Get local project configuration paths."""
        base_dir = Path.cwd()
        return {
            "config_dir": base_dir / "configs",
            "servers_dir": base_dir / "configs" / "servers",
            "suites_dir": base_dir / "configs" / "suites",
        }

    def get_system_paths(self) -> dict[str, Path]:
        """Get XDG-compliant system configuration paths."""
        # XDG Base Directory compliant paths (hardcoded, not from env vars)
        config_base = Path.home() / ".config" / self.app_name
        data_base = Path.home() / ".local" / "share" / self.app_name
        cache_base = Path.home() / ".cache" / self.app_name
        state_base = Path.home() / ".local" / "state" / self.app_name

        return {
            "config_dir": config_base,
            "servers_dir": config_base / "servers",
            "suites_dir": config_base / "suites",
            "data_dir": data_base,
            "cache_dir": cache_base,
            "state_dir": state_base,
        }

    def get_all_paths(self) -> dict[str, Any]:
        """Get combined local and system paths with precedence."""
        local_paths = self.get_local_paths()
        system_paths = self.get_system_paths()

        return {
            "local": local_paths,
            "system": system_paths,
            "servers_dirs": [local_paths["servers_dir"], system_paths["servers_dir"]],
            "suites_dirs": [local_paths["suites_dir"], system_paths["suites_dir"]],
        }


class ConfigManager:
    """Production-ready configuration management with organized directory structure"""

    def __init__(self):
        self.paths = MCPPaths()
        self.templates = self._load_templates()

        # Ensure system directories exist (for backward compatibility)
        system_paths = self.paths.get_system_paths()
        for path in [
            system_paths["servers_dir"],
            system_paths["suites_dir"],
            system_paths["data_dir"],
            system_paths["cache_dir"],
        ]:
            ensure_directory(path)

    def _load_templates(self) -> dict[str, dict[str, Any]]:
        """Load built-in configuration templates"""
        return {
            ConfigTemplate.BASIC_SERVER: {
                "url": "${MCP_SERVER_URL}",
                "name": "${MCP_SERVER_NAME:-My MCP Server}",
                "authorization_token": "${MCP_AUTH_TOKEN:-}",
            },
            ConfigTemplate.SIMPLE_SUITE: {
                "suite_id": "${SUITE_ID:-compliance_test_suite}",
                "name": "${SUITE_NAME:-MCP Compliance Test Suite}",
                "description": "${SUITE_DESCRIPTION:-MCP protocol compliance testing}",
                "suite_type": "compliance",
                "parallelism": 1,
                "test_cases": [
                    {
                        "test_id": "protocol_handshake",
                        "protocol_version": "2025-06-18",
                        "check_categories": ["handshake"],
                        "metadata": {
                            "category": "protocol",
                            "priority": "high",
                        },
                    },
                    {
                        "test_id": "capabilities_discovery",
                        "protocol_version": "2025-06-18",
                        "check_categories": ["capabilities"],
                        "metadata": {"category": "capabilities", "priority": "high"},
                    },
                    {
                        "test_id": "tool_enumeration",
                        "protocol_version": "2025-06-18",
                        "check_categories": ["tools"],
                        "metadata": {"category": "tools", "priority": "medium"},
                    },
                ],
                "auth_required": False,
                "strict_mode": True,
                "created_at": "${CURRENT_TIMESTAMP:-2024-01-01T00:00:00Z}",
            },
            ConfigTemplate.SECURITY_SUITE: {
                "suite_id": "${SUITE_ID:-security_test_suite}",
                "name": "${SUITE_NAME:-MCP Security Test Suite}",
                "description": "${SUITE_DESCRIPTION:-MCP security and authentication testing}",
                "suite_type": "security",
                "parallelism": 1,
                "test_cases": [
                    {
                        "test_id": "auth_validation",
                        "auth_method": "oauth",
                        "rate_limit_threshold": 100,
                        "vulnerability_checks": ["auth"],
                        "severity_threshold": "medium",
                        "metadata": {"category": "authentication", "priority": "high"},
                    },
                    {
                        "test_id": "rate_limiting",
                        "auth_method": "token",
                        "rate_limit_threshold": 50,
                        "vulnerability_checks": ["rate_limit"],
                        "severity_threshold": "medium",
                        "metadata": {"category": "rate_limiting", "priority": "medium"},
                    },
                    {
                        "test_id": "injection_testing",
                        "auth_method": "oauth",
                        "rate_limit_threshold": 100,
                        "vulnerability_checks": ["injection"],
                        "severity_threshold": "high",
                        "metadata": {
                            "category": "input_validation",
                            "priority": "high",
                        },
                    },
                ],
                "auth_required": True,
                "include_penetration_tests": False,
                "created_at": "${CURRENT_TIMESTAMP:-2024-01-01T00:00:00Z}",
            },
            ConfigTemplate.WORKFLOW_SUITE: {
                "suite_id": "${SUITE_ID:-conversational_test_suite}",
                "name": "${SUITE_NAME:-Conversational Test Suite}",
                "description": "${SUITE_DESCRIPTION:-Multi-turn conversation testing}",
                "suite_type": "conversational",
                "parallelism": 1,
                "test_cases": [
                    {
                        "test_id": "multi_turn_conversation",
                        "user_message": "Start a complex multi-step task with me",
                        "success_criteria": "Maintains context across multiple interactions",
                        "max_turns": 10,
                        "context_persistence": True,
                        "metadata": {"category": "conversation", "priority": "high"},
                    },
                    {
                        "test_id": "error_recovery",
                        "user_message": "Let's try something that might cause an error",
                        "success_criteria": "Graceful error handling and recovery",
                        "max_turns": 5,
                        "context_persistence": True,
                        "metadata": {
                            "category": "error_handling",
                            "priority": "medium",
                        },
                    },
                    {
                        "test_id": "context_persistence",
                        "user_message": "Remember what we discussed earlier",
                        "success_criteria": "Maintains conversation context across turns",
                        "max_turns": 8,
                        "context_persistence": True,
                        "metadata": {"category": "context", "priority": "high"},
                    },
                ],
                "user_patience_level": "medium",
                "conversation_style": "natural",
                "created_at": "${CURRENT_TIMESTAMP:-2024-01-01T00:00:00Z}",
            },
        }

    def save_server_config(self, server_id: str, server_config: dict) -> Path:
        """Save server configuration with memorable ID"""
        system_paths = self.paths.get_system_paths()
        config_path = system_paths["servers_dir"] / f"{server_id}.json"

        safe_json_dump(server_config, config_path, "saving server configuration")

        return config_path

    def save_suite_config(self, suite_id: str, suite_config: dict) -> Path:
        """Save test suite configuration with memorable ID"""
        system_paths = self.paths.get_system_paths()
        config_path = system_paths["suites_dir"] / f"{suite_id}.json"

        # Add creation timestamp if not provided
        if "created_at" not in suite_config:
            from datetime import datetime

            suite_config["created_at"] = datetime.now().isoformat()

        safe_json_dump(suite_config, config_path, "saving suite configuration")

        return config_path

    def save_test_suite(
        self, test_suite: TestSuiteType, use_global: bool = True
    ) -> Path:
        """Save test suite configuration from type-safe model"""
        if use_global:
            paths = self.paths.get_system_paths()
        else:
            paths = self.paths.get_local_paths()
        config_path = paths["suites_dir"] / f"{test_suite.suite_id}.json"

        # Add suite_type field for proper loading
        suite_data = test_suite.model_dump(mode="json")
        if hasattr(test_suite, "__class__"):
            if test_suite.__class__.__name__ == "ComplianceTestSuite":
                suite_data["suite_type"] = "compliance"
            elif test_suite.__class__.__name__ == "SecurityTestSuite":
                suite_data["suite_type"] = "security"
            elif test_suite.__class__.__name__ == "ConversationTestSuite":
                suite_data["suite_type"] = "conversational"

        safe_json_dump(suite_data, config_path, "saving suite data")

        return config_path

    def create_compliance_template(self) -> ComplianceTestSuite:
        """Create default compliance test suite template"""
        return ComplianceTestSuite(
            suite_id="compliance-tests",
            name="MCP Protocol Compliance Tests",
            description="Standard MCP protocol validation tests",
            test_cases=[
                ComplianceTestConfig(
                    test_id="protocol_handshake",
                    protocol_version="2025-06-18",
                    check_categories=["handshake"],
                ),
                ComplianceTestConfig(
                    test_id="capabilities_discovery", check_categories=["capabilities"]
                ),
                ComplianceTestConfig(
                    test_id="tool_enumeration", check_categories=["tools"]
                ),
                ComplianceTestConfig(
                    test_id="oauth_flow",
                    check_categories=["auth"],
                ),
            ],
            auth_required=False,
            strict_mode=True,
            parallelism=1,  # OAuth-safe for compliance tests with auth
        )

    def create_security_template(self) -> SecurityTestSuite:
        """Create default security test suite template"""
        return SecurityTestSuite(
            suite_id="security-tests",
            name="MCP Security Assessment Tests",
            description="Authentication and vulnerability testing",
            test_cases=[
                SecurityTestConfig(
                    test_id="auth_validation",
                    auth_method="oauth",
                    vulnerability_checks=["auth"],
                ),
                SecurityTestConfig(
                    test_id="rate_limiting",
                    auth_method="oauth",
                    rate_limit_threshold=100,
                    vulnerability_checks=["rate_limit"],
                ),
                SecurityTestConfig(
                    test_id="injection_testing",
                    auth_method="oauth",
                    vulnerability_checks=["injection"],
                ),
            ],
            auth_required=True,
            include_penetration_tests=False,
            parallelism=1,  # OAuth requires sequential execution
        )

    def create_conversational_template(self) -> ConversationTestSuite:
        """Create default conversational test suite template"""
        return ConversationTestSuite(
            suite_id="conversational-tests",
            name="Multi-Turn Conversation Tests",
            description="Interactive dialogue and workflow testing",
            test_cases=[
                ConversationalTestConfig(
                    test_id="greeting_and_capabilities",
                    user_message="Hello! Can you help me?",
                    success_criteria="Agent responds politely and explains capabilities",
                    max_turns=3,
                ),
                ConversationalTestConfig(
                    test_id="multi_turn_workflow",
                    user_message="I need to complete a complex task with multiple steps",
                    success_criteria="Agent successfully guides through multi-step process",
                    max_turns=10,
                    context_persistence=True,
                ),
            ],
            auth_required=False,
            user_patience_level="medium",
            conversation_style="natural",
            parallelism=1,  # Sequential execution for conversation context
        )

    def get_server_by_id(self, server_id: str) -> MCPServerConfig:
        """Load server configuration by ID, checking local first."""
        paths = self.paths.get_all_paths()

        # Check local first, then system
        for servers_dir in paths["servers_dirs"]:
            server_file = servers_dir / f"{server_id}.json"
            if server_file.exists():
                try:
                    with server_file.open() as f:
                        config_data = json.load(f)
                    return MCPServerConfig(**config_data)
                except Exception as e:
                    raise ValueError(
                        f"Error loading server '{server_id}': {e!s}\n"
                        f"The configuration file may be corrupted or have invalid format."
                    ) from e

        # Server not found, provide helpful error message
        available_servers = [
            f.stem
            for path in paths["servers_dirs"]
            for f in path.glob("*.json")
            if f.is_file()
        ]
        raise ValueError(
            f"Server '{server_id}' not found.\n"
            f"Available servers: {', '.join(available_servers) if available_servers else 'none'}\n"
            f"Create a new server with: mcp-t create server"
        )

    def get_suite_by_id(self, suite_id: str) -> TestSuiteType:
        """Load test suite by ID using type-safe models, checking local first."""
        return self.load_test_suite(suite_id)

    def _load_suite_config_with_error_handling(self, suite_id: str) -> dict[str, Any]:
        """Load suite config with helpful error messages"""
        try:
            return self._load_suite_config(suite_id)
        except FileNotFoundError:
            available_suites = self._get_available_suite_ids()
            raise ValueError(
                f"Test suite '{suite_id}' not found.\n"
                f"Available suites: {', '.join(available_suites) if available_suites else 'none'}\n"
                f"Create a new suite with: mcp-t create suite"
            ) from None

    def _get_available_suite_ids(self) -> list[str]:
        """Get list of available suite IDs for error messages"""
        return [
            f.stem
            for path in self.paths.get_all_paths()["suites_dirs"]
            for f in path.glob("*.json")
            if f.is_file()
        ]

    def load_test_suite(self, suite_id: str) -> TestSuiteType:
        """Load test suite with appropriate type-specific model"""
        config_data = self._load_suite_config_with_error_handling(suite_id)
        suite_type = self._determine_suite_type(config_data, suite_id)
        return self._create_typed_suite(suite_id, suite_type, config_data)

    def _determine_suite_type(self, config_data: dict[str, Any], suite_id: str) -> str:
        """Determine suite type from config or filename"""
        return config_data.get("suite_type") or self._infer_suite_type(suite_id)

    def _create_typed_suite(
        self, suite_id: str, suite_type: str, config_data: dict[str, Any]
    ) -> TestSuiteType:
        """Create typed suite with proper error handling"""
        try:
            return TestSuiteFactory.create_suite(suite_type, config_data)
        except Exception as e:
            if (
                "validation error" in str(e).lower()
                or "field required" in str(e).lower()
            ):
                raise ValueError(
                    f"Test suite '{suite_id}' has an incompatible format.\n"
                    f"This may be an older configuration that needs updating.\n"
                    f"Try creating a new {suite_type} suite with: mcp-t create suite\n"
                    f"Original error: {e!s}"
                ) from e
            else:
                raise ValueError(
                    f"Error loading test suite '{suite_id}': {e!s}"
                ) from None

    def _load_suite_config(self, suite_id: str) -> dict[str, Any]:
        """Load suite configuration data from file"""
        paths = self.paths.get_all_paths()

        # Check local first, then system
        for suites_dir in paths["suites_dirs"]:
            suite_file = suites_dir / f"{suite_id}.json"
            if suite_file.exists():
                with suite_file.open() as f:
                    return json.load(f)

        raise KeyError(
            f"Suite '{suite_id}' not found in local or system configurations"
        )

    def _infer_suite_type(self, suite_id: str) -> str:
        """Infer suite type from naming convention"""
        if "compliance" in suite_id.lower():
            return "compliance"
        elif "security" in suite_id.lower():
            return "security"
        else:
            return "conversational"

    def list_servers(self) -> dict[str, dict[str, str]]:
        """List all available servers from local and system paths."""
        servers = {}
        paths = self.paths.get_all_paths()

        # Check local first, then system
        for servers_dir in paths["servers_dirs"]:
            if not servers_dir.exists():
                continue

            for server_file in servers_dir.glob("*.json"):
                server_id = server_file.stem
                if server_id in servers:
                    continue  # Local takes precedence

                try:
                    with server_file.open() as f:
                        config = json.load(f)

                    # Determine source
                    is_local = servers_dir == paths["local"]["servers_dir"]
                    source = "local" if is_local else "system"

                    # Get file modification time as creation date
                    file_stat = server_file.stat()
                    creation_date = datetime.datetime.fromtimestamp(
                        file_stat.st_mtime
                    ).strftime("%Y-%m-%d")

                    servers[server_id] = {
                        "name": config.get("name", server_id),
                        "url": config.get("url", ""),
                        "source": source,
                        "path": str(server_file),
                        "transport": config.get("transport", "http"),
                        "oauth": config.get("oauth", False),
                        "creation_date": creation_date,
                    }
                except (json.JSONDecodeError, KeyError):
                    continue

        return servers

    def list_suites(self) -> dict[str, dict[str, Any]]:
        """List all available test suites from local and system paths."""
        suites = {}
        paths = self.paths.get_all_paths()

        # Check local first, then system
        for suites_dir in paths["suites_dirs"]:
            if not suites_dir.exists():
                continue

            for suite_file in suites_dir.glob("*.json"):
                suite_id = suite_file.stem
                if suite_id in suites:
                    continue  # Local takes precedence

                try:
                    with suite_file.open() as f:
                        config = json.load(f)

                    # Determine source
                    is_local = suites_dir == paths["local"]["suites_dir"]
                    source = "local" if is_local else "system"

                    # Get file modification time as creation date
                    file_stat = suite_file.stat()
                    creation_date = datetime.datetime.fromtimestamp(
                        file_stat.st_mtime
                    ).strftime("%Y-%m-%d")

                    suites[suite_id] = {
                        "name": config.get("name", suite_id),
                        "description": config.get("description", ""),
                        "test_count": len(config.get("test_cases", [])),
                        "source": source,
                        "path": str(suite_file),
                        "creation_date": creation_date,
                    }
                except (json.JSONDecodeError, KeyError):
                    continue

        return suites

    def list_server_ids(self) -> list[str]:
        """List all server IDs for tab completion"""
        server_ids: set[str] = set()
        paths = self.paths.get_all_paths()

        for servers_dir in paths["servers_dirs"]:
            if servers_dir.exists():
                server_ids.update(f.stem for f in servers_dir.glob("*.json"))

        return sorted(server_ids)

    def list_suite_ids(self) -> list[str]:
        """List all suite IDs for tab completion"""
        suite_ids: set[str] = set()
        paths = self.paths.get_all_paths()

        for suites_dir in paths["suites_dirs"]:
            if suites_dir.exists():
                suite_ids.update(f.stem for f in suites_dir.glob("*.json"))

        return sorted(suite_ids)

    def create_template(
        self,
        template_type: ConfigTemplate,
        output_path: str,
        substitutions: dict[str, str] | None = None,
    ) -> Path:
        """Create configuration file from template with environment variable substitution"""
        template_data = self.templates[template_type].copy()

        if substitutions:
            # Apply custom substitutions first
            template_json = json.dumps(template_data)
            for key, value in substitutions.items():
                template_json = template_json.replace(f"${{{key}}}", value)
            template_data = json.loads(template_json)

        # Apply environment variable substitution
        expanded_data = self._expand_environment_variables(template_data)

        # Add current timestamp if template uses it
        if "${CURRENT_TIMESTAMP}" in json.dumps(expanded_data):
            from datetime import datetime

            current_time = datetime.now().isoformat()
            expanded_json = json.dumps(expanded_data).replace(
                "${CURRENT_TIMESTAMP}", current_time
            )
            expanded_data = json.loads(expanded_json)

        output_file = Path(output_path)
        ensure_directory(output_file.parent)

        # Determine format from extension
        if (
            output_file.suffix.lower() == ".yaml"
            or output_file.suffix.lower() == ".yml"
        ):
            with open(output_file, "w") as f:
                yaml.dump(expanded_data, f, default_flow_style=False, indent=2)
        else:
            with open(output_file, "w") as f:
                json.dump(expanded_data, f, indent=2)

        return output_file

    def _expand_environment_variables(self, data: Any) -> Any:
        """Recursively expand environment variables in configuration data"""
        if isinstance(data, str):
            # Handle ${VAR} and ${VAR:-default} patterns
            import re

            def replace_env_var(match):
                var_expr = match.group(1)
                if ":-" in var_expr:
                    var_name, default_value = var_expr.split(":-", 1)
                    return os.environ.get(var_name, default_value)
                else:
                    return os.environ.get(
                        var_expr, match.group(0)
                    )  # Return original if not found

            return re.sub(r"\$\{([^}]+)\}", replace_env_var, data)

        elif isinstance(data, dict):
            return {
                key: self._expand_environment_variables(value)
                for key, value in data.items()
            }
        elif isinstance(data, list):
            return [self._expand_environment_variables(item) for item in data]
        else:
            return data

    def get_update_config(self) -> dict:
        """Get version update check configuration"""
        default_config = {
            "enabled": True,
            "check_interval_days": 7,
            "show_prerelease": False,
            "last_notification": None,
            "notification_cooldown_hours": 24,
        }

        try:
            config_path = (
                self.paths.get_system_paths()["config_dir"] / "update_config.json"
            )
            if config_path.exists():
                with open(config_path) as f:
                    user_config = json.load(f)
                    # Merge with defaults
                    default_config.update(user_config)
        except Exception:
            pass  # Use defaults on error

        return default_config

    def save_update_config(self, config: dict):
        """Save version update check configuration"""
        try:
            config_path = (
                self.paths.get_system_paths()["config_dir"] / "update_config.json"
            )
            ensure_directory(config_path.parent)
            with open(config_path, "w") as f:
                json.dump(config, f, indent=2)
        except Exception:
            pass  # Fail silently

    def should_check_for_updates(self) -> bool:
        """Determine if version checking should run"""
        # Check environment variables for opt-out
        import os

        if os.environ.get("NO_UPDATE_NOTIFIER"):
            return False

        if os.environ.get("CI"):
            return False

        # Check TTY (don't show in non-interactive sessions)
        import sys

        if not sys.stdout.isatty():
            return False

        # Check user configuration
        config = self.get_update_config()
        return config.get("enabled", True)


# Global config manager instance
config_manager = ConfigManager()
