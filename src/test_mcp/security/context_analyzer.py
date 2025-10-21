import re
from dataclasses import dataclass
from enum import Enum
from typing import Any

from ..mcp_client.client_manager import MCPClientManager


class DatabaseType(str, Enum):
    """Detected database types"""
    MYSQL = "mysql"
    POSTGRESQL = "postgresql"
    SQLITE = "sqlite"
    MONGODB = "mongodb"
    REDIS = "redis"
    UNKNOWN = "unknown"


class OperatingSystem(str, Enum):
    """Detected operating systems"""
    LINUX = "linux"
    WINDOWS = "windows"
    MACOS = "macos"
    UNIX = "unix"
    UNKNOWN = "unknown"


class Framework(str, Enum):
    """Detected frameworks"""
    DJANGO = "django"
    FLASK = "flask"
    EXPRESS = "express"
    FASTAPI = "fastapi"
    SPRING = "spring"
    RAILS = "rails"
    UNKNOWN = "unknown"


@dataclass
class TechnologyStack:
    """Detected server technology stack"""
    databases: list[DatabaseType]
    operating_system: OperatingSystem
    frameworks: list[Framework]
    languages: list[str]
    file_systems: list[str]
    web_servers: list[str]


@dataclass
class AttackSurface:
    """Analysis of potential attack vectors"""
    sql_injection_targets: list[dict[str, Any]]
    command_injection_targets: list[dict[str, Any]]
    path_traversal_targets: list[dict[str, Any]]
    file_manipulation_targets: list[dict[str, Any]]
    authentication_bypass_targets: list[dict[str, Any]]
    information_disclosure_targets: list[dict[str, Any]]


@dataclass
class ServerContext:
    """Complete server context analysis"""
    technology_stack: TechnologyStack
    attack_surface: AttackSurface
    tool_schemas: list[dict[str, Any]]
    server_metadata: dict[str, Any]
    capabilities_summary: dict[str, int]
    risk_assessment: dict[str, str]


class ContextAnalyzer:
    """Analyze server context and capabilities for targeted attack generation"""

    def __init__(self):
        # Technology detection patterns
        self.db_patterns = {
            DatabaseType.MYSQL: [
                r'mysql', r'mariadb', r'sql.*query', r'select.*from', r'insert.*into',
                r'database.*connection', r'mysql.*connector'
            ],
            DatabaseType.POSTGRESQL: [
                r'postgres', r'psql', r'pg_', r'postgresql', r'psycopg'
            ],
            DatabaseType.SQLITE: [
                r'sqlite', r'\.db$', r'\.sqlite$', r'sqlite3'
            ],
            DatabaseType.MONGODB: [
                r'mongo', r'mongodb', r'collection', r'document.*store'
            ],
            DatabaseType.REDIS: [
                r'redis', r'cache.*store', r'key.*value'
            ]
        }

        self.os_patterns = {
            OperatingSystem.LINUX: [
                r'/bin/', r'/usr/', r'/etc/', r'/var/', r'/home/', r'linux', r'ubuntu', r'debian'
            ],
            OperatingSystem.WINDOWS: [
                r'C:\\', r'\\Windows\\', r'\.exe$', r'windows', r'cmd\.exe', r'powershell'
            ],
            OperatingSystem.MACOS: [
                r'/Users/', r'/Applications/', r'macos', r'darwin', r'osx'
            ],
            OperatingSystem.UNIX: [
                r'/tmp/', r'unix', r'posix'
            ]
        }

        self.framework_patterns = {
            Framework.DJANGO: [
                r'django', r'models\.py', r'views\.py', r'urls\.py'
            ],
            Framework.FLASK: [
                r'flask', r'@app\.route', r'request\.', r'render_template'
            ],
            Framework.EXPRESS: [
                r'express', r'app\.get', r'app\.post', r'req\.', r'res\.'
            ],
            Framework.FASTAPI: [
                r'fastapi', r'@app\.', r'pydantic', r'async def'
            ],
            Framework.SPRING: [
                r'spring', r'@Controller', r'@Service', r'@Repository'
            ],
            Framework.RAILS: [
                r'rails', r'activerecord', r'controller', r'model'
            ]
        }

    async def analyze_server_context(self, server_id: str) -> ServerContext:
        """Extract server technology and capability context"""
        client_manager = MCPClientManager()
        connection = client_manager.connections.get(server_id)

        if not connection:
            raise ValueError(f"No connection found for server_id: {server_id}")

        # Analyze discovered tools for technology hints
        tech_stack = self._detect_technology_stack(connection.tools)

        # Analyze tool schemas for parameter types and validation patterns
        attack_surface = self._analyze_attack_surface(connection.tools)

        # Extract server metadata for additional context
        server_metadata = await self._extract_server_metadata(connection)

        # Create capabilities summary
        capabilities_summary = {
            "total_tools": len(connection.tools),
            "total_resources": len(connection.resources),
            "total_prompts": len(connection.prompts),
            "database_tools": len([t for t in connection.tools if self._is_database_tool(t)]),
            "file_tools": len([t for t in connection.tools if self._is_file_tool(t)]),
            "system_tools": len([t for t in connection.tools if self._is_system_tool(t)]),
        }

        # Assess security risk based on capabilities
        risk_assessment = self._assess_security_risk(tech_stack, attack_surface, capabilities_summary)

        return ServerContext(
            technology_stack=tech_stack,
            attack_surface=attack_surface,
            tool_schemas=connection.tools,
            server_metadata=server_metadata,
            capabilities_summary=capabilities_summary,
            risk_assessment=risk_assessment
        )

    def _detect_technology_stack(self, tools: list[dict[str, Any]]) -> TechnologyStack:
        """Infer server technology from tool names and descriptions"""

        # Combine all text content from tools for analysis
        tool_text = ""
        for tool in tools:
            tool_text += f" {tool.get('name', '')} {tool.get('description', '')}"

            # Include schema information if available
            input_schema = tool.get('inputSchema', {})
            if input_schema:
                tool_text += f" {input_schema!s}"

        tool_text = tool_text.lower()

        # Detect databases
        detected_databases = []
        for db_type, patterns in self.db_patterns.items():
            for pattern in patterns:
                if re.search(pattern, tool_text):
                    detected_databases.append(db_type)
                    break

        # Remove duplicates while preserving order
        detected_databases = list(dict.fromkeys(detected_databases))

        # Detect operating system
        detected_os = OperatingSystem.UNKNOWN
        for os_type, patterns in self.os_patterns.items():
            for pattern in patterns:
                if re.search(pattern, tool_text):
                    detected_os = os_type
                    break
            if detected_os != OperatingSystem.UNKNOWN:
                break

        # Detect frameworks
        detected_frameworks = []
        for framework_type, patterns in self.framework_patterns.items():
            for pattern in patterns:
                if re.search(pattern, tool_text):
                    detected_frameworks.append(framework_type)
                    break

        # Detect languages based on tool patterns
        detected_languages = []
        language_indicators = {
            'python': [r'\.py$', r'python', r'pip', r'virtualenv'],
            'javascript': [r'\.js$', r'node', r'npm', r'javascript'],
            'java': [r'\.java$', r'\.jar$', r'java', r'maven', r'gradle'],
            'php': [r'\.php$', r'php', r'composer'],
            'ruby': [r'\.rb$', r'ruby', r'gem', r'bundler'],
            'go': [r'\.go$', r'golang', r'go build'],
            'rust': [r'\.rs$', r'rust', r'cargo'],
            'c++': [r'\.cpp$', r'\.cc$', r'gcc', r'cmake']
        }

        for language, patterns in language_indicators.items():
            for pattern in patterns:
                if re.search(pattern, tool_text):
                    detected_languages.append(language)
                    break

        # Detect file systems
        detected_filesystems = []
        if detected_os in (OperatingSystem.LINUX, OperatingSystem.UNIX):
            detected_filesystems.extend(['ext4', 'xfs', 'btrfs'])
        elif detected_os == OperatingSystem.WINDOWS:
            detected_filesystems.extend(['ntfs', 'fat32'])
        elif detected_os == OperatingSystem.MACOS:
            detected_filesystems.extend(['apfs', 'hfs+'])

        # Detect web servers
        detected_webservers = []
        webserver_patterns = {
            'nginx': [r'nginx', r'/etc/nginx'],
            'apache': [r'apache', r'httpd', r'/etc/apache'],
            'iis': [r'iis', r'internet.*information.*services'],
            'gunicorn': [r'gunicorn', r'wsgi'],
            'uvicorn': [r'uvicorn', r'asgi']
        }

        for server, patterns in webserver_patterns.items():
            for pattern in patterns:
                if re.search(pattern, tool_text):
                    detected_webservers.append(server)
                    break

        return TechnologyStack(
            databases=detected_databases if detected_databases else [DatabaseType.UNKNOWN],
            operating_system=detected_os,
            frameworks=detected_frameworks if detected_frameworks else [Framework.UNKNOWN],
            languages=detected_languages,
            file_systems=detected_filesystems,
            web_servers=detected_webservers
        )

    def _analyze_attack_surface(self, tools: list[dict[str, Any]]) -> AttackSurface:
        """Analyze tools for potential attack vectors"""

        sql_injection_targets = []
        command_injection_targets = []
        path_traversal_targets = []
        file_manipulation_targets = []
        auth_bypass_targets = []
        info_disclosure_targets = []

        for tool in tools:
            tool_name = tool.get('name', '').lower()
            tool.get('description', '').lower()
            input_schema = tool.get('inputSchema', {})

            # SQL injection opportunities
            if self._is_database_tool(tool):
                sql_injection_targets.append({
                    'tool_name': tool.get('name'),
                    'description': tool.get('description'),
                    'vulnerable_params': self._find_vulnerable_parameters(input_schema, ['query', 'sql', 'search', 'filter', 'where']),
                    'injection_type': 'sql'
                })

            # Command injection opportunities
            if self._is_system_tool(tool):
                command_injection_targets.append({
                    'tool_name': tool.get('name'),
                    'description': tool.get('description'),
                    'vulnerable_params': self._find_vulnerable_parameters(input_schema, ['command', 'cmd', 'execute', 'run', 'shell']),
                    'injection_type': 'command'
                })

            # Path traversal opportunities
            if self._is_file_tool(tool):
                path_traversal_targets.append({
                    'tool_name': tool.get('name'),
                    'description': tool.get('description'),
                    'vulnerable_params': self._find_vulnerable_parameters(input_schema, ['path', 'file', 'filename', 'directory', 'folder']),
                    'injection_type': 'path_traversal'
                })

            # File manipulation opportunities
            if 'write' in tool_name or 'create' in tool_name or 'update' in tool_name or 'modify' in tool_name:
                file_manipulation_targets.append({
                    'tool_name': tool.get('name'),
                    'description': tool.get('description'),
                    'vulnerable_params': self._find_vulnerable_parameters(input_schema, ['content', 'data', 'body', 'text']),
                    'injection_type': 'file_manipulation'
                })

            # Authentication bypass opportunities
            if 'auth' in tool_name or 'login' in tool_name or 'token' in tool_name or 'session' in tool_name:
                auth_bypass_targets.append({
                    'tool_name': tool.get('name'),
                    'description': tool.get('description'),
                    'vulnerable_params': self._find_vulnerable_parameters(input_schema, ['username', 'password', 'token', 'credentials', 'auth']),
                    'injection_type': 'auth_bypass'
                })

            # Information disclosure opportunities
            if 'list' in tool_name or 'read' in tool_name or 'get' in tool_name or 'fetch' in tool_name:
                info_disclosure_targets.append({
                    'tool_name': tool.get('name'),
                    'description': tool.get('description'),
                    'vulnerable_params': self._find_vulnerable_parameters(input_schema, ['id', 'identifier', 'key', 'query']),
                    'injection_type': 'info_disclosure'
                })

        return AttackSurface(
            sql_injection_targets=sql_injection_targets,
            command_injection_targets=command_injection_targets,
            path_traversal_targets=path_traversal_targets,
            file_manipulation_targets=file_manipulation_targets,
            authentication_bypass_targets=auth_bypass_targets,
            information_disclosure_targets=info_disclosure_targets
        )

    async def _extract_server_metadata(self, connection) -> dict[str, Any]:
        """Extract server metadata for additional context"""
        metadata = {
            "server_url": connection.server_config.get("url", "unknown"),
            "transport": connection.server_config.get("transport", "http"),
            "oauth_enabled": connection.server_config.get("oauth", False),
            "connection_healthy": connection._is_healthy,
            "session_active": connection.session is not None
        }

        # Try to extract additional metadata from session if available
        if connection.session:
            try:
                # Get server info through MCP protocol if available
                # This would depend on what MCP methods the server supports
                metadata["mcp_protocol_version"] = "unknown"
                metadata["server_capabilities"] = {
                    "tools": len(connection.tools),
                    "resources": len(connection.resources),
                    "prompts": len(connection.prompts)
                }
            except Exception:
                # If metadata extraction fails, just use what we have
                pass

        return metadata

    def _is_database_tool(self, tool: dict[str, Any]) -> bool:
        """Check if tool interacts with databases"""
        tool_name = tool.get('name', '').lower()
        tool_desc = tool.get('description', '').lower()

        db_keywords = ['sql', 'query', 'database', 'table', 'select', 'insert', 'update', 'delete', 'mysql', 'postgres', 'sqlite']
        return any(keyword in tool_name or keyword in tool_desc for keyword in db_keywords)

    def _is_file_tool(self, tool: dict[str, Any]) -> bool:
        """Check if tool interacts with file system"""
        tool_name = tool.get('name', '').lower()
        tool_desc = tool.get('description', '').lower()

        file_keywords = ['file', 'read', 'write', 'create', 'delete', 'directory', 'folder', 'path', 'save', 'load']
        return any(keyword in tool_name or keyword in tool_desc for keyword in file_keywords)

    def _is_system_tool(self, tool: dict[str, Any]) -> bool:
        """Check if tool executes system commands"""
        tool_name = tool.get('name', '').lower()
        tool_desc = tool.get('description', '').lower()

        system_keywords = ['command', 'execute', 'run', 'shell', 'bash', 'cmd', 'system', 'process']
        return any(keyword in tool_name or keyword in tool_desc for keyword in system_keywords)

    def _find_vulnerable_parameters(self, input_schema: dict[str, Any], target_params: list[str]) -> list[str]:
        """Find parameters that might be vulnerable to injection"""
        vulnerable_params = []

        properties = input_schema.get('properties', {})
        for param_name in properties.keys():
            param_name_lower = param_name.lower()
            if any(target in param_name_lower for target in target_params):
                vulnerable_params.append(param_name)

        return vulnerable_params

    def _assess_security_risk(self, tech_stack: TechnologyStack, attack_surface: AttackSurface, capabilities: dict[str, int]) -> dict[str, str]:
        """Assess overall security risk based on analysis"""

        risk_factors = []

        # Database risk assessment
        if tech_stack.databases and tech_stack.databases[0] != DatabaseType.UNKNOWN:
            if len(attack_surface.sql_injection_targets) > 0:
                risk_factors.append("high_sql_injection_risk")

        # System command risk assessment
        if len(attack_surface.command_injection_targets) > 0:
            risk_factors.append("high_command_injection_risk")

        # File system risk assessment
        if len(attack_surface.path_traversal_targets) > 0:
            risk_factors.append("path_traversal_risk")

        # Authentication risk assessment
        if len(attack_surface.authentication_bypass_targets) > 0:
            risk_factors.append("auth_bypass_risk")

        # Information disclosure risk assessment
        if len(attack_surface.information_disclosure_targets) > 3:
            risk_factors.append("high_info_disclosure_risk")

        # Overall risk level
        overall_risk = "low"
        if len(risk_factors) >= 3:
            overall_risk = "high"
        elif len(risk_factors) >= 1:
            overall_risk = "medium"

        return {
            "overall_risk": overall_risk,
            "risk_factors": ",".join(risk_factors),
            "attack_vectors_count": str(len(attack_surface.sql_injection_targets) +
                                     len(attack_surface.command_injection_targets) +
                                     len(attack_surface.path_traversal_targets)),
            "recommendations": self._generate_security_recommendations(tech_stack, attack_surface)
        }

    def _generate_security_recommendations(self, tech_stack: TechnologyStack, attack_surface: AttackSurface) -> str:
        """Generate security recommendations based on analysis"""
        recommendations = []

        if len(attack_surface.sql_injection_targets) > 0:
            recommendations.append("Implement parameterized queries and input validation for database operations")

        if len(attack_surface.command_injection_targets) > 0:
            recommendations.append("Use input sanitization and avoid direct command execution")

        if len(attack_surface.path_traversal_targets) > 0:
            recommendations.append("Validate and sanitize file paths to prevent directory traversal")

        if len(attack_surface.authentication_bypass_targets) > 0:
            recommendations.append("Strengthen authentication mechanisms and token validation")

        if not recommendations:
            recommendations.append("Continue following security best practices")

        return "; ".join(recommendations)
