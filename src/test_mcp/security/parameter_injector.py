from dataclasses import dataclass
from typing import Any

from .context_analyzer import ServerContext
from .payload_generator import PayloadGenerator


@dataclass
class AttackVector:
    """Represents a specific attack vector for a tool parameter"""
    type: str
    target_parameter: str
    tool_name: str
    payloads: list[dict[str, Any]]
    risk_level: str
    description: str


@dataclass
class InjectionResult:
    """Result of a parameter injection attempt"""
    tool_name: str
    parameter_name: str
    payload: Any
    attack_type: str
    success: bool
    vulnerability_detected: bool
    response_indicators: list[str]
    error_messages: list[str]
    execution_time: float


class ParameterInjector:
    """Analyze tool parameters and inject context-aware attack payloads"""

    def __init__(self):
        self.payload_generator = PayloadGenerator()

        # Parameter name patterns that suggest vulnerability
        self.sensitive_parameter_patterns = {
            'sql_injection': ['query', 'sql', 'search', 'filter', 'where', 'select', 'table'],
            'command_injection': ['command', 'cmd', 'execute', 'run', 'shell', 'bash', 'system'],
            'path_traversal': ['path', 'file', 'filename', 'directory', 'folder', 'location'],
            'code_injection': ['code', 'script', 'eval', 'expression', 'function'],
            'template_injection': ['template', 'render', 'format', 'content', 'body'],
            'ldap_injection': ['dn', 'filter', 'ldap', 'directory'],
            'xpath_injection': ['xpath', 'xml', 'node', 'element'],
            'nosql_injection': ['mongo', 'collection', 'document', 'find', 'match']
        }

        # Response patterns that indicate successful injection
        self.vulnerability_indicators = {
            'sql_injection': [
                r'sql.*error', r'mysql.*error', r'ora-\d+', r'microsoft.*oledb',
                r'syntax.*error.*near', r'quoted.*string.*not.*terminated',
                r'column.*count.*doesn.*match', r'union.*select'
            ],
            'command_injection': [
                r'command.*not.*found', r'sh:.*command.*not.*found',
                r'uid=\d+', r'gid=\d+', r'groups=\d+',  # Unix id command output
                r'volume.*serial.*number', r'directory.*of.*c:',  # Windows dir output
                r'/bin/sh', r'/bin/bash', r'permission.*denied'
            ],
            'path_traversal': [
                r'root:.*:0:0:', r'\[boot loader\]', r'\[operating systems\]',  # passwd, boot.ini
                r'file.*not.*found', r'directory.*not.*found', r'access.*denied',
                r'no such file or directory', r'permission.*denied'
            ],
            'template_injection': [
                r'49', r'7777777', r'64',  # Common math results: 7*7, 7*7*7*7*7*7*7, 8*8
                r'templatenotfound', r'undefined.*variable', r'syntax.*error.*template'
            ],
            'code_injection': [
                r'eval.*error', r'compile.*error', r'syntax.*error',
                r'undefined.*function', r'cannot.*import', r'module.*not.*found'
            ]
        }

    def analyze_parameter_attack_surface(self, tool: dict[str, Any]) -> list[AttackVector]:
        """Analyze tool schema for injection opportunities"""
        attack_vectors: list[AttackVector] = []

        tool_name = tool.get('name', 'unknown_tool')
        input_schema = tool.get('inputSchema', {})

        if not input_schema or not isinstance(input_schema, dict):
            return attack_vectors

        properties = input_schema.get('properties', {})
        required_params = input_schema.get('required', [])

        for param_name, param_schema in properties.items():
            if not isinstance(param_schema, dict):
                continue

            param_type = param_schema.get('type', 'string')
            param_description = param_schema.get('description', '')
            is_required = param_name in required_params

            # Analyze parameter for various injection types
            injection_types = self._identify_injection_types(param_name, param_description)

            for injection_type in injection_types:
                # Generate appropriate payloads for this injection type
                payloads = self._generate_parameter_payloads(param_name, param_type, injection_type)

                if payloads:
                    # Assess risk level based on parameter characteristics
                    risk_level = self._assess_parameter_risk(
                        param_name, param_type, injection_type, is_required
                    )

                    attack_vector = AttackVector(
                        type=injection_type,
                        target_parameter=param_name,
                        tool_name=tool_name,
                        payloads=payloads,
                        risk_level=risk_level,
                        description=f"{injection_type} via {param_name} parameter in {tool_name}"
                    )
                    attack_vectors.append(attack_vector)

            # Check for parameter name injection opportunities
            if self._is_sensitive_parameter_name(param_name):
                name_payloads = self._generate_param_name_payloads()
                if name_payloads:
                    attack_vectors.append(AttackVector(
                        type="parameter_name_injection",
                        target_parameter=param_name,
                        tool_name=tool_name,
                        payloads=name_payloads,
                        risk_level="medium",
                        description=f"Parameter name injection targeting {param_name}"
                    ))

            # Check for type confusion opportunities
            if param_type in ["string", "object"]:
                type_payloads = self._generate_type_confusion_payloads(param_type)
                if type_payloads:
                    attack_vectors.append(AttackVector(
                        type="type_confusion",
                        target_parameter=param_name,
                        tool_name=tool_name,
                        payloads=type_payloads,
                        risk_level="medium",
                        description=f"Type confusion attack via {param_name}"
                    ))

        return attack_vectors

    def inject_targeted_payloads(
        self,
        tool: dict[str, Any],
        context: ServerContext,
        max_payloads_per_param: int = 3
    ) -> list[dict[str, Any]]:
        """Generate targeted injection payloads for a specific tool"""

        injection_attempts = []
        attack_vectors = self.analyze_parameter_attack_surface(tool)

        # Generate context-aware payloads using PayloadGenerator
        context_payloads = self.payload_generator.generate_context_aware_payloads(context)
        tool_specific_payloads = self.payload_generator.generate_tool_specific_payloads(tool, context)

        # Prioritize attack vectors by risk level
        high_risk_vectors = [v for v in attack_vectors if v.risk_level == "high"]
        medium_risk_vectors = [v for v in attack_vectors if v.risk_level == "medium"]
        low_risk_vectors = [v for v in attack_vectors if v.risk_level == "low"]

        prioritized_vectors = high_risk_vectors + medium_risk_vectors + low_risk_vectors

        for vector in prioritized_vectors:
            # Combine vector-specific payloads with context-aware payloads
            all_payloads = vector.payloads[:]

            # Add relevant context-aware payloads
            if vector.type == "sql_injection" and "sql_injection" in context_payloads:
                all_payloads.extend(context_payloads["sql_injection"][:2])
            elif vector.type == "command_injection" and "command_injection" in context_payloads:
                all_payloads.extend(context_payloads["command_injection"][:2])
            elif vector.type == "path_traversal" and "path_traversal" in context_payloads:
                all_payloads.extend(context_payloads["path_traversal"][:2])

            # Add tool-specific payloads that match this parameter
            matching_tool_payloads = [
                p for p in tool_specific_payloads
                if p.get("parameter") == vector.target_parameter
                and p.get("attack_type") == vector.type
            ]
            all_payloads.extend(matching_tool_payloads[:2])

            # Limit payloads per parameter to avoid overwhelming
            selected_payloads = all_payloads[:max_payloads_per_param]

            for payload_info in selected_payloads:
                injection_attempt = {
                    "tool_name": vector.tool_name,
                    "parameter_name": vector.target_parameter,
                    "attack_type": vector.type,
                    "payload": payload_info.get("payload"),
                    "description": payload_info.get("description", "Targeted injection"),
                    "severity": payload_info.get("severity", "medium"),
                    "risk_level": vector.risk_level,
                    "expected_indicators": self.vulnerability_indicators.get(vector.type, [])
                }
                injection_attempts.append(injection_attempt)

        return injection_attempts

    def _identify_injection_types(self, param_name: str, param_description: str) -> list[str]:
        """Identify potential injection types for a parameter"""
        injection_types = []

        combined_text = f"{param_name} {param_description}".lower()

        for injection_type, patterns in self.sensitive_parameter_patterns.items():
            for pattern in patterns:
                if pattern in combined_text:
                    injection_types.append(injection_type)
                    break

        # Always include generic injection types for comprehensive testing
        if not injection_types:
            injection_types = ["generic_injection"]

        return injection_types

    def _generate_parameter_payloads(
        self, param_name: str, param_type: str, injection_type: str
    ) -> list[dict[str, Any]]:
        """Generate payloads specific to parameter type and injection type"""

        payloads = []

        if injection_type == "sql_injection":
            payloads = [
                {"payload": "'; DROP TABLE test; --", "description": "SQL injection test", "severity": "high"},
                {"payload": "' OR 1=1 --", "description": "Boolean-based SQL injection", "severity": "high"},
                {"payload": "' UNION SELECT version() --", "description": "Union-based SQL injection", "severity": "medium"}
            ]

        elif injection_type == "command_injection":
            payloads = [
                {"payload": "; echo 'cmd_injection_test'", "description": "Command injection test", "severity": "high"},
                {"payload": "| whoami", "description": "Pipe-based command injection", "severity": "high"},
                {"payload": "`id`", "description": "Backtick command execution", "severity": "high"}
            ]

        elif injection_type == "path_traversal":
            payloads = [
                {"payload": "../../../etc/passwd", "description": "Path traversal test", "severity": "medium"},
                {"payload": "....//....//etc/passwd", "description": "Double encoding traversal", "severity": "medium"},
                {"payload": "/etc/passwd%00.txt", "description": "Null byte injection", "severity": "medium"}
            ]

        elif injection_type == "template_injection":
            payloads = [
                {"payload": "{{7*7}}", "description": "Template injection test", "severity": "high"},
                {"payload": "${7*7}", "description": "Expression injection test", "severity": "high"},
                {"payload": "#{7*7}", "description": "Ruby template injection", "severity": "high"}
            ]

        elif injection_type == "code_injection":
            payloads = [
                {"payload": "__import__('os').system('id')", "description": "Python code injection", "severity": "critical"},
                {"payload": "eval('1+1')", "description": "Generic code injection", "severity": "high"},
                {"payload": "exec('import sys; print(sys.version)')", "description": "Code execution test", "severity": "critical"}
            ]

        elif injection_type == "ldap_injection":
            payloads = [
                {"payload": "*)(&(objectClass=*", "description": "LDAP injection test", "severity": "medium"},
                {"payload": "admin)(&(password=*))", "description": "LDAP authentication bypass", "severity": "high"}
            ]

        elif injection_type == "xpath_injection":
            payloads = [
                {"payload": "' or '1'='1", "description": "XPath injection test", "severity": "medium"},
                {"payload": "'] | //user[contains(username,'admin') | //user['", "description": "XPath traversal", "severity": "medium"}
            ]

        elif injection_type == "nosql_injection":
            payloads = [
                {"payload": '{"$ne": null}', "description": "NoSQL not-equals injection", "severity": "high"},
                {"payload": '{"$regex": ".*"}', "description": "NoSQL regex injection", "severity": "medium"},
                {"payload": '{"$where": "function() { return true; }"}', "description": "NoSQL JavaScript injection", "severity": "critical"}
            ]

        else:  # generic_injection
            payloads = [
                {"payload": "'; DROP TABLE test; --", "description": "Generic SQL test", "severity": "medium"},
                {"payload": "; echo 'test'", "description": "Generic command test", "severity": "medium"},
                {"payload": "../../../etc/passwd", "description": "Generic path traversal", "severity": "low"}
            ]

        return payloads

    def _is_sensitive_parameter_name(self, param_name: str) -> bool:
        """Check if parameter name itself suggests vulnerability"""
        sensitive_names = [
            'query', 'sql', 'command', 'cmd', 'path', 'file', 'code', 'script',
            'template', 'eval', 'exec', 'system', 'shell', 'filter', 'search'
        ]

        param_lower = param_name.lower()
        return any(sensitive in param_lower for sensitive in sensitive_names)

    def _generate_param_name_payloads(self) -> list[dict[str, Any]]:
        """Generate payloads for parameter name injection attacks"""
        return [
            {"payload": '{"__proto__": {"isAdmin": true}}', "description": "Prototype pollution via parameter name", "severity": "high"},
            {"payload": '{"constructor": {"prototype": {"isAdmin": true}}}', "description": "Constructor pollution", "severity": "high"},
            {"payload": "../../../secret", "description": "Parameter name traversal", "severity": "medium"}
        ]

    def _generate_type_confusion_payloads(self, expected_type: str) -> list[dict[str, Any]]:
        """Generate payloads to test for type confusion vulnerabilities"""
        payloads: list[dict[str, Any]] = []

        if expected_type == "string":
            payloads = [
                {"payload": 12345, "description": "Integer instead of string", "severity": "medium"},
                {"payload": ["array", "value"], "description": "Array instead of string", "severity": "medium"},
                {"payload": {"object": "value"}, "description": "Object instead of string", "severity": "medium"},
                {"payload": True, "description": "Boolean instead of string", "severity": "low"},
                {"payload": None, "description": "Null instead of string", "severity": "low"}
            ]
        elif expected_type == "object":
            payloads = [
                {"payload": "string_value", "description": "String instead of object", "severity": "medium"},
                {"payload": 12345, "description": "Integer instead of object", "severity": "medium"},
                {"payload": ["array", "value"], "description": "Array instead of object", "severity": "medium"}
            ]
        elif expected_type == "array":
            payloads = [
                {"payload": "string_value", "description": "String instead of array", "severity": "medium"},
                {"payload": {"object": "value"}, "description": "Object instead of array", "severity": "medium"},
                {"payload": 12345, "description": "Integer instead of array", "severity": "medium"}
            ]

        return payloads

    def _assess_parameter_risk(
        self, param_name: str, param_type: str, injection_type: str, is_required: bool
    ) -> str:
        """Assess risk level for parameter injection"""

        risk_score = 0

        # Base risk by injection type
        high_risk_types = ["sql_injection", "command_injection", "code_injection"]
        medium_risk_types = ["template_injection", "path_traversal", "nosql_injection"]

        if injection_type in high_risk_types:
            risk_score += 3
        elif injection_type in medium_risk_types:
            risk_score += 2
        else:
            risk_score += 1

        # Additional risk factors
        if is_required:
            risk_score += 1

        if self._is_sensitive_parameter_name(param_name):
            risk_score += 1

        # Convert score to risk level
        if risk_score >= 4:
            return "high"
        elif risk_score >= 2:
            return "medium"
        else:
            return "low"

    def analyze_injection_response(
        self, response: Any, attack_type: str, payload: Any
    ) -> dict[str, Any]:
        """Analyze response for signs of successful injection"""

        analysis: dict[str, Any] = {
            "vulnerability_detected": False,
            "indicators_found": [],
            "confidence_level": "low",
            "response_analysis": {}
        }

        if not response:
            return analysis

        response_text = str(response).lower()

        # Check for vulnerability indicators specific to attack type
        indicators = self.vulnerability_indicators.get(attack_type, [])

        import re
        for pattern in indicators:
            if re.search(pattern, response_text):
                analysis["indicators_found"].append(pattern)
                analysis["vulnerability_detected"] = True

        # Assess confidence level based on number of indicators
        indicator_count = len(analysis["indicators_found"])
        if indicator_count >= 2:
            analysis["confidence_level"] = "high"
        elif indicator_count >= 1:
            analysis["confidence_level"] = "medium"

        # Additional response analysis
        analysis["response_analysis"] = {
            "response_length": len(str(response)),
            "contains_error": "error" in response_text,
            "contains_warning": "warning" in response_text,
            "response_type": type(response).__name__
        }

        return analysis

    def generate_comprehensive_injection_test_suite(
        self, tools: list[dict[str, Any]], context: ServerContext
    ) -> dict[str, list[dict[str, Any]]]:
        """Generate comprehensive injection test suite for all tools"""

        test_suite: dict[str, list[dict[str, Any]]] = {
            "high_priority_tests": [],
            "medium_priority_tests": [],
            "low_priority_tests": [],
            "type_confusion_tests": [],
            "parameter_name_tests": []
        }

        for tool in tools:
            injection_attempts = self.inject_targeted_payloads(tool, context)

            for attempt in injection_attempts:
                risk_level = attempt.get("risk_level", "low")

                if risk_level == "high":
                    test_suite["high_priority_tests"].append(attempt)
                elif risk_level == "medium":
                    test_suite["medium_priority_tests"].append(attempt)
                else:
                    test_suite["low_priority_tests"].append(attempt)

                # Categorize special test types
                if attempt.get("attack_type") == "type_confusion":
                    test_suite["type_confusion_tests"].append(attempt)
                elif attempt.get("attack_type") == "parameter_name_injection":
                    test_suite["parameter_name_tests"].append(attempt)

        return test_suite
