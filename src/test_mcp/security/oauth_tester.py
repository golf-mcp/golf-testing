from datetime import datetime
from typing import Any
from uuid import uuid4

import httpx
from pydantic import BaseModel, Field

from ..shared.progress_tracker import ProgressTracker, TestStatus
from ..shared.result_models import BaseTestResult, ErrorType, TestType
from .connection_manipulator import ConnectionManipulator
from .jwt_security_tester import JWTSecurityTester
from .oauth_security_scanner import OAuthSecurityScanner
from .session_manager import SessionLifecycleManager
from .token_extractor import TokenExtractor


class AuthTestResult(BaseTestResult):
    """Result of OAuth/auth testing (extends BaseTestResult)"""

    test_type: TestType = Field(
        default=TestType.SECURITY, description="Test type identifier"
    )

    # Auth-specific fields
    auth_method: str = Field(..., description="Authentication method tested")
    bypass_attempted: str = Field(..., description="Bypass method attempted")
    bypass_successful: bool = Field(
        default=False, description="Whether bypass was successful"
    )
    access_granted: bool = Field(
        default=False, description="Whether access was improperly granted"
    )
    vulnerability_severity: str = Field(
        default="low", description="Severity: low, medium, high, critical"
    )


class AuthSecurityReport(BaseModel):
    """OAuth and authentication security report"""

    server_name: str
    server_url: str
    test_timestamp: datetime
    overall_auth_score: float = Field(ge=0.0, le=100.0)

    total_auth_tests: int
    passed_auth_tests: int
    bypasses_detected: int
    critical_auth_issues: int
    high_auth_issues: int
    medium_auth_issues: int
    low_auth_issues: int

    test_results: list[AuthTestResult] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)


class OAuthTester:
    """OAuth and authentication security testing using HTTP client approach"""

    def __init__(
        self,
        server_config: dict[str, Any],
        progress_tracker: ProgressTracker | None = None,
    ):
        self.server_config = server_config
        server_url = server_config.get("url")
        if not server_url:
            raise ValueError("Server URL is required for OAuth testing")
        self.server_url = str(server_url)
        self.progress_tracker = progress_tracker

    async def run_oauth_tests(
        self, categories: list[str] | None = None
    ) -> list[AuthTestResult]:
        """Run OAuth and authentication tests"""
        results = []

        try:
            # Run token validation tests
            if not categories or "token_validation" in categories:
                results.extend(await self._run_token_validation_tests())

            # Run authentication bypass tests
            if not categories or "auth_bypass" in categories:
                results.extend(await self._run_auth_bypass_tests())

            # Run session management tests
            if not categories or "session_management" in categories:
                results.extend(await self._run_session_management_tests())

        except Exception as e:
            # Add a failure result if the entire assessment fails
            test_id = str(uuid4())
            results.append(
                AuthTestResult(
                    test_id=test_id,
                    auth_method="oauth_testing_setup",
                    bypass_attempted="test_setup",
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    duration=0.0,
                    status=TestStatus.FAILED,
                    success=False,
                    bypass_successful=False,
                    access_granted=False,
                    vulnerability_severity="high",
                    error_message=str(e),
                    error_type=ErrorType.EXECUTION,
                )
            )

        return results

    async def _get_test_tokens(self) -> list[dict[str, str]]:
        """Get tokens for testing - prefer real tokens over hardcoded"""
        test_tokens = []

        # Try to get real tokens first
        extractor = TokenExtractor()
        real_tokens = await extractor.get_real_tokens(self.server_url)

        if real_tokens:
            # Create manipulated versions of real tokens
            test_tokens.extend(extractor.create_manipulated_tokens(real_tokens))

        # Always include hardcoded fallback tokens
        fallback_tokens = [
            {"token": "invalid_token_123", "description": "Invalid token format"},
            {"token": "expired_token_456", "description": "Expired token"},
            {"token": "", "description": "Empty token"},
            {"token": "malformed.token.here", "description": "Malformed JWT"},
            {
                "token": "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.invalid",
                "description": "Invalid JWT payload",
            },
        ]
        test_tokens.extend(fallback_tokens)

        return test_tokens

    async def _run_token_validation_tests(self) -> list[AuthTestResult]:
        """Test OAuth token validation"""
        results = []

        # Test with invalid tokens (prefer real token manipulation over hardcoded)
        invalid_tokens = await self._get_test_tokens()

        for token_info in invalid_tokens:
            result = await self._test_token_access(
                token_info["token"], token_info["description"]
            )
            results.append(result)

        return results

    async def _test_token_access(self, token: str, description: str) -> AuthTestResult:
        """Test access with specific token"""
        test_id = str(uuid4())
        start_time = datetime.now()

        if self.progress_tracker:
            self.progress_tracker.update_test_status(
                test_id,
                TestType.SECURITY,
                TestStatus.RUNNING,
                step_description=f"Testing token: {description}",
            )

        try:
            # Test token by making authenticated requests
            bypass_successful = False
            access_granted = False
            evidence = []

            async with httpx.AsyncClient(timeout=10.0) as client:
                # Test different authentication header formats
                auth_headers_to_test = [
                    {"Authorization": f"Bearer {token}"},
                    {"Authorization": f"Token {token}"},
                    {"X-Auth-Token": token},
                    {"X-API-Key": token},
                ]

                for headers in auth_headers_to_test:
                    try:
                        # Try to access a protected endpoint
                        response = await client.get(self.server_url, headers=headers)

                        # Check if invalid token was accepted (vulnerability)
                        if response.status_code == 200 and token in [
                            "invalid_token_123",
                            "expired_token_456",
                            "",
                            "malformed.token.here",
                        ]:
                            bypass_successful = True
                            access_granted = True
                            evidence.append(
                                f"Invalid token {token[:10]}... granted access with {response.status_code}"
                            )
                        elif response.status_code in [401, 403]:
                            evidence.append(
                                f"Token properly rejected: {response.status_code}"
                            )
                        else:
                            evidence.append(f"Token response: {response.status_code}")

                    except Exception as e:
                        evidence.append(f"Request failed: {str(e)[:50]}")

            return AuthTestResult(
                test_id=test_id,
                auth_method="oauth_token",
                bypass_attempted=f"Invalid token test: {description}",
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.COMPLETED,
                success=not bypass_successful,  # Success means no bypass
                bypass_successful=bypass_successful,
                access_granted=access_granted,
                vulnerability_severity="high" if bypass_successful else "low",
            )

        except Exception as e:
            return AuthTestResult(
                test_id=test_id,
                auth_method="oauth_token",
                bypass_attempted=f"Token test: {description}",
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.FAILED,
                success=False,
                bypass_successful=False,
                access_granted=False,
                vulnerability_severity="medium",
                error_message=str(e),
                error_type=ErrorType.EXECUTION,
            )

    async def _run_auth_bypass_tests(self) -> list[AuthTestResult]:
        """Test authentication bypass attempts"""
        results = []

        bypass_methods = [
            {"method": "no_auth_header", "description": "No authentication header"},
            {
                "method": "malformed_auth_header",
                "description": "Malformed authorization header",
            },
            {
                "method": "wrong_auth_scheme",
                "description": "Wrong authentication scheme",
            },
            {"method": "admin_bypass_attempt", "description": "Admin bypass attempt"},
            {"method": "sql_injection_auth", "description": "SQL injection in auth"},
            {"method": "header_injection", "description": "Header injection attack"},
        ]

        for method_info in bypass_methods:
            result = await self._test_auth_bypass(
                method_info["method"], method_info["description"]
            )
            results.append(result)

        return results

    async def _test_auth_bypass(self, method: str, description: str) -> AuthTestResult:
        """Test specific auth bypass method"""
        test_id = str(uuid4())
        start_time = datetime.now()

        if self.progress_tracker:
            self.progress_tracker.update_test_status(
                test_id,
                TestType.SECURITY,
                TestStatus.RUNNING,
                step_description=f"Testing bypass: {description}",
            )

        try:
            bypass_successful = False
            access_granted = False
            evidence = []

            async with httpx.AsyncClient(timeout=10.0) as client:
                if method == "no_auth_header":
                    # Test access without any authentication
                    response = await client.get(self.server_url)
                    if response.status_code == 200:
                        bypass_successful = True
                        access_granted = True
                        evidence.append(
                            f"Access granted without authentication: {response.status_code}"
                        )
                    else:
                        evidence.append(
                            f"Properly rejected request without auth: {response.status_code}"
                        )

                elif method == "malformed_auth_header":
                    # Test malformed authorization headers
                    malformed_headers = [
                        {"Authorization": "Bearer "},  # Empty token
                        {"Authorization": "InvalidScheme token"},  # Invalid scheme
                        {"Authorization": "Bearer" + "A" * 1000},  # Very long token
                        {"Authorization": "Bearer NULL"},  # NULL token
                    ]

                    for headers in malformed_headers:
                        response = await client.get(self.server_url, headers=headers)
                        if response.status_code == 200:
                            bypass_successful = True
                            access_granted = True
                            evidence.append(
                                f"Malformed auth header granted access: {headers}"
                            )
                        else:
                            evidence.append(
                                f"Malformed header properly rejected: {response.status_code}"
                            )

                elif method == "wrong_auth_scheme":
                    # Test wrong authentication schemes
                    wrong_schemes = [
                        {
                            "Authorization": "Basic dXNlcjpwYXNz"
                        },  # Basic instead of Bearer
                        {"Authorization": "Digest username='admin'"},  # Digest
                        {"Authorization": "Custom token123"},  # Custom scheme
                    ]

                    for headers in wrong_schemes:
                        response = await client.get(self.server_url, headers=headers)
                        if response.status_code == 200:
                            bypass_successful = True
                            access_granted = True
                            evidence.append(
                                f"Wrong auth scheme granted access: {headers}"
                            )

                elif method == "admin_bypass_attempt":
                    # Test common admin bypass attempts
                    bypass_attempts = [
                        {"X-User-Role": "admin"},
                        {"X-Admin": "true"},
                        {"X-Bypass": "admin"},
                        {"X-Forwarded-User": "admin"},
                    ]

                    for headers in bypass_attempts:
                        response = await client.get(self.server_url, headers=headers)
                        if response.status_code == 200:
                            bypass_successful = True
                            access_granted = True
                            evidence.append(f"Admin bypass successful: {headers}")

                elif method == "sql_injection_auth":
                    # Test SQL injection in auth fields
                    injection_tokens = [
                        "' OR '1'='1",
                        "admin'--",
                        "'; DROP TABLE users; --",
                    ]

                    for token in injection_tokens:
                        headers = {"Authorization": f"Bearer {token}"}
                        response = await client.get(self.server_url, headers=headers)
                        response_text = response.text.lower()

                        # Look for SQL error indicators
                        sql_indicators = ["sql", "syntax error", "mysql", "database"]
                        if any(
                            indicator in response_text for indicator in sql_indicators
                        ):
                            bypass_successful = True
                            evidence.append(f"SQL injection in auth detected: {token}")

                elif method == "header_injection":
                    # Test header injection attacks
                    injection_headers = [
                        {"Authorization": "Bearer token\r\nX-Injected: true"},
                        {"Authorization": "Bearer token\nX-Admin: true"},
                    ]

                    for headers in injection_headers:
                        try:
                            response = await client.get(
                                self.server_url, headers=headers
                            )
                            if response.status_code == 200:
                                bypass_successful = True
                                evidence.append("Header injection bypass successful")
                        except Exception:
                            evidence.append("Header injection properly blocked")

            return AuthTestResult(
                test_id=test_id,
                auth_method="auth_bypass",
                bypass_attempted=description,
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.COMPLETED,
                success=not bypass_successful,
                bypass_successful=bypass_successful,
                access_granted=access_granted,
                vulnerability_severity="critical" if bypass_successful else "low",
            )

        except Exception as e:
            return AuthTestResult(
                test_id=test_id,
                auth_method="auth_bypass",
                bypass_attempted=description,
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.FAILED,
                success=False,
                bypass_successful=False,
                access_granted=False,
                vulnerability_severity="medium",
                error_message=str(e),
                error_type=ErrorType.EXECUTION,
            )

    async def _run_session_management_tests(self) -> list[AuthTestResult]:
        """Test session management security using real MCP session lifecycle testing"""
        results = []

        # Test session replay attacks using real MCP session lifecycles
        replay_results = await self._test_session_replay_attacks()
        results.extend(replay_results)

        # Test session timeout with dynamic session testing (fallback to static if needed)
        timeout_result = await self._test_session_timeout()
        results.append(timeout_result)

        # Test session fixation
        fixation_result = await self._test_session_fixation()
        results.append(fixation_result)

        return results

    async def _test_session_replay_attacks(self) -> list[AuthTestResult]:
        """Test session replay with real session lifecycles"""
        session_manager = SessionLifecycleManager()
        results = []

        try:
            # Capture real session establishment
            session_capture = await session_manager.capture_session_establishment(
                self.server_config
            )

            # Test session ID reuse across connections
            replay_result = await session_manager.replay_session_attack(session_capture)
            results.append(
                self._convert_replay_to_auth_result(replay_result, "session_replay")
            )

            # Test cross-client session contamination
            contamination_result = await session_manager.test_session_contamination(
                session_capture
            )
            results.append(
                self._convert_replay_to_auth_result(
                    contamination_result, "session_contamination"
                )
            )

            # Test connection hijacking using ConnectionManipulator
            connection_manipulator = ConnectionManipulator()
            hijack_result = await connection_manipulator.test_connection_hijacking(
                session_capture.server_id, session_capture.server_config
            )
            results.append(
                self._convert_security_to_auth_result(
                    hijack_result, "connection_hijacking"
                )
            )

            # Test session fixation using real session patterns
            fixation_result = await connection_manipulator.test_session_fixation(
                session_capture
            )
            results.append(
                self._convert_security_to_auth_result(
                    fixation_result, "session_fixation_dynamic"
                )
            )

        except Exception as e:
            # Fallback to legacy session hijacking test if dynamic testing fails
            legacy_result = await self._test_session_hijacking_legacy()
            # Add error context to the legacy result
            legacy_result.error_message = (
                f"Dynamic session testing failed: {str(e)[:100]}"
            )
            results.append(legacy_result)

        return results

    def _convert_replay_to_auth_result(
        self, replay_result, attack_type: str
    ) -> AuthTestResult:
        """Convert ReplayResult to AuthTestResult for consistency"""
        return AuthTestResult(
            test_id=replay_result.test_id,
            auth_method="session_management",
            bypass_attempted=f"{attack_type}: {replay_result.attack_type}",
            start_time=replay_result.timestamp,
            end_time=replay_result.timestamp,
            duration=0.1,  # Placeholder duration
            status=TestStatus.COMPLETED if replay_result.success else TestStatus.FAILED,
            success=replay_result.success,
            bypass_successful=replay_result.vulnerability_detected,
            access_granted=replay_result.vulnerability_detected,
            vulnerability_severity="high"
            if replay_result.vulnerability_detected
            else "low",
        )

    def _convert_security_to_auth_result(
        self, security_result, attack_type: str
    ) -> AuthTestResult:
        """Convert SecurityResult to AuthTestResult for consistency"""
        return AuthTestResult(
            test_id=security_result.test_id,
            auth_method="session_management",
            bypass_attempted=f"{attack_type}: {security_result.attack_type}",
            start_time=security_result.start_time,
            end_time=security_result.end_time,
            duration=security_result.duration,
            status=security_result.status,
            success=security_result.success,
            bypass_successful=security_result.vulnerability_detected,
            access_granted=security_result.vulnerability_detected,
            vulnerability_severity=security_result.severity,
            error_message=security_result.error_message,
        )

    async def _test_session_hijacking_legacy(self) -> AuthTestResult:
        """Legacy session hijacking test (fallback)"""
        test_id = str(uuid4())
        start_time = datetime.now()

        try:
            bypass_successful = False
            evidence = []

            # Fallback to static tokens when dynamic testing fails
            async with httpx.AsyncClient(timeout=10.0) as client:
                session_tokens = [
                    "session_token_123",
                    "SESSIONID=abc123",
                    "auth_session=xyz789",
                ]

                for token in session_tokens:
                    hijack_headers = {
                        "Cookie": token,
                        "User-Agent": "AttackerAgent/1.0",
                        "X-Forwarded-For": "192.168.1.100",
                    }

                    response = await client.get(self.server_url, headers=hijack_headers)

                    if response.status_code == 200:
                        response_text = response.text
                        if (
                            "welcome" in response_text.lower()
                            or "dashboard" in response_text.lower()
                        ):
                            bypass_successful = True
                            evidence.append(
                                f"Session hijacking possible with token: {token[:10]}..."
                            )
                    else:
                        evidence.append(
                            f"Session properly validated: {response.status_code}"
                        )

            return AuthTestResult(
                test_id=test_id,
                auth_method="session_management",
                bypass_attempted="session_hijacking_legacy",
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.COMPLETED,
                success=not bypass_successful,
                bypass_successful=bypass_successful,
                access_granted=bypass_successful,
                vulnerability_severity="high" if bypass_successful else "low",
            )

        except Exception as e:
            return AuthTestResult(
                test_id=test_id,
                auth_method="session_management",
                bypass_attempted="session_hijacking_legacy",
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.FAILED,
                success=False,
                bypass_successful=False,
                access_granted=False,
                vulnerability_severity="medium",
                error_message=str(e),
                error_type=ErrorType.EXECUTION,
            )

    async def _test_session_timeout(self) -> AuthTestResult:
        """Test session timeout enforcement"""
        test_id = str(uuid4())
        start_time = datetime.now()

        try:
            # Test session timeout by simulating old session tokens
            bypass_successful = False
            evidence = []

            async with httpx.AsyncClient(timeout=15.0) as client:
                # Try to get real tokens first, then create expired versions
                extractor = TokenExtractor()
                real_tokens = await extractor.get_real_tokens(self.server_url)

                if real_tokens and real_tokens.get("access_token"):
                    # Create expired version of real token
                    expired_token = extractor.create_expired_token(
                        real_tokens["access_token"]
                    )
                    old_session_headers = {
                        "Authorization": f"Bearer {expired_token}",
                        "Cookie": f"session=expired_{real_tokens['access_token'][:10]}",
                    }
                    evidence.append(
                        "Using expired version of real token for timeout test"
                    )
                else:
                    # Fallback to mock old session tokens when no real tokens available
                    old_session_headers = {
                        "Cookie": "session=old_session_token_from_yesterday",
                        "Authorization": "Bearer expired_token_12345",
                    }
                    evidence.append("Using hardcoded expired tokens (fallback)")

                response = await client.get(
                    self.server_url, headers=old_session_headers
                )

                if response.status_code == 200:
                    bypass_successful = True
                    evidence.append(
                        "Session timeout not enforced - old session accepted"
                    )
                elif response.status_code in [401, 403]:
                    evidence.append("Session timeout properly enforced")
                else:
                    evidence.append(
                        f"Unexpected session timeout response: {response.status_code}"
                    )

            return AuthTestResult(
                test_id=test_id,
                auth_method="session_management",
                bypass_attempted="session_timeout_bypass",
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.COMPLETED,
                success=not bypass_successful,
                bypass_successful=bypass_successful,
                access_granted=bypass_successful,
                vulnerability_severity="medium" if bypass_successful else "low",
            )

        except Exception as e:
            return AuthTestResult(
                test_id=test_id,
                auth_method="session_management",
                bypass_attempted="session_timeout_bypass",
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.FAILED,
                success=False,
                bypass_successful=False,
                access_granted=False,
                vulnerability_severity="medium",
                error_message=str(e),
                error_type=ErrorType.EXECUTION,
            )

    async def _test_session_fixation(self) -> AuthTestResult:
        """Test session fixation vulnerability"""
        test_id = str(uuid4())
        start_time = datetime.now()

        try:
            # Test session fixation by providing predetermined session ID
            bypass_successful = False
            evidence = []

            async with httpx.AsyncClient(timeout=10.0) as client:
                # Try to fixate a session ID
                fixated_sessions = [
                    "PHPSESSID=attacker_controlled_session",
                    "session_id=fixed_session_12345",
                    "JSESSIONID=ATTACKER_SESSION_ID",
                ]

                for session in fixated_sessions:
                    headers = {
                        "Cookie": session,
                        "X-Session-Fixation": "true",  # Test header
                    }

                    response = await client.get(self.server_url, headers=headers)

                    # Check if the server accepts the predetermined session
                    if response.status_code == 200:
                        # Look for session acceptance indicators
                        set_cookie = response.headers.get("set-cookie", "")
                        if session.split("=")[1] in set_cookie:
                            bypass_successful = True
                            evidence.append(f"Session fixation possible: {session}")
                    else:
                        evidence.append(
                            f"Session fixation properly prevented: {response.status_code}"
                        )

            return AuthTestResult(
                test_id=test_id,
                auth_method="session_management",
                bypass_attempted="session_fixation",
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.COMPLETED,
                success=not bypass_successful,
                bypass_successful=bypass_successful,
                access_granted=bypass_successful,
                vulnerability_severity="high" if bypass_successful else "low",
            )

        except Exception as e:
            return AuthTestResult(
                test_id=test_id,
                auth_method="session_management",
                bypass_attempted="session_fixation",
                start_time=start_time,
                end_time=datetime.now(),
                duration=(datetime.now() - start_time).total_seconds(),
                status=TestStatus.FAILED,
                success=False,
                bypass_successful=False,
                access_granted=False,
                vulnerability_severity="medium",
                error_message=str(e),
                error_type=ErrorType.EXECUTION,
            )

    async def test_oauth_security_vulnerabilities(self) -> list[AuthTestResult]:
        """Test for OAuth security vulnerabilities and bypass techniques"""
        scanner = OAuthSecurityScanner(self.server_url)
        jwt_tester = JWTSecurityTester(self.server_url)
        results = []

        try:
            # Test resource indicator security bypass
            resource_bypass = await scanner.test_resource_indicator_bypass(self.server_config)
            results.append(
                self._convert_security_to_auth_result(resource_bypass, "resource_indicator_bypass")
            )

            # Test metadata injection attacks
            metadata_injection = await scanner.test_metadata_injection_attacks(self.server_url)
            results.append(
                self._convert_security_to_auth_result(metadata_injection, "metadata_injection")
            )

            # Test PKCE bypass attacks
            pkce_bypass = await scanner.test_pkce_bypass_attacks(self.server_config)
            results.append(
                self._convert_security_to_auth_result(pkce_bypass, "pkce_bypass")
            )

            # Test JWT security vulnerabilities if we have real tokens
            extractor = TokenExtractor()
            real_tokens = await extractor.get_real_tokens(self.server_url)

            if real_tokens and real_tokens.get("access_token"):
                real_token = real_tokens["access_token"]

                # Test JWT signature bypass attacks
                signature_bypass = await jwt_tester.test_signature_bypass_attacks(
                    real_token, self.server_url
                )
                results.append(
                    self._convert_security_to_auth_result(signature_bypass, "jwt_signature_bypass")
                )

                # Test JWT validation bypass
                validation_bypass = await jwt_tester.test_token_validation_bypass(real_token)
                results.append(
                    self._convert_security_to_auth_result(validation_bypass, "jwt_validation_bypass")
                )

                # Test JWT injection attacks
                injection_attacks = await jwt_tester.test_jwt_injection_attacks(real_token)
                results.append(
                    self._convert_security_to_auth_result(injection_attacks, "jwt_injection")
                )

            else:
                # Fallback: Test with a sample JWT when no real tokens available
                sample_token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ0ZXN0IiwiaXNzIjoidGVzdCIsImV4cCI6OTk5OTk5OTk5OX0.sample_signature"

                signature_bypass = await jwt_tester.test_signature_bypass_attacks(
                    sample_token, self.server_url
                )
                results.append(
                    self._convert_security_to_auth_result(signature_bypass, "jwt_signature_bypass_fallback")
                )

        except Exception as e:
            # Add a failure result if OAuth security testing fails
            test_id = str(uuid4())
            results.append(
                AuthTestResult(
                    test_id=test_id,
                    auth_method="oauth_security_vulnerabilities",
                    bypass_attempted="oauth_security_testing",
                    start_time=datetime.now(),
                    end_time=datetime.now(),
                    duration=0.0,
                    status=TestStatus.FAILED,
                    success=False,
                    bypass_successful=False,
                    access_granted=False,
                    vulnerability_severity="high",
                    error_message=str(e),
                    error_type=ErrorType.EXECUTION,
                )
            )

        return results

    def generate_auth_security_report(
        self, results: list[AuthTestResult]
    ) -> AuthSecurityReport:
        """Generate comprehensive authentication security report"""

        total_tests = len(results)
        passed_tests = len([r for r in results if r.success])
        bypasses_detected = len([r for r in results if r.bypass_successful])

        # Count by severity
        critical_issues = len(
            [
                r
                for r in results
                if r.vulnerability_severity == "critical" and not r.success
            ]
        )
        high_issues = len(
            [r for r in results if r.vulnerability_severity == "high" and not r.success]
        )
        medium_issues = len(
            [
                r
                for r in results
                if r.vulnerability_severity == "medium" and not r.success
            ]
        )
        low_issues = len(
            [r for r in results if r.vulnerability_severity == "low" and not r.success]
        )

        # Calculate authentication security score (weighted by severity)
        if total_tests == 0:
            auth_score = 100.0
        else:
            max_score = total_tests * 100
            deductions = (
                (critical_issues * 50)
                + (high_issues * 30)
                + (medium_issues * 15)
                + (low_issues * 5)
            )
            auth_score = max(0, (max_score - deductions) / max_score * 100)

        # Generate recommendations based on findings
        recommendations = []
        if critical_issues > 0:
            recommendations.append(
                "CRITICAL: Implement proper authentication validation to prevent bypasses"
            )
        if high_issues > 0:
            recommendations.append("Strengthen session management and token validation")
        if medium_issues > 0:
            recommendations.append(
                "Review authentication header handling and timeout policies"
            )
        if bypasses_detected > 0:
            recommendations.append(
                "Audit all authentication bypass vectors identified in testing"
            )
        if auth_score < 70:
            recommendations.append(
                "Comprehensive authentication security review recommended"
            )

        return AuthSecurityReport(
            server_name=self.server_config.get("name", "unknown"),
            server_url=str(self.server_url) if self.server_url else "unknown",
            test_timestamp=datetime.now(),
            overall_auth_score=auth_score,
            total_auth_tests=total_tests,
            passed_auth_tests=passed_tests,
            bypasses_detected=bypasses_detected,
            critical_auth_issues=critical_issues,
            high_auth_issues=high_issues,
            medium_auth_issues=medium_issues,
            low_auth_issues=low_issues,
            test_results=results,
            recommendations=recommendations,
        )
