import base64
import json
import uuid
from datetime import datetime

import httpx

from ..shared.result_models import TestStatus
from .connection_manipulator import SecurityResult


class OAuthSecurityScanner:
    """Test for OAuth security vulnerabilities and bypass techniques"""

    def __init__(self, server_url: str, timeout: float = 10.0):
        self.server_url = server_url
        self.timeout = timeout

    async def test_resource_indicator_bypass(self, server_config: dict) -> SecurityResult:
        """Test for RFC 8707 Resource Indicator bypass vulnerabilities"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Test 1: Token without resource parameter should be rejected for cross-service access
                evidence.append("Testing resource indicator bypass attacks...")

                # Test audience restriction bypass by omitting resource parameter
                test_cases = [
                    {
                        "name": "Missing resource parameter",
                        "params": {"grant_type": "authorization_code", "code": "test_code"},
                        "description": "Token request without resource parameter",
                    },
                    {
                        "name": "Wrong resource parameter",
                        "params": {
                            "grant_type": "authorization_code",
                            "code": "test_code",
                            "resource": "https://wrong-service.example.com",
                        },
                        "description": "Token with incorrect resource indicator",
                    },
                    {
                        "name": "Multiple resource parameters",
                        "params": {
                            "grant_type": "authorization_code",
                            "code": "test_code",
                            "resource": [
                                "https://service1.example.com",
                                "https://service2.example.com",
                            ],
                        },
                        "description": "Token with multiple resource parameters",
                    },
                    {
                        "name": "Resource parameter injection",
                        "params": {
                            "grant_type": "authorization_code",
                            "code": "test_code",
                            "resource": "javascript:alert(1)",
                        },
                        "description": "Resource parameter with script injection",
                    },
                ]

                oauth_endpoints = [
                    f"{self.server_url}/oauth/token",
                    f"{self.server_url}/token",
                    f"{self.server_url}/auth/token",
                    f"{self.server_url}/.well-known/oauth-authorization-server",
                ]

                for endpoint in oauth_endpoints:
                    for test_case in test_cases:
                        try:
                            # Test token endpoint with resource bypass attempts
                            # Handle list values in params by converting to form data format
                            form_data = {}
                            for key, value in test_case["params"].items():
                                if isinstance(value, list):
                                    # For lists, httpx expects multiple key-value pairs
                                    for item in value:
                                        form_data[key] = str(item)
                                else:
                                    form_data[key] = str(value)

                            response = await client.post(
                                endpoint, data=form_data
                            )

                            evidence.append(
                                f"Endpoint {endpoint}: {test_case['name']} -> {response.status_code}"
                            )

                            # Check if server improperly grants tokens without proper resource validation
                            if response.status_code == 200:
                                try:
                                    token_data = response.json()
                                    if "access_token" in token_data:
                                        vulnerability_detected = True
                                        evidence.append(
                                            f"VULNERABILITY: {test_case['description']} granted token"
                                        )
                                except json.JSONDecodeError:
                                    pass
                            elif response.status_code in [400, 401, 403]:
                                evidence.append(
                                    f"Proper rejection: {test_case['description']}"
                                )

                        except Exception as e:
                            evidence.append(
                                f"Request to {endpoint} failed: {str(e)[:50]}"
                            )

                # Test 2: Cross-service token acceptance without proper audience validation
                fake_tokens = [
                    self._create_fake_jwt_with_audience("https://other-service.com"),
                    self._create_fake_jwt_with_audience("*"),
                    self._create_fake_jwt_with_audience(""),
                ]

                for token in fake_tokens:
                    try:
                        headers = {"Authorization": f"Bearer {token}"}
                        response = await client.get(self.server_url, headers=headers)

                        if response.status_code == 200:
                            vulnerability_detected = True
                            evidence.append(
                                f"VULNERABILITY: Cross-service token accepted: {token[:20]}..."
                            )
                        else:
                            evidence.append(
                                f"Proper audience validation: {response.status_code}"
                            )

                    except Exception as e:
                        evidence.append(f"Token test failed: {str(e)[:50]}")

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="Resource Indicator Bypass Test",
                attack_type="resource_indicator_bypass",
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
                test_name="Resource Indicator Bypass Test",
                attack_type="resource_indicator_bypass",
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

    async def test_metadata_injection_attacks(self, server_url: str) -> SecurityResult:
        """Test for OAuth metadata manipulation vulnerabilities"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                evidence.append("Testing OAuth metadata injection attacks...")

                # Test 1: JWKS endpoint manipulation via DNS/routing attacks
                metadata_endpoints = [
                    f"{server_url}/.well-known/oauth-authorization-server",
                    f"{server_url}/.well-known/openid_configuration",
                    f"{server_url}/oauth/metadata",
                    f"{server_url}/auth/.well-known/oauth-authorization-server",
                ]

                for endpoint in metadata_endpoints:
                    try:
                        response = await client.get(endpoint)
                        if response.status_code == 200:
                            try:
                                metadata = response.json()
                                evidence.append(
                                    f"Found OAuth metadata at {endpoint}"
                                )

                                # Check for potential JWKS manipulation vulnerabilities
                                jwks_uri = metadata.get("jwks_uri", "")
                                if jwks_uri:
                                    # Test JWKS endpoint security
                                    jwks_response = await client.get(jwks_uri)
                                    if jwks_response.status_code == 200:
                                        evidence.append(f"JWKS accessible at {jwks_uri}")

                                        # Test for JWKS manipulation vulnerability
                                        # Try to access JWKS with malicious Host header
                                        malicious_headers = {
                                            "Host": "attacker.com",
                                            "X-Forwarded-Host": "attacker.com",
                                            "X-Original-Host": "attacker.com",
                                        }

                                        malicious_response = await client.get(
                                            jwks_uri, headers=malicious_headers
                                        )
                                        if (
                                            malicious_response.status_code == 200
                                            and "attacker.com" in malicious_response.text
                                        ):
                                            vulnerability_detected = True
                                            evidence.append(
                                                "VULNERABILITY: JWKS endpoint susceptible to Host header injection"
                                            )

                                # Test authorization server metadata poisoning
                                critical_fields = [
                                    "authorization_endpoint",
                                    "token_endpoint",
                                    "jwks_uri",
                                    "issuer",
                                ]
                                for field in critical_fields:
                                    if field in metadata:
                                        field_value = metadata[field]
                                        evidence.append(f"Found {field}: {field_value}")

                                        # Check for potential redirect URI validation bypass
                                        if "authorization_endpoint" in metadata:
                                            auth_endpoint = metadata["authorization_endpoint"]
                                            # Test with malicious redirect URI
                                            bypass_params = {
                                                "response_type": "code",
                                                "client_id": "test_client",
                                                "redirect_uri": "javascript:alert(1)",
                                                "state": "test_state",
                                            }

                                            bypass_response = await client.get(
                                                auth_endpoint, params=bypass_params
                                            )

                                            if bypass_response.status_code not in [
                                                400,
                                                401,
                                                403,
                                            ]:
                                                # Server should reject malicious redirect URIs
                                                if "javascript:" in bypass_response.text:
                                                    vulnerability_detected = True
                                                    evidence.append(
                                                        "VULNERABILITY: Authorization endpoint allows malicious redirect URIs"
                                                    )

                            except json.JSONDecodeError:
                                evidence.append(
                                    f"Invalid JSON metadata at {endpoint}"
                                )

                    except Exception as e:
                        evidence.append(
                            f"Metadata endpoint test failed: {str(e)[:50]}"
                        )

                # Test 2: Metadata parameter injection
                injection_payloads = [
                    '{"jwks_uri": "https://attacker.com/jwks"}',
                    '{"issuer": "https://attacker.com"}',
                    '{"authorization_endpoint": "javascript:alert(1)"}',
                    '"issuer":"https://attacker.com"',
                ]

                for payload in injection_payloads:
                    try:
                        # Test if metadata can be influenced via query parameters
                        for endpoint in metadata_endpoints:
                            response = await client.get(
                                endpoint, params={"metadata": payload}
                            )

                            if "attacker.com" in response.text or "javascript:" in response.text:
                                vulnerability_detected = True
                                evidence.append(
                                    f"VULNERABILITY: Metadata injection successful with payload: {payload[:30]}..."
                                )

                    except Exception:
                        pass

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="OAuth Metadata Injection Test",
                attack_type="metadata_injection",
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
                test_name="OAuth Metadata Injection Test",
                attack_type="metadata_injection",
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

    async def test_pkce_bypass_attacks(self, server_config: dict) -> SecurityResult:
        """Test PKCE security bypass vulnerabilities"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False

        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                evidence.append("Testing PKCE bypass attacks...")

                # Test 1: Code verifier brute force attacks with weak entropy
                weak_verifiers = [
                    "12345",  # Too short
                    "a" * 43,  # Minimum length but no entropy
                    "password123",  # Predictable
                    "00000000000000000000000000000000000000000000",  # All zeros
                    "",  # Empty verifier
                ]

                oauth_endpoints = [
                    f"{self.server_url}/oauth/token",
                    f"{self.server_url}/token",
                    f"{self.server_url}/auth/token",
                ]

                for endpoint in oauth_endpoints:
                    for verifier in weak_verifiers:
                        try:
                            # Generate challenge for weak verifier
                            self._generate_pkce_challenge(verifier)

                            # Test token request with weak verifier
                            token_params = {
                                "grant_type": "authorization_code",
                                "code": "test_code",
                                "code_verifier": verifier,
                                "client_id": "test_client",
                            }

                            response = await client.post(endpoint, data=token_params)

                            if response.status_code == 200:
                                vulnerability_detected = True
                                evidence.append(
                                    f"VULNERABILITY: Weak code verifier accepted: {verifier[:10]}..."
                                )
                            elif response.status_code in [400, 401]:
                                evidence.append(
                                    "Proper PKCE validation: weak verifier rejected"
                                )

                            evidence.append(
                                f"Weak verifier test at {endpoint}: {response.status_code}"
                            )

                        except Exception as e:
                            evidence.append(
                                f"PKCE test failed: {str(e)[:50]}"
                            )

                # Test 2: Authorization code interception without PKCE validation
                # Test if authorization endpoints accept requests without PKCE
                auth_endpoints = [
                    f"{self.server_url}/oauth/authorize",
                    f"{self.server_url}/authorize",
                    f"{self.server_url}/auth/authorize",
                ]

                for endpoint in auth_endpoints:
                    try:
                        # Request without PKCE parameters
                        no_pkce_params = {
                            "response_type": "code",
                            "client_id": "test_client",
                            "redirect_uri": "https://example.com/callback",
                            "state": "test_state",
                        }

                        response = await client.get(endpoint, params=no_pkce_params)

                        if response.status_code not in [400, 401, 403]:
                            # Server should require PKCE for public clients
                            vulnerability_detected = True
                            evidence.append(
                                f"VULNERABILITY: Authorization without PKCE allowed at {endpoint}"
                            )
                        else:
                            evidence.append(
                                f"Proper PKCE enforcement at {endpoint}: {response.status_code}"
                            )

                    except Exception as e:
                        evidence.append(
                            f"Authorization endpoint test failed: {str(e)[:50]}"
                        )

                # Test 3: Downgrade attacks from S256 to plain method
                downgrade_challenges = [
                    {"code_challenge": "plain_challenge", "code_challenge_method": "plain"},
                    {"code_challenge": "weak_challenge", "code_challenge_method": "S256"},
                    {"code_challenge": "test", "code_challenge_method": ""},
                ]

                for challenge_data in downgrade_challenges:
                    try:
                        # Test authorization with downgraded PKCE method
                        auth_params = {
                            "response_type": "code",
                            "client_id": "test_client",
                            "redirect_uri": "https://example.com/callback",
                            "state": "test_state",
                            **challenge_data,
                        }

                        for endpoint in auth_endpoints:
                            response = await client.get(endpoint, params=auth_params)

                            if (
                                response.status_code not in [400, 401, 403]
                                and challenge_data.get("code_challenge_method") == "plain"
                            ):
                                vulnerability_detected = True
                                evidence.append(
                                    "VULNERABILITY: PKCE downgrade to 'plain' method allowed"
                                )
                            else:
                                evidence.append(
                                    f"PKCE method validation: {response.status_code}"
                                )

                    except Exception as e:
                        evidence.append(
                            f"PKCE downgrade test failed: {str(e)[:50]}"
                        )

                # Test 4: PKCE replay attacks
                # Test if the same code_verifier can be used multiple times
                valid_verifier = self._generate_secure_verifier()
                self._generate_pkce_challenge(valid_verifier)

                replay_attempts = 3
                for attempt in range(replay_attempts):
                    try:
                        token_params = {
                            "grant_type": "authorization_code",
                            "code": f"test_code_{attempt}",
                            "code_verifier": valid_verifier,
                            "client_id": "test_client",
                        }

                        for endpoint in oauth_endpoints:
                            response = await client.post(endpoint, data=token_params)
                            if attempt > 0 and response.status_code == 200:
                                vulnerability_detected = True
                                evidence.append(
                                    f"VULNERABILITY: PKCE verifier replay allowed (attempt {attempt + 1})"
                                )

                    except Exception:
                        pass

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="PKCE Bypass Test",
                attack_type="pkce_bypass",
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
                test_name="PKCE Bypass Test",
                attack_type="pkce_bypass",
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

    def _create_fake_jwt_with_audience(self, audience: str) -> str:
        """Create a fake JWT token with specific audience for testing"""
        # Create a fake JWT header
        header = {"alg": "HS256", "typ": "JWT"}

        # Create payload with audience
        payload = {
            "iss": "https://fake-issuer.com",
            "aud": audience,
            "sub": "test_user",
            "exp": 9999999999,  # Far future
            "iat": 1234567890,
        }

        # Encode header and payload (without signature for testing)
        header_encoded = base64.urlsafe_b64encode(
            json.dumps(header).encode()
        ).decode().rstrip("=")
        payload_encoded = base64.urlsafe_b64encode(
            json.dumps(payload).encode()
        ).decode().rstrip("=")

        # Create unsigned JWT for testing (signature will be invalid)
        fake_jwt = f"{header_encoded}.{payload_encoded}.fake_signature"

        return fake_jwt

    def _generate_pkce_challenge(self, verifier: str) -> str:
        """Generate PKCE challenge from verifier (simplified for testing)"""
        import base64
        import hashlib

        # For S256 method
        digest = hashlib.sha256(verifier.encode()).digest()
        challenge = base64.urlsafe_b64encode(digest).decode().rstrip("=")
        return challenge

    def _generate_secure_verifier(self) -> str:
        """Generate a secure code verifier for PKCE testing"""
        import secrets
        import string

        # Generate 128 bytes of random data (meets PKCE requirements)
        alphabet = string.ascii_letters + string.digits + "-._~"
        verifier = "".join(secrets.choice(alphabet) for _ in range(128))
        return verifier
