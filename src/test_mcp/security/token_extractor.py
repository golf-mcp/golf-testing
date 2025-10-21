import base64
import json
from datetime import datetime, timedelta
from typing import Any

from ..mcp_client.client_manager import SharedTokenStorage


class TokenExtractor:
    """Extract and manipulate real OAuth tokens from SharedTokenStorage"""

    async def get_real_tokens(self, server_url: str) -> dict[str, Any] | None:
        """Extract authentic tokens from SharedTokenStorage"""
        try:
            token_storage = SharedTokenStorage.get_instance(server_url)
            if not token_storage.has_valid_tokens():
                return None

            oauth_token = await token_storage.get_token()
            if not oauth_token:
                return None

            return {
                "access_token": oauth_token.access_token,
                "refresh_token": oauth_token.refresh_token,
                "expires_at": oauth_token.expires_at,
                "token_type": oauth_token.token_type,
            }
        except Exception:
            # If token extraction fails, return None to fallback to hardcoded tokens
            return None

    def create_manipulated_tokens(
        self, real_tokens: dict[str, Any]
    ) -> list[dict[str, str]]:
        """Generate attack tokens based on real token structure"""
        manipulated_tokens = []
        access_token = real_tokens.get("access_token", "")

        if not access_token:
            return []

        try:
            # Try to decode JWT structure for manipulation
            if self._is_jwt(access_token):
                manipulated_tokens.extend(self._create_jwt_attacks(access_token))
            else:
                # Non-JWT token manipulation
                manipulated_tokens.extend(
                    self._create_opaque_token_attacks(access_token)
                )

        except Exception:
            # If manipulation fails, return empty list to use hardcoded fallbacks
            return []

        return manipulated_tokens

    def create_expired_token(self, access_token: str) -> str:
        """Create an expired version of a real token for timeout testing"""
        try:
            if self._is_jwt(access_token):
                # Create expired JWT
                header, payload, signature = access_token.split(".")
                decoded_payload = self._decode_base64_json(payload)

                # Set expiration to past date (1 hour ago)
                expired_time = datetime.utcnow() - timedelta(hours=1)
                decoded_payload["exp"] = int(expired_time.timestamp())

                # Re-encode payload
                modified_payload = self._encode_base64_json(decoded_payload)
                return f"{header}.{modified_payload}.{signature}"
            else:
                # For opaque tokens, create a modified version that suggests expiration
                return f"expired_{access_token}"

        except Exception:
            # If manipulation fails, return a generic expired token
            return f"expired_{access_token[:10]}..."

    def _is_jwt(self, token: str) -> bool:
        """Check if token is a JWT by counting dots"""
        return len(token.split(".")) == 3

    def _create_jwt_attacks(self, jwt_token: str) -> list[dict[str, str]]:
        """Create JWT-specific attack tokens"""
        attacks = []

        try:
            header, payload, signature = jwt_token.split(".")

            # Attack 1: Remove signature
            attacks.append(
                {
                    "token": f"{header}.{payload}.",
                    "description": "JWT with signature removed",
                }
            )

            # Attack 2: Modify expiration to future date
            try:
                decoded_payload = self._decode_base64_json(payload)
                if "exp" in decoded_payload:
                    future_exp = int(
                        (datetime.utcnow() + timedelta(days=365)).timestamp()
                    )
                    decoded_payload["exp"] = future_exp
                    modified_payload = self._encode_base64_json(decoded_payload)
                    attacks.append(
                        {
                            "token": f"{header}.{modified_payload}.{signature}",
                            "description": "JWT with modified expiration",
                        }
                    )
            except Exception:
                pass

            # Attack 3: Modify algorithm to "none"
            try:
                decoded_header = self._decode_base64_json(header)
                decoded_header["alg"] = "none"
                modified_header = self._encode_base64_json(decoded_header)
                attacks.append(
                    {
                        "token": f"{modified_header}.{payload}.",
                        "description": "JWT with algorithm changed to 'none'",
                    }
                )
            except Exception:
                pass

            # Attack 4: Corrupt the signature
            attacks.append(
                {
                    "token": f"{header}.{payload}.corrupted_signature",
                    "description": "JWT with corrupted signature",
                }
            )

        except Exception:
            pass

        return attacks

    def _create_opaque_token_attacks(self, token: str) -> list[dict[str, str]]:
        """Create attacks for opaque (non-JWT) tokens"""
        attacks = []

        # Attack 1: Truncated token
        if len(token) > 10:
            attacks.append(
                {
                    "token": token[: len(token) // 2],
                    "description": "Truncated opaque token",
                }
            )

        # Attack 2: Modified token (change one character)
        if len(token) > 5:
            modified = token[:-1] + ("x" if token[-1] != "x" else "y")
            attacks.append({"token": modified, "description": "Modified opaque token"})

        # Attack 3: Repeated token segments
        if len(token) > 20:
            segment = token[:10]
            attacks.append(
                {
                    "token": segment + segment + token[10:],
                    "description": "Opaque token with repeated segments",
                }
            )

        return attacks

    def _decode_base64_json(self, b64_string: str) -> dict[str, Any]:
        """Decode base64 JSON with proper padding"""
        # Add padding if needed
        missing_padding = len(b64_string) % 4
        if missing_padding:
            b64_string += "=" * (4 - missing_padding)

        decoded_bytes = base64.urlsafe_b64decode(b64_string)
        decoded_json: dict[str, Any] = json.loads(decoded_bytes.decode("utf-8"))
        return decoded_json

    def _encode_base64_json(self, data: dict[str, Any]) -> str:
        """Encode JSON to base64 without padding"""
        json_bytes = json.dumps(data, separators=(",", ":")).encode("utf-8")
        b64_string = base64.urlsafe_b64encode(json_bytes).decode("utf-8")
        return b64_string.rstrip("=")
