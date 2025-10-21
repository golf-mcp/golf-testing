import json
import os
from typing import Any

from openai import OpenAI


class OpenAIClientWrapper:
    """
    Unified OpenAI client wrapper to eliminate API call duplication across testing modules.
    Handles o3 model temperature restrictions and consistent JSON parsing.
    """

    def __init__(self, model: str = "gpt-5-2025-08-07", api_key: str | None = None):
        self.model = model
        self.client = OpenAI(api_key=api_key or os.getenv("OPENAI_API_KEY"))

        if not self.client.api_key:
            raise ValueError(
                "OpenAI API key is required. Set OPENAI_API_KEY environment variable."
            )

    def create_completion(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.1,
        json_mode: bool = True,
    ) -> str:
        """
        Create OpenAI completion with consistent handling across all testing modules.

        Args:
            messages: List of message dictionaries with 'role' and 'content'
            max_tokens: Maximum completion tokens
            temperature: Temperature for non-o3 models (ignored for o3 models)
            json_mode: Enable JSON response format (default: True)

        Returns:
            Raw response content from OpenAI
        """
        api_params: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_completion_tokens": max_tokens,
        }

        # Only add temperature for non-o3 models (o3 models only support default temperature)
        if not self.model.startswith("o3"):
            api_params["temperature"] = temperature

        # Enable JSON mode for structured responses
        if json_mode:
            api_params["response_format"] = {"type": "json_object"}

        try:
            response = self.client.chat.completions.create(**api_params)
            content = response.choices[0].message.content

            # Handle empty or None responses
            if not content or content.strip() == "":
                raise Exception("OpenAI returned empty response")

            return str(content)
        except Exception as e:
            raise Exception(f"OpenAI API call failed: {e!s}") from e

    def parse_json_response(self, raw_response: str) -> dict[str, Any]:
        """
        Parse JSON response with consistent markdown removal handling.

        Args:
            raw_response: Raw response string from OpenAI

        Returns:
            Parsed JSON data as dictionary

        Raises:
            json.JSONDecodeError: If JSON parsing fails
        """
        json_str = raw_response.strip()

        # Remove markdown code blocks if present
        if "```json" in json_str:
            json_str = json_str.split("```json")[1].split("```")[0].strip()
        elif "```" in json_str:
            json_str = json_str.split("```")[1].split("```")[0].strip()

        result: dict[str, Any] = json.loads(json_str)
        return result

    def create_completion_with_json_parsing(
        self,
        messages: list[dict[str, str]],
        max_tokens: int = 1000,
        temperature: float = 0.1,
        fallback_data: dict[str, Any] | None = None,
        json_mode: bool = True,
    ) -> tuple[dict[str, Any], str]:
        """
        Complete workflow: API call + JSON parsing with fallback handling.

        Args:
            messages: List of message dictionaries
            max_tokens: Maximum completion tokens
            temperature: Temperature for non-o3 models
            fallback_data: Default data to return if JSON parsing fails
            json_mode: Enable JSON response format (default: True)

        Returns:
            Tuple of (parsed_data, raw_response)
        """
        try:
            raw_response = self.create_completion(
                messages, max_tokens, temperature, json_mode
            )

            try:
                parsed_data = self.parse_json_response(raw_response)
                return parsed_data, raw_response
            except json.JSONDecodeError as e:
                print(f"Warning: Failed to parse JSON response: {e}")
                print(f"Raw response: {raw_response}")

                if fallback_data is not None:
                    return fallback_data, raw_response
                else:
                    raise e

        except Exception as e:
            error_msg = f"OpenAI completion failed: {e!s}"
            if fallback_data is not None:
                return fallback_data, error_msg
            else:
                raise e
