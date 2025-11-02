"""
Configuration constants and settings for the MCP Testing Framework.

Local-first configuration for standalone CLI testing tool.
"""

import os
import warnings

ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")
OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")

if not ANTHROPIC_API_KEY:
    warnings.warn(
        "ANTHROPIC_API_KEY environment variable is not set. Agent functionality will be limited.",
        stacklevel=2,
    )

if not OPENAI_API_KEY:
    warnings.warn(
        "OPENAI_API_KEY environment variable is not set. Judge and user simulator functionality will be limited.",
        stacklevel=2,
    )
