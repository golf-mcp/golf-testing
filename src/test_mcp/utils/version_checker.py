import importlib.metadata
import json
import logging
import os
import tempfile
import threading
from datetime import datetime, timedelta
from pathlib import Path

import httpx
from packaging import version

from ..config.config_manager import ConfigManager

logger = logging.getLogger(__name__)


class VersionChecker:
    """Handles version checking against PyPI with smart caching"""

    DEFAULT_TIMEOUT = 5
    DEFAULT_CACHE_TTL_DAYS = 7
    PYPI_BASE_URL = "https://pypi.org"

    def __init__(self, package_name: str = "mcp-testing", timeout: int | None = None):
        self.package_name = package_name
        self.timeout = timeout or self.DEFAULT_TIMEOUT
        self.config_manager = ConfigManager()
        self.cache_file = self._get_cache_file()

    def _get_cache_file(self) -> Path:
        """Get version cache file path"""
        cache_dir = self.config_manager.paths.get_system_paths()["cache_dir"]
        return cache_dir / "version_check.json"

    def get_current_version(self) -> str | None:
        """Get currently installed package version."""
        try:
            return importlib.metadata.version(self.package_name)
        except importlib.metadata.PackageNotFoundError:
            # Development mode - package not installed
            return None

    def check_for_update_async(self, callback=None):
        """Run version check in background thread."""

        def check():
            try:
                result = self.check_for_update()
                if callback:
                    try:
                        callback(result)
                    except Exception as e:
                        logger.warning(f"Version check callback failed: {e}")
            except Exception as e:
                logger.debug(f"Background version check failed: {e}")

        thread = threading.Thread(target=check, name="version-checker")
        thread.daemon = True
        thread.start()

    def check_for_update(self) -> dict | None:  # noqa: PLR0911
        """Check PyPI for newer version with caching."""
        # Skip check in development mode (package not installed)
        current_version = self.get_current_version()
        if current_version is None:
            logger.debug(
                f"Package '{self.package_name}' not installed, skipping version check"
            )
            return None

        # Check cache first
        cached_result = self._load_cache()
        if cached_result and not self._is_cache_expired(cached_result):
            return cached_result

        try:
            # Fetch from PyPI
            response = httpx.get(
                f"{self.PYPI_BASE_URL}/pypi/{self.package_name}/json",
                timeout=self.timeout,
            )
            response.raise_for_status()

            data = response.json()

            # Validate PyPI response structure
            if "info" not in data or "version" not in data["info"]:
                logger.warning(f"Invalid PyPI response for {self.package_name}")
                return cached_result

            latest_version = data["info"]["version"]

            # Prepare result
            result = {
                "current_version": current_version,
                "latest_version": latest_version,
                "has_update": version.parse(latest_version)
                > version.parse(current_version),
                "last_check": datetime.now().isoformat(),
                "package_url": f"{self.PYPI_BASE_URL}/project/{self.package_name}/",
                "release_notes_url": f"{self.PYPI_BASE_URL}/project/{self.package_name}/{latest_version}/",
            }

            # Cache result
            self._save_cache(result)
            return result

        except (httpx.HTTPError, httpx.TimeoutException) as e:
            logger.debug(f"Network error checking PyPI: {e}")
            return cached_result
        except (json.JSONDecodeError, KeyError) as e:
            logger.warning(f"Invalid PyPI response format: {e}")
            return cached_result
        except Exception as e:
            logger.error(f"Unexpected error checking for updates: {e}")
            return cached_result

    def _load_cache(self) -> dict | None:
        """Load cached version check result."""
        try:
            if self.cache_file.exists():
                with open(self.cache_file) as f:
                    return json.load(f)
        except (json.JSONDecodeError, OSError) as e:
            logger.debug(f"Failed to load version cache: {e}")
        return None

    def _save_cache(self, result: dict):
        """Save version check result to cache using atomic write."""
        try:
            self.cache_file.parent.mkdir(parents=True, exist_ok=True)

            # Atomic write: write to temp file, then rename
            with tempfile.NamedTemporaryFile(
                mode="w",
                dir=self.cache_file.parent,
                delete=False,
                prefix=".version_check_",
                suffix=".tmp",
            ) as f:
                json.dump(result, f, indent=2)
                temp_path = f.name

            # Atomic rename (overwrites existing file)
            os.replace(temp_path, self.cache_file)

        except OSError as e:
            logger.debug(f"Failed to save version cache: {e}")
            # Clean up temp file if it exists
            try:
                if "temp_path" in locals():
                    os.unlink(temp_path)
            except OSError:
                pass

    def _is_cache_expired(
        self, cached_result: dict, ttl_days: int | None = None
    ) -> bool:
        """Check if cached result has expired."""
        ttl_days = ttl_days or self.DEFAULT_CACHE_TTL_DAYS
        try:
            last_check = datetime.fromisoformat(cached_result["last_check"])
            return datetime.now() - last_check > timedelta(days=ttl_days)
        except (KeyError, ValueError, TypeError) as e:
            logger.debug(f"Invalid cache timestamp: {e}")
            return True  # Treat invalid cache as expired
