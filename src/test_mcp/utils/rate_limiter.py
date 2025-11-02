import asyncio
import logging
import time
import uuid
from collections import defaultdict
from typing import NamedTuple

logger = logging.getLogger(__name__)


class RequestRecord(NamedTuple):
    """Immutable record of a rate-limited request."""

    timestamp: float
    tokens_used: int
    correlation_id: str


class RateLimiter:
    """
    Thread-safe async rate limiter with RPM and token limits.

    Manages rate limiting across multiple providers with both request-per-minute
    and token-per-minute constraints. Uses asyncio locks for coroutine safety.
    """

    TOKEN_USAGE_THRESHOLD = 0.8
    RATE_LIMIT_WINDOW_SECONDS = 60
    REQUEST_TIMEOUT_SECONDS = 300
    CLEANUP_CHECK_INTERVAL = 1.0

    def __init__(self) -> None:
        self.providers = {
            "anthropic": {"requests_per_minute": 5000, "tokens_per_minute": 100000},
            "openai": {"requests_per_minute": 5000, "tokens_per_minute": 100000},
            "gemini": {"requests_per_minute": 60, "tokens_per_minute": 8000},
        }

        self.request_history: dict[str, dict[str, RequestRecord]] = defaultdict(dict)
        self.token_usage: dict[str, int] = defaultdict(int)
        self._pending_requests: dict[str, tuple[str, float]] = {}

        self._locks: dict[str, asyncio.Lock] = {}
        self._global_lock = asyncio.Lock()

    async def _get_provider_lock(self, provider: str) -> asyncio.Lock:
        """Get or create a lock for a specific provider."""
        async with self._global_lock:
            if provider not in self._locks:
                self._locks[provider] = asyncio.Lock()
            return self._locks[provider]

    async def acquire_request_slot(self, provider: str) -> str:
        """
        Acquire permission to make API request and return correlation ID.

        Thread-safe operation that waits if rate limits are exceeded.

        Args:
            provider: API provider name (e.g., 'anthropic', 'openai')

        Returns:
            Correlation ID for tracking this request

        Raises:
            ValueError: If provider limits are not configured
        """
        if provider not in self.providers:
            logger.warning(f"Unknown provider '{provider}', using default limits")

        limits = self.providers.get(provider, {})
        rpm_limit = limits.get("requests_per_minute", 500)
        tpm_limit = limits.get("tokens_per_minute", 100000)

        if rpm_limit <= 0 or tpm_limit <= 0:
            raise ValueError(f"Invalid rate limits for provider '{provider}'")

        lock = await self._get_provider_lock(provider)

        async with lock:
            now = time.time()
            self._clean_old_requests(provider, now)

            while (
                len(self.request_history[provider]) >= rpm_limit
                or self.token_usage[provider] > tpm_limit * self.TOKEN_USAGE_THRESHOLD
            ):
                await asyncio.sleep(self.CLEANUP_CHECK_INTERVAL)
                now = time.time()
                self._clean_old_requests(provider, now)

            correlation_id = f"{provider}_{int(now)}_{uuid.uuid4().hex[:8]}"
            record = RequestRecord(
                timestamp=now, tokens_used=0, correlation_id=correlation_id
            )
            self.request_history[provider][correlation_id] = record
            self._pending_requests[correlation_id] = (provider, now)

            return correlation_id

    async def record_token_usage(self, correlation_id: str, tokens_used: int) -> None:
        """
        Record actual token usage from API response using correlation ID.

        Thread-safe operation that updates token usage tracking.

        Args:
            correlation_id: ID returned from acquire_request_slot
            tokens_used: Number of tokens consumed by the request

        Raises:
            ValueError: If tokens_used is negative
        """
        if tokens_used < 0:
            raise ValueError(f"tokens_used must be non-negative, got {tokens_used}")

        if correlation_id not in self._pending_requests:
            logger.warning(f"Unknown correlation ID {correlation_id}")
            return

        provider, _timestamp = self._pending_requests[correlation_id]
        lock = await self._get_provider_lock(provider)

        async with lock:
            self.token_usage[provider] += tokens_used

            if correlation_id in self.request_history[provider]:
                old_record = self.request_history[provider][correlation_id]
                updated_record = RequestRecord(
                    timestamp=old_record.timestamp,
                    tokens_used=tokens_used,
                    correlation_id=correlation_id,
                )
                self.request_history[provider][correlation_id] = updated_record

            del self._pending_requests[correlation_id]

    def _clean_old_requests(self, provider: str, current_time: float) -> None:
        """
        Remove requests older than rate limit window and their token usage.

        Must be called while holding the provider lock.

        Args:
            provider: Provider name to clean requests for
            current_time: Current timestamp
        """
        cutoff_time = current_time - self.RATE_LIMIT_WINDOW_SECONDS
        timeout_cutoff = current_time - self.REQUEST_TIMEOUT_SECONDS

        tokens_to_remove = 0
        correlation_ids_to_remove = []

        for correlation_id, record in list(self.request_history[provider].items()):
            if record.timestamp >= cutoff_time:
                continue

            should_remove = False

            if record.timestamp < timeout_cutoff:
                should_remove = True
                if correlation_id in self._pending_requests:
                    logger.warning(
                        f"Timing out request {correlation_id} after "
                        f"{self.REQUEST_TIMEOUT_SECONDS}s"
                    )
                    del self._pending_requests[correlation_id]
            elif correlation_id not in self._pending_requests:
                should_remove = True

            if should_remove:
                tokens_to_remove += record.tokens_used
                correlation_ids_to_remove.append(correlation_id)

        for correlation_id in correlation_ids_to_remove:
            del self.request_history[provider][correlation_id]

        self.token_usage[provider] = max(
            0, self.token_usage[provider] - tokens_to_remove
        )

    async def cleanup_pending_request(self, correlation_id: str) -> None:
        """
        Clean up pending request on error.

        Thread-safe operation to remove a pending request and its history entry.

        Args:
            correlation_id: ID of the request to clean up
        """
        if correlation_id not in self._pending_requests:
            return

        provider, _timestamp = self._pending_requests[correlation_id]
        lock = await self._get_provider_lock(provider)

        async with lock:
            if correlation_id in self._pending_requests:
                del self._pending_requests[correlation_id]

            if correlation_id in self.request_history[provider]:
                del self.request_history[provider][correlation_id]
