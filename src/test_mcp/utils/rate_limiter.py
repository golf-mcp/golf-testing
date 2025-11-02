import asyncio
import time
import uuid
from collections import defaultdict, deque


class RateLimiter:
    """Simple rate limiter with RPM and token limits"""

    # Entry tuple indices
    TIMESTAMP_INDEX = 0
    TOKENS_INDEX = 1
    CORRELATION_ID_INDEX = 2

    # Entry tuple minimum lengths
    MIN_ENTRY_WITH_TOKENS = 2
    MIN_ENTRY_WITH_ID = 3

    def __init__(self) -> None:
        # Updated to realistic API limits (conservative defaults for reliable operation)
        self.providers = {
            "anthropic": {"requests_per_minute": 5000, "tokens_per_minute": 100000},
            "openai": {"requests_per_minute": 5000, "tokens_per_minute": 100000},
            "gemini": {"requests_per_minute": 60, "tokens_per_minute": 8000},
        }
        self.request_history: dict[str, deque] = defaultdict(deque)
        # Add token usage tracking
        self.token_usage: dict[str, int] = defaultdict(int)  # Current window total
        # Track correlation IDs to provider/timestamp mapping
        self._pending_requests: dict[str, tuple[str, float]] = {}

    async def acquire_request_slot(self, provider: str) -> str:
        """Acquire permission to make API request and return correlation ID"""
        limits = self.providers.get(provider, {})
        rpm_limit = limits.get("requests_per_minute", 500)
        tpm_limit = limits.get("tokens_per_minute", 100000)

        now = time.time()
        self._clean_old_requests(provider, now)

        # Check both request and token limits
        while (
            len(self.request_history[provider]) >= rpm_limit
            or self.token_usage[provider] > tpm_limit * 0.8
        ):
            await asyncio.sleep(1)
            now = time.time()
            self._clean_old_requests(provider, now)

        # Generate correlation ID and record the request
        correlation_id = f"{provider}_{int(now)}_{uuid.uuid4().hex[:8]}"
        self.request_history[provider].append((now, 0, correlation_id))
        self._pending_requests[correlation_id] = (provider, now)

        return correlation_id

    def record_token_usage(self, correlation_id: str, tokens_used: int) -> None:
        """Record actual token usage from API response using correlation ID"""
        if correlation_id not in self._pending_requests:
            print(f"Warning: Unknown correlation ID {correlation_id}")
            return

        provider, _timestamp = self._pending_requests[correlation_id]
        self.token_usage[provider] += tokens_used

        # Find and update the specific request entry
        for i, entry in enumerate(self.request_history[provider]):
            if (
                len(entry) >= self.MIN_ENTRY_WITH_ID
                and entry[self.CORRELATION_ID_INDEX] == correlation_id
            ):
                req_time, _req_tokens, req_id = entry
                self.request_history[provider][i] = (req_time, tokens_used, req_id)
                break

        # Clean up pending request
        del self._pending_requests[correlation_id]

    def _clean_old_requests(self, provider: str, current_time: float) -> None:
        """Remove requests older than 1 minute and their token usage"""
        cutoff_time = current_time - 60
        timeout_cutoff = current_time - 300  # 5 minute absolute timeout

        tokens_to_remove = 0

        # Use index-based removal to avoid O(n²) performance and race conditions
        # Process from right to left to maintain valid indices during removal
        for i in range(len(self.request_history[provider]) - 1, -1, -1):
            entry = self.request_history[provider][i]

            if entry[self.TIMESTAMP_INDEX] >= cutoff_time:
                continue  # Entry is still fresh, keep it

            should_remove = False

            # Force cleanup of extremely old requests (5+ minutes)
            if entry[self.TIMESTAMP_INDEX] < timeout_cutoff:
                should_remove = True
                if len(entry) >= self.MIN_ENTRY_WITH_ID:
                    correlation_id = entry[self.CORRELATION_ID_INDEX]
                    if correlation_id in self._pending_requests:
                        print(
                            f"Warning: Timing out request {correlation_id} after 5 minutes"
                        )
                        del self._pending_requests[correlation_id]
            # Only remove if tokens have been recorded (not pending)
            elif len(entry) >= self.MIN_ENTRY_WITH_ID:
                correlation_id = entry[self.CORRELATION_ID_INDEX]
                # Skip entries that are still pending token recording
                if correlation_id not in self._pending_requests:
                    should_remove = True
            else:
                # Entry without correlation ID can be safely removed
                should_remove = True

            if should_remove:
                # Count tokens before removal
                if len(entry) >= self.MIN_ENTRY_WITH_TOKENS:
                    tokens = entry[self.TOKENS_INDEX]
                    tokens_to_remove += tokens

                # Remove entry using index (O(1) for deque)
                del self.request_history[provider][i]

        # Remove old tokens from current usage
        self.token_usage[provider] = max(
            0, self.token_usage[provider] - tokens_to_remove
        )

    def cleanup_pending_request(self, correlation_id: str) -> None:
        """Clean up pending request on error"""
        if correlation_id in self._pending_requests:
            del self._pending_requests[correlation_id]
