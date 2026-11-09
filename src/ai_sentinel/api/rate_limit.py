import threading
import time
from collections.abc import Hashable
from dataclasses import dataclass
from math import ceil


@dataclass(frozen=True)
class RateLimitDecision:
    allowed: bool
    limit: int
    remaining: int
    retry_after_seconds: int
    reset_at: int
    request_count: int
    rejection_reason: str | None = None


class FixedWindowRateLimiter:
    def __init__(
        self,
        *,
        window_seconds: int = 60,
        max_keys: int = 10_000,
        cleanup_interval_seconds: int = 60,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("Rate-limit window must be positive.")
        if max_keys <= 0:
            raise ValueError("Rate-limit key capacity must be positive.")
        if cleanup_interval_seconds <= 0:
            raise ValueError("Rate-limit cleanup interval must be positive.")
        self._window_seconds = window_seconds
        self._max_keys = max_keys
        self._cleanup_interval_seconds = cleanup_interval_seconds
        self._windows: dict[Hashable, tuple[float, int]] = {}
        self._next_cleanup_at = 0.0
        self._lock = threading.Lock()

    @property
    def window_seconds(self) -> int:
        return self._window_seconds

    def consume(self, key: Hashable, limit: int) -> RateLimitDecision:
        if limit <= 0:
            raise ValueError("Rate-limit allowance must be positive.")
        with self._lock:
            now = time.monotonic()
            wall_now = time.time()
            self._cleanup_expired(now)
            window = self._windows.get(key)
            if window is not None and now - window[0] >= self._window_seconds:
                del self._windows[key]
                window = None
            if window is None:
                if len(self._windows) >= self._max_keys:
                    self._prune_expired(now)
                    if len(self._windows) >= self._max_keys:
                        seconds_until_capacity = max(
                            0,
                            min(
                                start + self._window_seconds
                                for start, _ in self._windows.values()
                            )
                            - now,
                        )
                        retry_after = max(1, ceil(seconds_until_capacity))
                        return RateLimitDecision(
                            allowed=False,
                            limit=limit,
                            remaining=0,
                            retry_after_seconds=retry_after,
                            reset_at=ceil(wall_now + seconds_until_capacity),
                            request_count=0,
                            rejection_reason="client_key_capacity",
                        )
                self._windows[key] = (now, 1)
                return RateLimitDecision(
                    allowed=True,
                    limit=limit,
                    remaining=max(0, limit - 1),
                    retry_after_seconds=(self._window_seconds if limit == 1 else 0),
                    reset_at=ceil(wall_now + self._window_seconds),
                    request_count=1,
                )

            request_count = window[1]
            seconds_until_reset = max(0, window[0] + self._window_seconds - now)
            reset_at = ceil(wall_now + seconds_until_reset)
            if request_count >= limit:
                return RateLimitDecision(
                    allowed=False,
                    limit=limit,
                    remaining=0,
                    retry_after_seconds=max(1, ceil(seconds_until_reset)),
                    reset_at=reset_at,
                    request_count=request_count,
                    rejection_reason="limit_exceeded",
                )

            request_count += 1
            self._windows[key] = (window[0], request_count)
            remaining = max(0, limit - request_count)
            return RateLimitDecision(
                allowed=True,
                limit=limit,
                remaining=remaining,
                retry_after_seconds=(
                    max(1, ceil(seconds_until_reset)) if remaining == 0 else 0
                ),
                reset_at=reset_at,
                request_count=request_count,
            )

    def _cleanup_expired(self, now: float) -> None:
        if now >= self._next_cleanup_at:
            self._prune_expired(now)
            self._next_cleanup_at = now + self._cleanup_interval_seconds

    def _prune_expired(self, now: float) -> None:
        cutoff = now - self._window_seconds
        self._windows = {
            key: window for key, window in self._windows.items() if window[0] > cutoff
        }
