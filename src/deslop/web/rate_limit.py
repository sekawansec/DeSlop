"""A tiny in-process rate limiter for public endpoints.

Not a substitute for a reverse-proxy limiter, but it bounds abuse of the status
page and reply endpoint out of the box.
"""

from __future__ import annotations

import time
from collections import defaultdict, deque

from fastapi import HTTPException


class RateLimiter:
    def __init__(self) -> None:
        self._hits: dict[str, deque[float]] = defaultdict(deque)

    def check(self, key: str, *, limit: int, window: float) -> None:
        now = time.monotonic()
        bucket = self._hits[key]
        while bucket and now - bucket[0] > window:
            bucket.popleft()
        if len(bucket) >= limit:
            raise HTTPException(status_code=429, detail="rate limit exceeded")
        bucket.append(now)

    def reset(self) -> None:
        self._hits.clear()


limiter = RateLimiter()
