"""In-process rate limiting and failed-sign-in lockout."""
from __future__ import annotations

import os
import threading
import time



API_RATE_LIMIT = int(os.getenv("FLOWOPS_API_RATE_LIMIT", "120"))

API_RATE_WINDOW_SECONDS = 60

LOGIN_RATE_LIMIT_PER_IP = 60

LOGIN_RATE_WINDOW_PER_IP_SECONDS = 60

LOGIN_RATE_LIMIT_PER_ACCOUNT = 8

LOGIN_RATE_WINDOW_PER_ACCOUNT_SECONDS = 300

_rate_limit_state: dict[str, tuple[float, int]] = {}

_rate_limit_lock = threading.Lock()

def check_rate_limit(key: str, limit: int | None = None, window_seconds: int | None = None) -> int | None:
    """Fixed-window limiter. Returns None if the request is allowed, or the
    number of seconds the caller should wait (Retry-After) if it isn't.
    `limit`/`window_seconds` default to the API-token values but callers with
    a different threshold (e.g. login brute-force protection, which needs a
    much stricter window than routine API traffic) can override them --
    each distinct `key` still gets its own independent window/counter.
    Defaults are resolved here rather than in the signature -- a `def
    f(x=SOME_GLOBAL)` default is bound once at module-import time, so
    existing tests that patch server.API_RATE_LIMIT to exercise this at a
    low threshold would silently keep hitting the original value."""
    limit = API_RATE_LIMIT if limit is None else limit
    window_seconds = API_RATE_WINDOW_SECONDS if window_seconds is None else window_seconds
    now_ts = time.monotonic()
    with _rate_limit_lock:
        window_start, count = _rate_limit_state.get(key, (now_ts, 0))
        if now_ts - window_start >= window_seconds:
            window_start, count = now_ts, 0
        count += 1
        _rate_limit_state[key] = (window_start, count)
        if count > limit:
            return max(1, int(window_seconds - (now_ts - window_start)))
    return None

def rate_limit_lockout(key: str, limit: int, window_seconds: int) -> int | None:
    """Read-only counterpart to check_rate_limit(): reports whether `key` is
    already over threshold without consuming a slot. Used for the login
    account-lockout gate, which must be checked *before* an attempt (to
    reject it outright while locked out) but must only accumulate on actual
    failures -- recorded separately via record_rate_limit_failure() -- so a
    legitimate user's successful logins never count toward their own
    lockout. (An earlier version called check_rate_limit() unconditionally
    on every attempt, success included, which meant as few as 8 logins by
    the same real, correctly-authenticated user within 5 minutes locked
    the account out -- caught by test_browser.py's real UI login in every
    one of its 20 test cases.)"""
    now_ts = time.monotonic()
    with _rate_limit_lock:
        window_start, count = _rate_limit_state.get(key, (now_ts, 0))
        if now_ts - window_start >= window_seconds or count <= limit:
            return None
        return max(1, int(window_seconds - (now_ts - window_start)))

def record_rate_limit_failure(key: str, window_seconds: int) -> None:
    """Increments the failure counter used by rate_limit_lockout(), or
    clears it entirely (a fresh window) once a caller succeeds -- see
    reset_rate_limit_failures()."""
    now_ts = time.monotonic()
    with _rate_limit_lock:
        window_start, count = _rate_limit_state.get(key, (now_ts, 0))
        if now_ts - window_start >= window_seconds:
            window_start, count = now_ts, 0
        _rate_limit_state[key] = (window_start, count + 1)

def reset_rate_limit_failures(key: str) -> None:
    with _rate_limit_lock:
        _rate_limit_state.pop(key, None)
