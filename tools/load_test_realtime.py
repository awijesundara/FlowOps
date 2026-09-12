#!/usr/bin/env python3
"""Real-time SSE load test: N concurrent viewers, measure propagation latency
from a single write to every connected client receiving the resulting event.

Usage: FLOWOPS_BASE=http://localhost:8088 python3 tools/load_test_realtime.py [concurrency]
"""
import http.client
import http.cookiejar
import json
import os
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor

BASE = os.environ.get("FLOWOPS_BASE", "http://localhost:8088")
CONCURRENCY = int(sys.argv[1]) if len(sys.argv) > 1 else 25
USERNAME = os.environ.get("FLOWOPS_LOAD_USER", "admin")
PASSWORD = os.environ.get("FLOWOPS_LOAD_PASSWORD", "FlowOps!Preview2026")


def login():
    jar = http.cookiejar.CookieJar()
    opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
    req = urllib.request.Request(
        f"{BASE}/api/auth/login",
        data=json.dumps({"username": USERNAME, "password": PASSWORD}).encode(),
        headers={"Content-Type": "application/json"},
    )
    with opener.open(req, timeout=5) as resp:
        body = json.loads(resp.read())
    return opener, body["data"]["csrf_token"]


def listener(opener, index, ready_barrier, results, deadline_marker, barrier_timeout):
    req = urllib.request.Request(f"{BASE}/api/events")
    try:
        with opener.open(req, timeout=20) as resp:
            ready_barrier.wait(timeout=barrier_timeout)
            for raw_line in resp:
                line = raw_line.decode().strip()
                if line == "event: workspace":
                    next(resp)  # data: ...
                    results[index] = time.monotonic() - deadline_marker[0]
                    return
    except Exception as exc:  # noqa: BLE001 - report, don't crash the harness
        results[index] = exc


def main():
    print(f"Load-testing real-time propagation: {BASE}, concurrency={CONCURRENCY}")
    opener, csrf = login()
    # Logging in is deliberately expensive (240,000-round PBKDF2 per
    # attempt, server-side) -- at higher concurrency, CONCURRENCY sequential
    # logins alone can take longer than the readiness barrier's timeout
    # before a single listener thread even starts. Parallelize it, the same
    # way the listeners themselves already are.
    login_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=min(CONCURRENCY, 50)) as pool:
        listeners = list(pool.map(lambda _: login()[0], range(CONCURRENCY)))
    print(f"Logged in {CONCURRENCY} viewers in {time.monotonic() - login_start:.1f}s")
    ready_barrier = threading.Barrier(CONCURRENCY + 1)
    deadline_marker = [0.0]
    results = [None] * CONCURRENCY
    # SSE connection establishment itself (not just login) measurably slows
    # down at higher concurrency in this environment (observed: Docker
    # Desktop's port-forwarding NAT arrives in bursts of ~10-20 connections
    # every few seconds well past 300 concurrent connects) -- a real,
    # environment-specific characteristic, not something to paper over with
    # an arbitrarily large fixed timeout. Scale it visibly instead. Every
    # party (each listener thread AND the main thread) must use the SAME
    # scaled timeout -- a barrier breaks the instant any single waiting
    # party's timeout elapses, so an unscaled per-listener timeout defeats
    # this entirely even if the main thread's own wait is scaled correctly.
    barrier_timeout = max(10, CONCURRENCY * 0.2)
    threads = [
        threading.Thread(target=listener, args=(listeners[i], i, ready_barrier, results, deadline_marker, barrier_timeout))
        for i in range(CONCURRENCY)
    ]
    for t in threads:
        t.start()
    ready_barrier.wait(timeout=barrier_timeout)
    time.sleep(0.3)  # let SSE connections actually establish server-side
    deadline_marker[0] = time.monotonic()
    req = urllib.request.Request(
        f"{BASE}/api/runbooks",
        data=json.dumps({"name": f"Load test runbook {time.time()}"}).encode(),
        headers={"Content-Type": "application/json", "X-CSRF-Token": csrf},
    )
    with opener.open(req, timeout=5) as resp:
        assert resp.status == 201, resp.status
    for t in threads:
        t.join(timeout=15)
    latencies = [r for r in results if isinstance(r, float)]
    errors = [r for r in results if not isinstance(r, float)]
    timeouts = CONCURRENCY - len(latencies) - len(errors)
    print(f"Delivered: {len(latencies)}/{CONCURRENCY}  Errors: {len(errors)}  Timeouts: {timeouts}")
    if latencies:
        latencies.sort()
        p50 = latencies[len(latencies) // 2]
        p95 = latencies[min(len(latencies) - 1, int(len(latencies) * 0.95))]
        worst = latencies[-1]
        print(f"Latency p50={p50:.3f}s p95={p95:.3f}s max={worst:.3f}s")
        print("PASS: all clients under 2.0s" if worst < 2.0 and len(latencies) == CONCURRENCY else "FAIL")
    if errors:
        print("Errors:", errors[:5])
    return 0 if latencies and len(latencies) == CONCURRENCY and max(latencies) < 2.0 else 1


if __name__ == "__main__":
    sys.exit(main())
