"""限流 + 暴力破解防护服务（内存存储，滑动窗口 + 失败锁定）。

两套独立机制：
1. 限流（Rate Limiting）：(ip, endpoint) 维度的滑动窗口，超限返回 429
2. 锁定（Brute-Force Lockout）：(ip / client_id) 维度的失败计数 + 临时锁定

内存存储，重启重置。单实例下足够；多实例需换 Redis。
"""
from __future__ import annotations

import logging
import threading
import time
from collections import defaultdict, deque

logger = logging.getLogger(__name__)


class RateLimiter:
    """内存限流 + 爆破锁定。线程安全。"""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        # 限流：{key: deque[timestamps]}（滑动窗口）
        self._rate_counters: dict[str, deque] = defaultdict(deque)
        # 锁定：{key: {"fails": int, "locked_until": float}}
        self._lock_counters: dict[str, dict] = defaultdict(
            lambda: {"fails": 0, "locked_until": 0.0}
        )

    # ---- 限流（滑动窗口）----

    def check_rate(
        self, key: str, max_requests: int, window_sec: float = 60.0
    ) -> tuple[bool, int]:
        """检查是否在限流窗口内允许通过。

        返回 (allowed, remaining)。
        allowed=True 表示允许，remaining 是窗口内剩余配额。
        """
        now = time.monotonic()
        cutoff = now - window_sec

        with self._lock:
            counter = self._rate_counters[key]
            # 清除过期时间戳
            while counter and counter[0] < cutoff:
                counter.popleft()
            # 检查是否超限
            if len(counter) >= max_requests:
                return False, 0
            counter.append(now)
            remaining = max_requests - len(counter)
            return True, remaining

    # ---- 爆破锁定（失败计数 + 临时锁定）----

    def is_locked(self, key: str) -> bool:
        """检查 key 是否处于锁定状态。"""
        with self._lock:
            state = self._lock_counters[key]
            if state["locked_until"] > time.monotonic():
                return True
            # 锁定已过期，重置
            if state["locked_until"] > 0:
                state["locked_until"] = 0.0
                state["fails"] = 0
            return False

    def get_lock_remaining(self, key: str) -> int:
        """获取剩余锁定秒数（0 表示未锁定）。"""
        with self._lock:
            state = self._lock_counters[key]
            remaining = state["locked_until"] - time.monotonic()
            return max(0, int(remaining))

    def record_failure(
        self, key: str, max_fails: int, lockout_sec: float
    ) -> bool:
        """记录一次认证失败。

        返回是否触发了锁定（达到 max_fails）。
        """
        with self._lock:
            state = self._lock_counters[key]
            state["fails"] += 1
            if state["fails"] >= max_fails:
                state["locked_until"] = time.monotonic() + lockout_sec
                logger.warning(
                    "Brute-force lockout triggered: key=%s fails=%d lockout=%.0fs",
                    key, state["fails"], lockout_sec,
                )
                return True
            return False

    def clear_failure(self, key: str) -> None:
        """认证成功后清除失败计数。"""
        with self._lock:
            if key in self._lock_counters:
                self._lock_counters[key]["fails"] = 0
                self._lock_counters[key]["locked_until"] = 0.0

    def get_status(self) -> dict:
        """获取当前状态概览（用于调试/展示）。"""
        with self._lock:
            now = time.monotonic()
            active_locks = sum(
                1 for s in self._lock_counters.values()
                if s["locked_until"] > now
            )
            return {
                "tracked_rate_keys": len(self._rate_counters),
                "tracked_lock_keys": len(self._lock_counters),
                "active_lockouts": active_locks,
            }


# 全局单例
rate_limiter = RateLimiter()
