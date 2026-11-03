"""限流器测试：滑动窗口限流 + 暴力破解锁定。"""

from __future__ import annotations

from app.security.rate_limiter import RateLimiter


class TestCheckRate:
    def test_allows_under_limit(self):
        rl = RateLimiter()
        for _ in range(5):
            allowed, _ = rl.check_rate("k", 10, window_sec=60.0)
            assert allowed is True

    def test_blocks_over_limit(self):
        rl = RateLimiter()
        for _ in range(3):
            rl.check_rate("k", 3, window_sec=60.0)
        allowed, remaining = rl.check_rate("k", 3, window_sec=60.0)
        assert allowed is False
        assert remaining == 0

    def test_remaining_decrements(self):
        rl = RateLimiter()
        _, r1 = rl.check_rate("k", 5, window_sec=60.0)
        assert r1 == 4
        _, r2 = rl.check_rate("k", 5, window_sec=60.0)
        assert r2 == 3

    def test_different_keys_independent(self):
        rl = RateLimiter()
        rl.check_rate("a", 1, window_sec=60.0)
        # a 已达上限，b 仍可
        allowed_a, _ = rl.check_rate("a", 1, window_sec=60.0)
        allowed_b, _ = rl.check_rate("b", 1, window_sec=60.0)
        assert allowed_a is False
        assert allowed_b is True

    def test_window_expiry(self):
        """过期时间戳应在窗口外被清除（用极小窗口验证逻辑）。"""
        rl = RateLimiter()
        # 0.01 秒窗口
        rl.check_rate("k", 1, window_sec=0.01)
        import time

        time.sleep(0.02)
        allowed, _ = rl.check_rate("k", 1, window_sec=0.01)
        assert allowed is True


class TestLockout:
    def test_not_locked_initially(self):
        rl = RateLimiter()
        assert rl.is_locked("k") is False

    def test_lock_after_max_fails(self):
        rl = RateLimiter()
        triggered = False
        for _ in range(5):
            triggered = rl.record_failure("k", max_fails=5, lockout_sec=60.0)
        assert triggered is True
        assert rl.is_locked("k") is True

    def test_no_lock_before_max(self):
        rl = RateLimiter()
        for _ in range(4):
            rl.record_failure("k", max_fails=5, lockout_sec=60.0)
        assert rl.is_locked("k") is False

    def test_lock_remaining_positive(self):
        rl = RateLimiter()
        rl.record_failure("k", max_fails=1, lockout_sec=60.0)
        remaining = rl.get_lock_remaining("k")
        assert 0 < remaining <= 60

    def test_lock_remaining_zero_when_not_locked(self):
        rl = RateLimiter()
        assert rl.get_lock_remaining("k") == 0

    def test_clear_failure_resets(self):
        rl = RateLimiter()
        for _ in range(3):
            rl.record_failure("k", max_fails=5, lockout_sec=60.0)
        rl.clear_failure("k")
        assert rl.is_locked("k") is False
        # 再次失败应从 0 开始
        triggered = rl.record_failure("k", max_fails=5, lockout_sec=60.0)
        assert triggered is False

    def test_independent_keys(self):
        rl = RateLimiter()
        rl.record_failure("a", max_fails=1, lockout_sec=60.0)
        assert rl.is_locked("a") is True
        assert rl.is_locked("b") is False

    def test_get_status(self):
        rl = RateLimiter()
        rl.check_rate("rate-key", 10, window_sec=60.0)
        rl.record_failure("lock-key", max_fails=1, lockout_sec=60.0)
        status = rl.get_status()
        assert status["tracked_rate_keys"] >= 1
        assert status["tracked_lock_keys"] >= 1
        assert status["active_lockouts"] >= 1
