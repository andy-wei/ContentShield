"""扫描工具基础结构测试：FindingRaw 指纹、注册表、适配器可用性。

不依赖真实工具二进制（用 mock），聚焦测标准化与注册逻辑。
"""

from __future__ import annotations

from app.scan.tools.base import FindingRaw, ToolAdapter, list_available_tools, registry

# ==================== FindingRaw ====================


class TestFindingRawFingerprint:
    def test_fingerprint_deterministic(self):
        """相同输入产生相同指纹。"""
        f1 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f2 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        assert f1.compute_fingerprint() == f2.compute_fingerprint()

    def test_fingerprint_changes_with_file(self):
        f1 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f2 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="b.py", line=10, rule_id="B602"
        )
        assert f1.compute_fingerprint() != f2.compute_fingerprint()

    def test_fingerprint_changes_with_line(self):
        f1 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f2 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=11, rule_id="B602"
        )
        assert f1.compute_fingerprint() != f2.compute_fingerprint()

    def test_fingerprint_changes_with_rule(self):
        f1 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f2 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B603"
        )
        assert f1.compute_fingerprint() != f2.compute_fingerprint()

    def test_fingerprint_changes_with_tool(self):
        """不同工具报同一位置，指纹不同（用于区分来源）。"""
        f1 = FindingRaw(
            tool="bandit", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        f2 = FindingRaw(
            tool="trivy", severity="low", category="sast", file="a.py", line=10, rule_id="B602"
        )
        assert f1.compute_fingerprint() != f2.compute_fingerprint()

    def test_fingerprint_is_32_char_hex(self):
        f = FindingRaw(tool="x", severity="info", category="sast", file="y", line=1, rule_id="z")
        fp = f.compute_fingerprint()
        assert len(fp) == 32
        assert all(c in "0123456789abcdef" for c in fp)

    def test_compute_fingerprint_sets_field(self):
        f = FindingRaw(tool="x", severity="info", category="sast", file="y", line=1, rule_id="z")
        assert f.fingerprint == ""
        f.compute_fingerprint()
        assert f.fingerprint != ""


# ==================== 注册表 ====================


class TestRegistry:
    def test_registry_has_built_in_tools(self):
        """import app.scan.tools 后，内置适配器应已注册。"""
        # 触发导入（确保装饰器执行）
        import app.scan.tools  # noqa: F401

        assert "bandit" in registry
        assert "gitleaks" in registry
        assert "pip-audit" in registry
        assert "trivy" in registry

    def test_get_adapter_returns_instance(self):
        import app.scan.tools  # noqa: F401

        adapter = registry.get("bandit")
        assert adapter is not None
        assert adapter.name == "bandit"
        assert adapter.category == "sast"

    def test_get_adapter_unknown_returns_none(self):
        assert registry.get("nonexistent_tool") is None

    def test_list_available_tools_returns_all(self):
        import app.scan.tools  # noqa: F401

        tools = list_available_tools()
        names = [t["name"] for t in tools]
        assert "bandit" in names
        assert "gitleaks" in names
        # 每项都有必要字段
        for t in tools:
            assert "name" in t
            assert "category" in t
            assert "description" in t
            assert "available" in t
            assert isinstance(t["available"], bool)

    def test_adapter_is_available_checks_path(self):
        """is_available 应返回 bool（不管工具是否真装了）。"""
        import app.scan.tools  # noqa: F401

        for name in ["bandit", "gitleaks", "trivy", "pip-audit", "npm"]:
            adapter = registry[name]
            assert isinstance(adapter.is_available(), bool)


# ==================== ToolAdapter 子类行为 ====================


class TestToolAdapterBase:
    def test_finalize_sets_fingerprint(self):
        """_finalize 应为所有 finding 计算指纹。"""

        class Dummy(ToolAdapter):
            name = "dummy"
            category = "sast"  # type: ignore[assignment]

            def run(self, workdir):
                return [
                    FindingRaw(
                        tool="", severity="low", category="sast", file="a.py", line=1, rule_id="X"
                    ),
                    FindingRaw(
                        tool="", severity="high", category="sast", file="b.py", line=2, rule_id="Y"
                    ),
                ]

        d = Dummy()
        findings = d._finalize(d.run("/tmp"))
        assert all(f.fingerprint for f in findings)
        assert all(f.tool == "dummy" for f in findings)

    def test_finalize_fills_empty_tool(self):
        """finding 未填 tool 时，_finalize 用适配器 name 补全。"""

        class Dummy(ToolAdapter):
            name = "mytool"
            category = "sast"  # type: ignore[assignment]

            def run(self, workdir):
                return [
                    FindingRaw(
                        tool="", severity="low", category="sast", file="a", line=1, rule_id="x"
                    )
                ]

        d = Dummy()
        findings = d._finalize(d.run("/tmp"))
        assert findings[0].tool == "mytool"

    def test_run_not_implemented(self):
        """基类 run 应抛 NotImplementedError。"""

        class NoRun(ToolAdapter):
            name = "norun"

        import pytest

        with pytest.raises(NotImplementedError):
            NoRun().run("/tmp")
