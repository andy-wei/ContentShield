"""数据集扫描结果推断逻辑测试：issue_types/poison_type/is_flagged。"""

from __future__ import annotations

from app.training.dataset_scanner import ScanRecordResult
from app.training.poison_patterns import PoisonHit


def _make_result(
    decision="pass",
    layers=None,
    categories=None,
    poison_hits=None,
) -> ScanRecordResult:
    return ScanRecordResult(
        record_idx=0,
        record_hash="abc123",
        decision=decision,
        risk_score=0.0,
        layers=layers or {},
        categories=categories or [],
        poison_hits=poison_hits or [],
    )


# ==================== issue_types 推断 ====================


class TestIssueTypesInference:
    def test_dlp_hit_infers_pii(self):
        r = _make_result(layers={"dlp": {"hit": True}})
        assert "pii" in r.issue_types

    def test_llama_guard_hit_infers_toxic(self):
        r = _make_result(layers={"llama_guard": {"hit": True}})
        assert "toxic" in r.issue_types

    def test_prompt_guard_hit_infers_injection(self):
        r = _make_result(layers={"prompt_guard": {"hit": True}})
        assert "injection" in r.issue_types

    def test_indirect_injection_hit(self):
        r = _make_result(layers={"indirect_injection": {"hit": True}})
        assert "injection" in r.issue_types

    def test_poison_hit_infers_poison(self):
        r = _make_result(poison_hits=[PoisonHit("instruction_injection", "high", "x", "y")])
        assert "poison" in r.issue_types

    def test_secret_category_infers_secret(self):
        r = _make_result(categories=["secret:API Key"])
        assert "secret" in r.issue_types

    def test_credential_category_infers_secret(self):
        r = _make_result(categories=["credential:JWT"])
        assert "secret" in r.issue_types

    def test_clean_record_no_issues(self):
        r = _make_result()
        assert r.issue_types == []

    def test_multiple_issues(self):
        r = _make_result(
            layers={"dlp": {"hit": True}, "llama_guard": {"hit": True}},
            poison_hits=[PoisonHit("role_override", "high", "x", "y")],
        )
        assert "pii" in r.issue_types
        assert "toxic" in r.issue_types
        assert "poison" in r.issue_types

    def test_layers_without_hit_no_issue(self):
        """层存在但 hit=False 不应产生 issue。"""
        r = _make_result(layers={"dlp": {"hit": False}})
        assert r.issue_types == []


# ==================== poison_type 推断 ====================


class TestPoisonTypeInference:
    def test_no_poison_returns_empty(self):
        r = _make_result()
        assert r.poison_type == ""

    def test_single_poison_returns_its_type(self):
        r = _make_result(poison_hits=[PoisonHit("hidden_trigger", "medium", "x", "y")])
        assert r.poison_type == "hidden_trigger"

    def test_high_severity_takes_priority(self):
        """多个投毒命中时，取最高严重度的类型。"""
        r = _make_result(
            poison_hits=[
                PoisonHit("format_anomaly", "low", "x", "y"),
                PoisonHit("instruction_injection", "high", "x", "y"),
                PoisonHit("repeated_pattern", "medium", "x", "y"),
            ]
        )
        assert r.poison_type == "instruction_injection"

    def test_medium_beats_low(self):
        r = _make_result(
            poison_hits=[
                PoisonHit("format_anomaly", "low", "x", "y"),
                PoisonHit("repeated_pattern", "medium", "x", "y"),
            ]
        )
        assert r.poison_type == "repeated_pattern"


# ==================== is_flagged ====================


class TestIsFlagged:
    def test_pass_decision_no_poison_not_flagged(self):
        r = _make_result(decision="pass")
        assert r.is_flagged is False

    def test_block_decision_flagged(self):
        r = _make_result(decision="block")
        assert r.is_flagged is True

    def test_warn_decision_flagged(self):
        r = _make_result(decision="warn")
        assert r.is_flagged is True

    def test_modify_decision_flagged(self):
        r = _make_result(decision="modify")
        assert r.is_flagged is True

    def test_poison_hit_flagged_even_pass(self):
        """即使 decision=pass，有投毒命中也应标记。"""
        r = _make_result(decision="pass", poison_hits=[PoisonHit("x", "low", "y", "z")])
        assert r.is_flagged is True

    def test_clean_not_flagged(self):
        r = _make_result(decision="pass", layers={"dlp": {"hit": False}})
        assert r.is_flagged is False


# ==================== 集成回归测试（覆盖真实运行发现的 bug）====================


class TestPydanticLayersCompat:
    """回归测试：orchestrator 返回的 layers 值可能是 pydantic 对象（LayerResult），
    issue_types 推断和 JSON 序列化必须兼容这种情况。

    这些 bug 在本地启动验证时发现（单元测试覆盖不到，需真实 orchestrator 集成）。
    """

    def test_issue_types_with_pydantic_layer_object(self):
        """layers 值是 pydantic-like 对象（有 .hit 属性）时应正确推断 issue_types。"""

        class FakeLayerResult:
            """模拟 orchestrator 返回的 LayerResult pydantic 对象。"""

            def __init__(self, hit: bool, decision: str = "pass"):
                self.hit = hit
                self.decision = decision

        # DLP 层命中（pydantic 对象形式）→ 应推断出 pii
        r = _make_result(layers={"dlp": FakeLayerResult(hit=True, decision="modify")})
        assert "pii" in r.issue_types

        # llama_guard 命中 → toxic
        r = _make_result(layers={"llama_guard": FakeLayerResult(hit=True, decision="block")})
        assert "toxic" in r.issue_types

        # prompt_guard 命中 → injection
        r = _make_result(layers={"prompt_guard": FakeLayerResult(hit=True)})
        assert "injection" in r.issue_types

    def test_issue_types_with_dict_layer(self):
        """layers 值是 dict 形式也应正常工作（向后兼容）。"""
        r = _make_result(layers={"dlp": {"hit": True, "decision": "modify"}})
        assert "pii" in r.issue_types

    def test_issue_types_mixed_dict_and_object(self):
        """混合 dict 和 pydantic 对象。"""

        class FakeLayer:
            def __init__(self, hit):
                self.hit = hit

        r = _make_result(
            layers={
                "dlp": {"hit": True},  # dict 形式
                "llama_guard": FakeLayer(hit=True),  # pydantic 对象形式
            }
        )
        assert "pii" in r.issue_types
        assert "toxic" in r.issue_types


class TestScanRecordResultConstruction:
    """回归测试：ScanRecordResult 必须接收 record_idx 参数。

    bug：scan_record 函数曾遗漏传 record_idx，导致
    'ScanRecordResult.__init__() missing record_idx' 运行时错误。
    """

    def test_record_idx_required(self):
        """构造时必须能传 record_idx。"""
        r = ScanRecordResult(record_idx=42, record_hash="abc")
        assert r.record_idx == 42

    def test_record_idx_preserved_in_scan_record(self):
        """scan_record 应把传入的 record_idx 保存到结果中。"""
        import asyncio

        from app.training.dataset_scanner import scan_record

        class FakeOrch:
            async def moderate(self, text, **kw):
                return {"decision": "pass", "risk_score": 0.0, "layers": {}, "categories": []}

        result = asyncio.run(scan_record("test text", FakeOrch(), record_idx=7))
        assert result.record_idx == 7


class TestLayersJsonSerializable:
    """回归测试：ScanRecordResult.layers 必须可 JSON 序列化。

    bug：orchestrator 返回的 layers 含 pydantic 对象，json.dumps 失败。
    scan_record 现在用 _layers_to_dict 转换。
    """

    def test_layers_serializable_after_pydantic_input(self):
        """模拟 orchestrator 返回 pydantic layers，验证 scan_record 后可序列化。"""
        import asyncio
        import json

        from app.training.dataset_scanner import scan_record

        class FakeLayerResult:
            def __init__(self, hit, decision="pass"):
                self.hit = hit
                self.decision = decision

        class FakeOrch:
            async def moderate(self, text, **kw):
                return {
                    "decision": "warn",
                    "risk_score": 0.5,
                    "layers": {"dlp": FakeLayerResult(hit=True, decision="modify")},
                    "categories": ["pii"],
                }

        result = asyncio.run(scan_record("my phone 13812345678", FakeOrch(), record_idx=0))
        # 关键：layers 必须能 JSON 序列化（之前会抛 TypeError）
        serialized = json.dumps(result.layers, ensure_ascii=False)
        assert "dlp" in serialized
        assert "hit" in serialized
