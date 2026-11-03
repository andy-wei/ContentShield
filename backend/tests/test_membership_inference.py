"""成员推理攻击（MIA）测试：探针集、特征提取、MI 统计分析。

纯函数测试，不依赖外部模型服务。
"""

from __future__ import annotations

from app.redteam.membership_inference import (
    DEFAULT_PROBES,
    ResponseFeature,
    analyze_membership,
    extract_features,
    get_default_probes,
)

# ==================== 探针集 ====================


class TestDefaultProbes:
    def test_has_member_and_nonmember(self):
        members = [p for p in DEFAULT_PROBES if p.is_member]
        nonmembers = [p for p in DEFAULT_PROBES if not p.is_member]
        assert len(members) >= 5
        assert len(nonmembers) >= 5

    def test_get_default_probes_returns_copy(self):
        p1 = get_default_probes()
        p1.clear()
        p2 = get_default_probes()
        assert len(p2) > 0  # 清空副本不影响默认集

    def test_probes_have_text(self):
        for p in DEFAULT_PROBES:
            assert p.text
            assert len(p.text) > 5

    def test_problems_have_group(self):
        for p in DEFAULT_PROBES:
            assert p.group  # 便于分析

    def test_balanced_groups(self):
        """member 和 non-member 数量应大致平衡。"""
        members = sum(1 for p in DEFAULT_PROBES if p.is_member)
        nonmembers = sum(1 for p in DEFAULT_PROBES if not p.is_member)
        assert abs(members - nonmembers) <= 2


# ==================== 特征提取 ====================


class TestExtractFeatures:
    def test_extracts_length(self):
        f = extract_features("q", True, "hello world this is a response")
        assert f.response_length == len("hello world this is a response")

    def test_certainty_increases_with_definite_words(self):
        """确定性词汇应提高 certainty 分数。"""
        f_certain = extract_features("q", True, "Yes, definitely correct.")
        f_neutral = extract_features("q", True, "The cat sat on the mat.")
        assert f_certain.certainty_score > f_neutral.certainty_score

    def test_certainty_decreases_with_uncertain_words(self):
        """不确定性词汇应降低 certainty 分数。"""
        f_uncertain = extract_features("q", True, "Maybe it's possible, perhaps.")
        f_neutral = extract_features("q", True, "The cat sat on the mat.")
        assert f_uncertain.certainty_score < f_neutral.certainty_score

    def test_short_response_higher_certainty(self):
        """短回复应比长回复 certainty 更高（更直接 = 更确定）。"""
        f_short = extract_features("q", True, "Yes.")
        f_long = extract_features(
            "q", True, "Well, that's an interesting question and there are many " * 10
        )
        assert f_short.certainty_score > f_long.certainty_score

    def test_chinese_certainty_markers(self):
        f = extract_features("q", True, "是的，确实如此，没错。")
        assert f.certainty_score > 0.5

    def test_chinese_uncertainty_markers(self):
        f = extract_features("q", True, "可能吧，也许是这样，我不太清楚。")
        assert f.certainty_score < 0.5

    def test_empty_response(self):
        f = extract_features("q", True, "")
        assert f.response_length == 0
        assert f.certainty_score == 0.0

    def test_preserves_metadata(self):
        f = extract_features("probe text", False, "resp", latency_ms=150)
        assert f.text == "probe text"
        assert f.is_member is False
        assert f.latency_ms == 150

    def test_certainty_bounded(self):
        """certainty 应在 [0, 1] 范围内。"""
        for resp in ["definitely yes correct", "maybe perhaps possibly might", "", "x" * 500]:
            f = extract_features("q", True, resp)
            assert 0.0 <= f.certainty_score <= 1.0


# ==================== MI 统计分析 ====================


class TestAnalyzeMembership:
    def test_clear_separation_detected(self):
        """member 回复明显更确定时，应检测到泄露信号。"""
        # member: 高 certainty；non-member: 低 certainty
        features = [
            ResponseFeature("m1", True, "Yes, definitely.", 15, 0.9, 100),
            ResponseFeature("m2", True, "Correct, exactly.", 16, 0.85, 100),
            ResponseFeature("m3", True, "Yes.", 4, 0.95, 100),
            ResponseFeature("n1", False, "Maybe, perhaps it could be.", 26, 0.2, 100),
            ResponseFeature("n2", False, "I'm not sure, possibly.", 22, 0.15, 100),
            ResponseFeature("n3", False, "It might be, I think so.", 24, 0.25, 100),
        ]
        result = analyze_membership(features)
        assert result.certainty_gap > 0.5
        assert result.mi_advantage > 0.3
        assert result.risk_level in ("high", "critical")

    def test_no_separation_low_risk(self):
        """member 和 non-member 响应无差异时，风险应低。"""
        features = [
            ResponseFeature("m1", True, "resp", 4, 0.5, 100),
            ResponseFeature("m2", True, "resp", 4, 0.5, 100),
            ResponseFeature("n1", False, "resp", 4, 0.5, 100),
            ResponseFeature("n2", False, "resp", 4, 0.5, 100),
        ]
        result = analyze_membership(features)
        assert result.mi_advantage <= 0.05
        assert result.risk_level == "low"

    def test_mi_advantage_nonneg(self):
        """MI Advantage 应非负（最差是 0 = 随机猜测水平）。"""
        features = [
            ResponseFeature("m1", True, "r", 1, 0.3, 100),
            ResponseFeature("n1", False, "r", 1, 0.9, 100),  # non-member 反而更确定
        ]
        result = analyze_membership(features)
        # 即使反向，枚举阈值仍能找到 >= 0.5 的准确率
        assert result.mi_advantage >= 0.0

    def test_empty_features(self):
        result = analyze_membership([])
        assert "探针不足" in result.interpretation

    def test_only_members(self):
        features = [ResponseFeature("m1", True, "r", 1, 0.5, 100)]
        result = analyze_membership(features)
        assert "探针不足" in result.interpretation

    def test_interpretation_contains_metrics(self):
        features = [
            ResponseFeature("m1", True, "definitely", 10, 0.8, 100),
            ResponseFeature("n1", False, "maybe", 6, 0.3, 100),
        ]
        result = analyze_membership(features)
        assert "MI Advantage" in result.interpretation
        assert "certainty 差距" in result.interpretation
        assert "风险等级" in result.interpretation

    def test_per_probe_details(self):
        features = [
            ResponseFeature("m1", True, "resp", 10, 0.8, 100),
            ResponseFeature("n1", False, "resp", 8, 0.4, 120),
        ]
        result = analyze_membership(features)
        assert len(result.per_probe) == 2
        assert result.per_probe[0]["is_member"] is True
        assert "certainty" in result.per_probe[0]

    def test_member_avg_higher_when_leak(self):
        """有泄露时，member 平均 certainty 应高于 non-member。"""
        features = [
            ResponseFeature("m1", True, "r", 1, 0.9, 100),
            ResponseFeature("m2", True, "r", 1, 0.8, 100),
            ResponseFeature("n1", False, "r", 1, 0.3, 100),
            ResponseFeature("n2", False, "r", 1, 0.2, 100),
        ]
        result = analyze_membership(features)
        assert result.member_avg_certainty > result.nonmember_avg_certainty

    def test_risk_levels_thresholds(self):
        """验证风险等级能正确识别严重的成员关系泄露。"""
        # critical: member/non-member certainty 差异巨大
        big = analyze_membership(
            [
                ResponseFeature("m1", True, "r", 1, 0.95, 100),
                ResponseFeature("m2", True, "r", 1, 0.90, 100),
                ResponseFeature("n1", False, "r", 1, 0.10, 100),
                ResponseFeature("n2", False, "r", 1, 0.15, 100),
            ]
        )
        assert big.risk_level == "critical"
        assert big.certainty_gap > 0.5
        assert big.mi_advantage > 0.3
