"""威胁建模服务纯函数测试：风险评分、JSON 解析容错、类别归一化。

这些是项目里最有特色、最值得保护的逻辑（LLM 输出解析的健壮性）。
不依赖 DB，纯函数测试。
"""

from __future__ import annotations

from app.services.threat_model_service import ThreatModelService

# ==================== compute_risk_level ====================


class TestComputeRiskLevel:
    """风险评分：L×I → Low/Medium/High/Critical。"""

    def setup_method(self):
        from app.services.threat_model_service import compute_risk_level

        self.compute = compute_risk_level

    def test_low(self):
        # 1-4 分 → Low
        assert self.compute(1, 1) == "Low"
        assert self.compute(1, 4) == "Low"
        assert self.compute(2, 2) == "Low"
        assert self.compute(4, 1) == "Low"

    def test_medium(self):
        # 5-9 分 → Medium
        assert self.compute(1, 5) == "Medium"
        assert self.compute(5, 1) == "Medium"
        assert self.compute(3, 3) == "Medium"
        assert self.compute(1, 9) == "Medium"

    def test_high(self):
        # 10-16 分 → High
        assert self.compute(2, 5) == "High"
        assert self.compute(5, 2) == "High"
        assert self.compute(4, 4) == "High"
        assert self.compute(5, 3) == "High"

    def test_critical(self):
        # 17-25 分 → Critical
        assert self.compute(5, 4) == "Critical"
        assert self.compute(4, 5) == "Critical"
        assert self.compute(5, 5) == "Critical"

    def test_boundary(self):
        """边界值：恰好 4/5/9/10/16/17。"""
        assert self.compute(2, 2) == "Low"  # 4 → Low
        assert self.compute(1, 5) == "Medium"  # 5 → Medium
        assert self.compute(3, 3) == "Medium"  # 9 → Medium
        assert self.compute(2, 5) == "High"  # 10 → High
        assert self.compute(4, 4) == "High"  # 16 → High
        assert self.compute(5, 4) == "Critical"  # 17 → Critical


# ==================== _parse_threats_json（LLM 输出解析容错） ====================


class TestParseThreatsJson:
    """LLM 输出解析：这是项目最关键的健壮性逻辑。"""

    def setup_method(self):
        self.svc = ThreatModelService()

    def test_clean_json_array(self):
        """干净 JSON 数组。"""
        text = '[{"title": "t1", "category": "S"}]'
        result = self.svc._parse_threats_json(text)
        assert len(result) == 1
        assert result[0]["title"] == "t1"

    def test_markdown_fenced_json(self):
        """带 ```json 围栏。"""
        text = '```json\n[{"title": "t1"}]\n```'
        result = self.svc._parse_threats_json(text)
        assert len(result) == 1
        assert result[0]["title"] == "t1"

    def test_markdown_fenced_no_lang(self):
        """带 ``` 围栏但无语言标识。"""
        text = '```\n[{"title": "t1"}]\n```'
        result = self.svc._parse_threats_json(text)
        assert len(result) == 1

    def test_json_with_surrounding_text(self):
        """JSON 前后有多余文字。"""
        text = '好的，以下是威胁清单：\n[{"title": "t1"}]\n以上是分析结果。'
        result = self.svc._parse_threats_json(text)
        assert len(result) == 1
        assert result[0]["title"] == "t1"

    def test_dict_with_threats_key(self):
        """返回的是 dict 而非 list（带 threats 键）。"""
        text = '{"threats": [{"title": "t1"}]}'
        result = self.svc._parse_threats_json(text)
        assert len(result) == 1
        assert result[0]["title"] == "t1"

    def test_empty_input(self):
        """空输入。"""
        assert self.svc._parse_threats_json("") == []
        assert self.svc._parse_threats_json("   ") == []

    def test_garbage_input(self):
        """完全无法解析的输入。"""
        assert self.svc._parse_threats_json("这不是 JSON") == []

    def test_malformed_json(self):
        """JSON 格式错误。"""
        assert self.svc._parse_threats_json("[{title: t1}]") == []

    def test_multiple_threats(self):
        """多条威胁。"""
        text = '[{"title": "t1"}, {"title": "t2"}, {"title": "t3"}]'
        result = self.svc._parse_threats_json(text)
        assert len(result) == 3


# ==================== _normalize_category ====================


class TestNormalizeCategory:
    """类别归一化：LLM 可能输出中英文/各种写法。"""

    def setup_method(self):
        self.svc = ThreatModelService()

    # STRIDE 单字母
    def test_stride_single_letter(self):
        assert self.svc._normalize_category("S") == "S"
        assert self.svc._normalize_category("T") == "T"
        assert self.svc._normalize_category("R") == "R"
        assert self.svc._normalize_category("I") == "I"
        assert self.svc._normalize_category("D") == "D"
        assert self.svc._normalize_category("E") == "E"

    def test_stride_case_insensitive(self):
        assert self.svc._normalize_category("s") == "S"
        assert self.svc._normalize_category("e") == "E"

    # STRIDE 英文全称
    def test_stride_full_name(self):
        assert self.svc._normalize_category("spoofing") == "S"
        assert self.svc._normalize_category("tampering") == "T"
        assert self.svc._normalize_category("repudiation") == "R"
        assert self.svc._normalize_category("information disclosure") == "I"
        assert self.svc._normalize_category("denial of service") == "D"
        assert self.svc._normalize_category("elevation of privilege") == "E"

    def test_stride_abbreviation(self):
        assert self.svc._normalize_category("dos") == "D"
        assert self.svc._normalize_category("info disclosure") == "I"

    # STRIDE 中文
    def test_stride_chinese(self):
        assert self.svc._normalize_category("伪装") == "S"
        assert self.svc._normalize_category("篡改") == "T"
        assert self.svc._normalize_category("抵赖") == "R"
        assert self.svc._normalize_category("信息泄露") == "I"
        assert self.svc._normalize_category("拒绝服务") == "D"
        assert self.svc._normalize_category("权限提升") == "E"

    # AI 专属
    def test_ai_categories(self):
        assert self.svc._normalize_category("prompt_injection") == "prompt_injection"
        assert self.svc._normalize_category("prompt injection") == "prompt_injection"
        assert self.svc._normalize_category("提示注入") == "prompt_injection"
        assert self.svc._normalize_category("data_poisoning") == "data_poisoning"
        assert self.svc._normalize_category("model_inversion") == "model_inversion"
        assert self.svc._normalize_category("alignment_bypass") == "alignment_bypass"
        assert self.svc._normalize_category("loss_of_provenance") == "loss_of_provenance"

    # 边界
    def test_empty(self):
        assert self.svc._normalize_category("") == "S"
        assert self.svc._normalize_category(None) == "S"

    def test_unknown_falls_back_to_s(self):
        """未知类别兜底为 S。"""
        assert self.svc._normalize_category("unknown_thing") == "S"

    def test_whitespace_trimming(self):
        assert self.svc._normalize_category("  S  ") == "S"
        assert self.svc._normalize_category(" Spoofing ") == "S"
