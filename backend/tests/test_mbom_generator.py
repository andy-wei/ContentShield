"""MBOM 核心功能测试：哈希计算、完整性校验、License 合规、模型卡解析、风险评估。

纯函数测试，不依赖外部服务。
"""

from __future__ import annotations

from app.mbom.generator import (
    assess_license,
    assess_supply_chain_risk,
    compute_file_hash,
    compute_hash,
    parse_model_card,
    verify_integrity,
)

# ==================== 哈希计算 ====================


class TestComputeHash:
    def test_text_hash_deterministic(self):
        assert compute_hash("hello") == compute_hash("hello")

    def test_text_hash_different(self):
        assert compute_hash("hello") != compute_hash("world")

    def test_sha256_length(self):
        assert len(compute_hash("x")) == 64

    def test_md5_length(self):
        assert len(compute_hash("x", "md5")) == 32

    def test_unicode(self):
        h = compute_hash("中文")
        assert len(h) == 64


class TestComputeFileHash:
    def test_existing_file(self, tmp_path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"fake model weights")
        h = compute_file_hash(str(f))
        assert len(h) == 64
        assert h == compute_hash("fake model weights")

    def test_nonexistent_file(self):
        assert compute_file_hash("/nonexistent/path") == ""

    def test_large_file_streaming(self, tmp_path):
        """大文件应能流式计算（不一次性读入内存）。"""
        f = tmp_path / "big.bin"
        # 写 5MB 数据
        chunk = b"x" * (1024 * 1024)
        with open(f, "wb") as fp:
            for _ in range(5):
                fp.write(chunk)
        h = compute_file_hash(str(f))
        assert len(h) == 64

    def test_empty_file(self, tmp_path):
        f = tmp_path / "empty"
        f.write_bytes(b"")
        h = compute_file_hash(str(f))
        assert len(h) == 64  # 空文件也有合法哈希


# ==================== 完整性校验 ====================


class TestVerifyIntegrity:
    def test_verified(self, tmp_path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"original content")
        expected = compute_hash("original content")
        result = verify_integrity(str(f), expected)
        assert result.verified is True
        assert result.actual_sha256 == expected

    def test_tampered(self, tmp_path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"tampered content")
        expected = compute_hash("original content")  # 不同的哈希
        result = verify_integrity(str(f), expected)
        assert result.verified is False
        assert "篡改" in result.message

    def test_nonexistent_file(self):
        result = verify_integrity("/nonexistent", "abc123")
        assert result.verified is False
        assert "不存在" in result.message

    def test_no_expected_hash(self, tmp_path):
        f = tmp_path / "model.bin"
        f.write_bytes(b"content")
        result = verify_integrity(str(f), "")
        assert result.verified is False
        assert "无期望哈希" in result.message
        assert result.actual_sha256 != ""  # 实际哈希仍计算了

    def test_case_insensitive_hash(self, tmp_path):
        f = tmp_path / "m.bin"
        f.write_bytes(b"x")
        expected = compute_hash("x").upper()
        result = verify_integrity(str(f), expected)
        assert result.verified is True


# ==================== License 合规 ====================


class TestAssessLicense:
    def test_mit_is_safe(self):
        result = assess_license("MIT")
        assert result.risk_level == "safe"
        assert result.commercial_use is True

    def test_apache_is_safe(self):
        result = assess_license("Apache-2.0")
        assert result.risk_level == "safe"

    def test_bsd_is_safe(self):
        result = assess_license("BSD-3-Clause")
        assert result.risk_level == "safe"

    def test_gpl_is_restricted(self):
        result = assess_license("GPL-3.0")
        assert result.risk_level == "restricted"

    def test_cc_by_nc_is_restricted_no_commercial(self):
        result = assess_license("CC-BY-NC-4.0")
        assert result.risk_level == "restricted"
        assert result.commercial_use is False

    def test_llama_license_caution(self):
        result = assess_license("llama-3-license")
        assert result.risk_level == "caution"
        assert result.commercial_use is True
        assert "Llama" in result.note

    def test_unknown_license(self):
        result = assess_license("unknown")
        assert result.risk_level == "unknown"

    def test_empty_license(self):
        result = assess_license("")
        assert result.risk_level == "unknown"

    def test_custom_license(self):
        result = assess_license("some-weird-license-2024")
        assert result.risk_level == "unknown"

    def test_case_insensitive(self):
        assert assess_license("mit").risk_level == "safe"
        assert assess_license("Mit").risk_level == "safe"
        assert assess_license("MIT").risk_level == "safe"


# ==================== 模型卡解析 ====================


class TestParseModelCard:
    def test_parses_yaml_frontmatter(self):
        content = """---
license: apache-2.0
language: en
tags:
  - safety
  - llama
---
# Llama Guard 4

A safety classification model."""
        result = parse_model_card(content)
        assert result["license"] == "apache-2.0"
        assert result["language"] == ["en"]
        assert "safety" in result["tags"]
        assert "Llama Guard 4" in result["description"]

    def test_no_frontmatter(self):
        content = "# Just a markdown\n\nNo YAML here."
        result = parse_model_card(content)
        assert result["license"] == ""
        assert "Just a markdown" in result["description"]

    def test_multiple_languages(self):
        content = """---
language:
  - en
  - zh
  - ja
---
# Model"""
        result = parse_model_card(content)
        assert result["language"] == ["en", "zh", "ja"]

    def test_empty_content(self):
        result = parse_model_card("")
        assert result["license"] == ""

    def test_description_truncated(self):
        long_desc = "x" * 1000
        content = f"# Title\n\n{long_desc}"
        result = parse_model_card(content)
        assert len(result["description"]) <= 500

    def test_tags_list(self):
        content = """---
tags:
  - pytorch
  - safetensors
---
# M"""
        result = parse_model_card(content)
        assert "pytorch" in result["tags"]
        assert "safetensors" in result["tags"]


# ==================== 供应链风险评估 ====================


class TestAssessSupplyChainRisk:
    def test_safe_artifact_low_risk(self):
        """可信来源 + 宽松 license + 已校验 + 已签名 → 低风险。"""
        risk = assess_supply_chain_risk(
            {
                "source": "internal",
                "license": "apache-2.0",
                "integrity_status": "verified",
                "signature_status": "verified",
            }
        )
        assert risk.risk_level == "low"
        assert risk.risk_score < 20
        assert len(risk.issues) == 0 or len(risk.issues) == 0

    def test_huggingface_source_adds_risk(self):
        risk = assess_supply_chain_risk(
            {
                "source": "huggingface",
                "license": "apache-2.0",
                "integrity_status": "verified",
                "signature_status": "verified",
            }
        )
        assert risk.risk_score >= 10
        assert any("HuggingFace" in i for i in risk.issues)

    def test_unknown_source_high_risk(self):
        risk = assess_supply_chain_risk(
            {
                "source": "custom",
                "license": "unknown",
                "integrity_status": "unknown",
                "signature_status": "unsigned",
            }
        )
        assert risk.risk_level in ("high", "critical")
        assert risk.risk_score >= 50

    def test_tampered_integrity_critical(self):
        """篡改的文件 → 高风险。"""
        risk = assess_supply_chain_risk(
            {
                "source": "huggingface",
                "license": "mit",
                "integrity_status": "tampered",
                "signature_status": "verified",
            }
        )
        assert risk.risk_level in ("high", "critical")
        assert any("篡改" in i for i in risk.issues)

    def test_restricted_license_adds_risk(self):
        risk = assess_supply_chain_risk(
            {
                "source": "internal",
                "license": "GPL-3.0",
                "integrity_status": "verified",
                "signature_status": "verified",
            }
        )
        assert risk.risk_score >= 25
        assert any("限制性" in i for i in risk.issues)

    def test_unsigned_adds_risk(self):
        risk = assess_supply_chain_risk(
            {
                "source": "internal",
                "license": "mit",
                "integrity_status": "verified",
                "signature_status": "unsigned",
            }
        )
        assert risk.risk_score >= 15
        assert any("未签名" in i for i in risk.issues)

    def test_recommendations_provided(self):
        risk = assess_supply_chain_risk(
            {
                "source": "custom",
                "license": "unknown",
                "integrity_status": "unknown",
                "signature_status": "unsigned",
            }
        )
        assert len(risk.recommendations) > 0

    def test_risk_score_capped_at_100(self):
        """风险分上限 100。"""
        risk = assess_supply_chain_risk(
            {
                "source": "custom",
                "license": "GPL-3.0",
                "integrity_status": "tampered",
                "signature_status": "failed",
            }
        )
        assert risk.risk_score <= 100

    def test_risk_levels_order(self):
        """风险等级正确分级。"""
        low = assess_supply_chain_risk(
            {
                "source": "internal",
                "license": "mit",
                "integrity_status": "verified",
                "signature_status": "verified",
            }
        )
        high = assess_supply_chain_risk(
            {
                "source": "custom",
                "license": "unknown",
                "integrity_status": "tampered",
                "signature_status": "failed",
            }
        )
        assert low.risk_score < high.risk_score
