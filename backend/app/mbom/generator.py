"""MBOM 核心功能：哈希计算、完整性校验、模型卡解析、风险评估。

纯函数为主，便于测试。
"""

from __future__ import annotations

import hashlib
import logging
import os
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)


@dataclass
class IntegrityResult:
    """完整性校验结果。"""

    verified: bool
    actual_sha256: str
    expected_sha256: str
    message: str


# ==================== 哈希计算 ====================


def compute_file_hash(file_path: str, algorithm: str = "sha256") -> str:
    """计算文件哈希（支持大文件流式读取）。

    Args:
        file_path: 文件路径
        algorithm: sha256（默认）/ md5 / sha1

    Returns:
        十六进制哈希字符串；文件不存在返回空
    """
    if not os.path.isfile(file_path):
        return ""

    h = hashlib.new(algorithm)
    chunk_size = 1024 * 1024  # 1MB 流式读取，支持大模型文件
    try:
        with open(file_path, "rb") as f:
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except OSError as e:
        logger.warning("计算哈希失败 %s: %s", file_path, e)
        return ""


def compute_hash(text: str, algorithm: str = "sha256") -> str:
    """计算文本哈希（用于测试和小数据）。"""
    return hashlib.new(algorithm, text.encode()).hexdigest()


# ==================== 完整性校验 ====================


def verify_integrity(file_path: str, expected_sha256: str) -> IntegrityResult:
    """校验文件完整性：实际哈希 vs 期望哈希。

    Args:
        file_path: 文件路径
        expected_sha256: 期望的 SHA256 哈希

    Returns:
        IntegrityResult：verified=True 表示文件未被篡改
    """
    actual = compute_file_hash(file_path)

    if not actual:
        return IntegrityResult(
            verified=False,
            actual_sha256="",
            expected_sha256=expected_sha256,
            message="文件不存在或无法读取",
        )

    if not expected_sha256:
        return IntegrityResult(
            verified=False,
            actual_sha256=actual,
            expected_sha256="",
            message="无期望哈希，无法校验",
        )

    verified = actual.lower() == expected_sha256.lower()
    if verified:
        message = "完整性校验通过"
    else:
        message = "完整性校验失败：文件可能被篡改"

    return IntegrityResult(
        verified=verified,
        actual_sha256=actual,
        expected_sha256=expected_sha256,
        message=message,
    )


# ==================== License 合规检查 ====================

# 已知安全的 license（允许商业使用）
SAFE_LICENSES = {
    "mit",
    "apache-2.0",
    "apache 2.0",
    "bsd-3-clause",
    "bsd-2-clause",
    "isc",
    "cc0-1.0",
    "cc-by-4.0",
    "cc-by-sa-4.0",
    "mpl-2.0",
}

# 高风险 license（限制商用 / 需特别注意）
RISKY_LICENSES = {
    "gpl-3.0",
    "gpl-2.0",
    "agpl-3.0",
    "lgpl-3.0",
    "cc-by-nc-4.0",
    "cc-by-nc-sa-4.0",
    "research-only",
    "proprietary",
}

# Llama 系列 license（Meta 自定义，允许商用但有使用限制）
LLAMA_LICENSES = {"llama-3-license", "llama-license", "llama3-license"}


@dataclass
class LicenseAssessment:
    """License 合规评估。"""

    license: str
    risk_level: str  # safe / caution / restricted / unknown
    commercial_use: bool
    note: str


def assess_license(license_name: str) -> LicenseAssessment:
    """评估 license 的合规风险。"""
    if not license_name or license_name.lower() == "unknown":
        return LicenseAssessment(
            license=license_name,
            risk_level="unknown",
            commercial_use=False,
            note="License 未知，需人工确认合规性",
        )

    normalized = license_name.lower().strip()

    if normalized in SAFE_LICENSES:
        return LicenseAssessment(
            license=license_name,
            risk_level="safe",
            commercial_use=True,
            note="宽松 license，允许商业使用",
        )

    if normalized in LLAMA_LICENSES:
        return LicenseAssessment(
            license=license_name,
            risk_level="caution",
            commercial_use=True,
            note="Llama 自定义 license，允许商用但有月活用户限制（>7亿需授权）",
        )

    if normalized in RISKY_LICENSES:
        commercial = "nc" not in normalized and "non-commercial" not in normalized
        return LicenseAssessment(
            license=license_name,
            risk_level="restricted",
            commercial_use=commercial,
            note="限制性 license，需法务审核",
        )

    return LicenseAssessment(
        license=license_name,
        risk_level="unknown",
        commercial_use=False,
        note="非标准 license，需人工确认",
    )


# ==================== HuggingFace 模型卡解析 ====================


def parse_model_card(content: str) -> dict:
    """解析 HuggingFace 模型卡（README.md）的 YAML frontmatter + Markdown。

    HF 模型卡格式：
        ---
        license: apache-2.0
        language: en
        tags:
          - safety
        ---
        # Model description
        ...
    """
    import re

    result: dict = {
        "license": "",
        "language": [],
        "tags": [],
        "description": "",
        "raw_yaml": {},
    }

    # 提取 YAML frontmatter
    yaml_match = re.match(r"^---\s*\n(.*?)\n---\s*\n", content, re.DOTALL)
    if yaml_match:
        yaml_text = yaml_match.group(1)
        result["raw_yaml"] = _parse_simple_yaml(yaml_text)
        result["license"] = result["raw_yaml"].get("license", "")
        result["language"] = result["raw_yaml"].get("language", [])
        if isinstance(result["language"], str):
            result["language"] = [result["language"]]
        result["tags"] = result["raw_yaml"].get("tags", [])
        description = content[yaml_match.end() :]
    else:
        description = content

    # 提取描述（第一个标题后的内容，限 500 字符）
    result["description"] = description.strip()[:500]

    return result


def _parse_simple_yaml(yaml_text: str) -> dict:
    """简易 YAML 解析（不依赖 PyYAML，处理常见的 key: value 和列表）。"""
    result: dict = {}
    current_key = None

    for line in yaml_text.split("\n"):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        # 列表项：  - value
        if stripped.startswith("- ") and current_key:
            value = stripped[2:].strip()
            if not isinstance(result.get(current_key), list):
                result[current_key] = []
            result[current_key].append(value)
            continue

        # key: value
        if ":" in stripped:
            key, _, value = stripped.partition(":")
            key = key.strip()
            value = value.strip()
            current_key = key
            if value:
                result[key] = value
            else:
                result[key] = []

    return result


# ==================== 供应链风险评估 ====================


@dataclass
class SupplyChainRisk:
    """供应链风险评估。"""

    risk_level: str  # low / medium / high / critical
    risk_score: int  # 0-100
    issues: list[str] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


def assess_supply_chain_risk(artifact: dict) -> SupplyChainRisk:
    """评估单个模型制品的供应链风险。

    Args:
        artifact: 模型制品的 dict（含 source/license/integrity/signature 等字段）
    """
    risk_score = 0
    issues: list[str] = []
    recommendations: list[str] = []

    source = artifact.get("source", "unknown")
    license_name = artifact.get("license", "unknown")
    integrity = artifact.get("integrity_status", "unknown")
    signature = artifact.get("signature_status", "unsigned")

    # 来源风险
    if source == "huggingface":
        risk_score += 10
        issues.append("来源为 HuggingFace（开放平台，需验证上传者可信度）")
        recommendations.append("确认上传者是否为官方账号，检查下载量与评分")
    elif source == "custom" or source == "unknown":
        risk_score += 30
        issues.append("来源不明，供应链风险高")
        recommendations.append("明确模型来源，优先使用可信来源")

    # License 风险
    license_assessment = assess_license(license_name)
    if license_assessment.risk_level == "restricted":
        risk_score += 25
        issues.append(f"License 限制性：{license_name}（{license_assessment.note}）")
        recommendations.append("法务审核 license 合规性后再使用")
    elif license_assessment.risk_level == "unknown":
        risk_score += 15
        issues.append("License 未知，存在合规风险")
        recommendations.append("确认并记录模型的 license")
    elif license_assessment.risk_level == "caution":
        risk_score += 10
        issues.append(f"License 需注意：{license_assessment.note}")

    # 完整性风险
    if integrity == "tampered":
        risk_score += 40
        issues.append("❌ 文件完整性校验失败，可能被篡改")
        recommendations.append("立即停止使用，重新从可信来源下载")
    elif integrity == "unknown":
        risk_score += 20
        issues.append("未进行完整性校验")
        recommendations.append("计算并记录 SHA256 哈希，定期校验")

    # 签名风险
    if signature == "unsigned":
        risk_score += 15
        issues.append("模型未签名，无法验证来源真实性")
        recommendations.append("使用 cosign 等工具对模型签名")
    elif signature == "failed":
        risk_score += 35
        issues.append("❌ 签名验证失败")
        recommendations.append("停止使用，重新获取可信签名版本")

    # 确定风险等级
    if risk_score >= 60:
        level = "critical"
    elif risk_score >= 40:
        level = "high"
    elif risk_score >= 20:
        level = "medium"
    else:
        level = "low"

    return SupplyChainRisk(
        risk_level=level,
        risk_score=min(risk_score, 100),
        issues=issues,
        recommendations=recommendations,
    )
