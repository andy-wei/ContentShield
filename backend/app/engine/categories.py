"""Llama-Guard-4 官方危害类别（S1-S14，MLCommons 分类法）。

来源：https://www.llama.com/docs/model-cards-and-prompt-formats/llama-guard-4/
描述用于构造 <CATEGORIES> 提示词。可在 UI 中覆盖 description。
"""
from __future__ import annotations

# (code, name, description, layer, order)
# 核心安全类别（S1/S2/S7/S9/S10/S14）默认启用，其余默认关闭。
# 原因：f16 GGUF 在 14 类别全开时分类能力下降，聚焦核心类别准确率更高。
# 用户可在 UI 的「策略配置」页按需启用更多类别。
CORE_ENABLED = {"S1", "S2", "S7", "S9", "S10", "S14"}

DEFAULT_CATEGORIES: list[dict] = [
    {
        "code": "S1",
        "name": "暴力犯罪 Violent Crimes",
        "description": (
            "AI models should not generate content that enables, encourages, or "
            "excuses violence, or provides instructions on how to create weapons, "
            "explosives, or other means of causing physical harm. This includes "
            "content that promotes terrorism, mass shootings, or other violent acts."
        ),
        "layer": "llama_guard",
        "order": 1,
    },
    {
        "code": "S2",
        "name": "非暴力犯罪 Non-Violent Crimes",
        "description": (
            "AI models should not generate content that enables, encourages, or "
            "provides instructions on how to commit a non-violent crime. This "
            "includes content that provides instructions on how to commit fraud, "
            "steal something, or circumvent security measures. This also includes "
            "content that provides instructions on creating or distributing malware, "
            "ransomware, or other malicious code."
        ),
        "layer": "llama_guard",
        "order": 2,
    },
    {
        "code": "S3",
        "name": "性犯罪 Sex Crimes",
        "description": (
            "AI models should not generate content that enables, encourages, or "
            "excuses sexual crimes, including content that sexualizes minors."
        ),
        "layer": "llama_guard",
        "order": 3,
    },
    {
        "code": "S4",
        "name": "儿童性剥削 Child Sexual Exploitation",
        "description": (
            "AI models should not generate content that sexualizes minors or "
            "depicts/encourages child sexual exploitation in any form."
        ),
        "layer": "llama_guard",
        "order": 4,
    },
    {
        "code": "S5",
        "name": "诽谤 Defamation",
        "description": (
            "AI models should not generate content that is defamatory toward any "
            "person, organization, or group based on protected characteristics."
        ),
        "layer": "llama_guard",
        "order": 5,
    },
    {
        "code": "S6",
        "name": "专业建议 Specialized Advice",
        "description": (
            "AI models should not generate content that provides specialized advice "
            "(e.g., medical, legal, financial) that could cause harm if relied upon, "
            "without appropriate disclaimers."
        ),
        "layer": "llama_guard",
        "order": 6,
    },
    {
        "code": "S7",
        "name": "隐私 Privacy",
        "description": (
            "AI models should not generate content that contains sensitive personal "
            "information of individuals without consent, or that enables "
            "doxxing/stalking."
        ),
        "layer": "llama_guard",
        "order": 7,
    },
    {
        "code": "S8",
        "name": "知识产权 Intellectual Property",
        "description": (
            "AI models should not generate content that infringes on intellectual "
            "property rights, such as reproducing copyrighted material verbatim."
        ),
        "layer": "llama_guard",
        "order": 8,
    },
    {
        "code": "S9",
        "name": "无指示攻击 Indiscriminate Weapons",
        "description": (
            "AI models should not generate content that provides instructions on how "
            "to create weapons of mass destruction or indiscriminate weapons."
        ),
        "layer": "llama_guard",
        "order": 9,
    },
    {
        "code": "S10",
        "name": "仇恨 Hate",
        "description": (
            "AI models should not generate content that is hateful, discriminatory, "
            "or demeaning toward people based on race, ethnicity, religion, sexual "
            "orientation, gender, disability, or other protected characteristics."
        ),
        "layer": "llama_guard",
        "order": 10,
    },
    {
        "code": "S11",
        "name": "自杀与自残 Suicide & Self-Harm",
        "description": (
            "AI models should not generate content that encourages or provides "
            "instructions for suicide, self-harm, or eating disorders."
        ),
        "layer": "llama_guard",
        "order": 11,
    },
    {
        "code": "S12",
        "name": "性内容 Sexual Content",
        "description": (
            "AI models should not generate explicit sexual content, pornography, "
            "or erotica."
        ),
        "layer": "llama_guard",
        "order": 12,
    },
    {
        "code": "S13",
        "name": "选举 Elections",
        "description": (
            "AI models should not generate content that misrepresents information "
            "about elections, voting procedures, or civic processes in a way that "
            "could suppress or manipulate voting."
        ),
        "layer": "llama_guard",
        "order": 13,
    },
    {
        "code": "S14",
        "name": "代码解释器滥用 Code Interpreter Abuse",
        "description": (
            "AI models should not generate content that exploits a code interpreter "
            "or sandbox to perform malicious actions, escape sandboxes, or execute "
            "arbitrary harmful code."
        ),
        "layer": "llama_guard",
        "order": 14,
    },
]


def seed_default_categories(session_sync) -> None:
    """将默认类别写入数据库（已存在则跳过）。传入同步 session。"""
    from ..models import CategoryRule  # noqa: WPS433

    for cat in DEFAULT_CATEGORIES:
        exists = (
            session_sync.query(CategoryRule)
            .filter(CategoryRule.code == cat["code"])
            .first()
        )
        if exists:
            continue
        session_sync.add(CategoryRule(**cat, enabled=True, action="block"))
