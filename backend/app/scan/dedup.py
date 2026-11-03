"""跨工具 finding 去重与严重度归一化。

场景：trivy 和 gitleaks 都可能报同一个密钥泄露；bandit 和 trivy fs 都可能报同一处配置问题。
策略：按 (file, line, category) 聚类，同簇内保留最高严重度的那条，合并 tool 字段。

注意：完全相同的指纹（tool+file+line+rule_id）已在落库时天然去重，
本模块处理的是"不同工具报同一漏洞但 rule_id 不同"的情况。
"""

from __future__ import annotations

from collections import defaultdict

from .tools.base import FindingRaw

# 严重度排序权重，便于比较
_SEVERITY_RANK = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def dedup_findings(findings: list[FindingRaw]) -> list[FindingRaw]:
    """跨工具去重。

    规则：
    1. 完全相同指纹（已由各适配器计算）的直接去重。
    2. 同 (file, line, category) 但不同 tool 的，合并为一条，
       severity 取最高，tool 字段记为 "tool_a+tool_b"。
    """
    if not findings:
        return []

    # 第一轮：按指纹去重
    by_fp: dict[str, FindingRaw] = {}
    for f in findings:
        if f.fingerprint and f.fingerprint in by_fp:
            # 同指纹保留严重度更高的
            existing = by_fp[f.fingerprint]
            if _SEVERITY_RANK.get(f.severity, 0) > _SEVERITY_RANK.get(existing.severity, 0):
                by_fp[f.fingerprint] = f
        else:
            by_fp[f.fingerprint or f"{f.tool}|{f.file}|{f.line}|{f.rule_id}"] = f

    # 第二轮：按 (file, line, category) 合并跨工具
    clusters: dict[tuple, list[FindingRaw]] = defaultdict(list)
    no_cluster: list[FindingRaw] = []
    for f in by_fp.values():
        # 只有 file+line+category 都有效的才聚类
        if f.file and f.line > 0 and f.category:
            clusters[(f.file, f.line, f.category)].append(f)
        else:
            no_cluster.append(f)

    result: list[FindingRaw] = list(no_cluster)
    for cluster in clusters.values():
        if len(cluster) == 1:
            result.append(cluster[0])
        else:
            result.append(_merge_cluster(cluster))

    return result


def _merge_cluster(cluster: list[FindingRaw]) -> FindingRaw:
    """合并同位置的多工具 finding：取最高严重度，tool 用 + 连接。"""
    # 按严重度降序
    sorted_f = sorted(cluster, key=lambda f: _SEVERITY_RANK.get(f.severity, 0), reverse=True)
    primary = sorted_f[0]
    tools = sorted({f.tool for f in cluster if f.tool})
    if len(tools) > 1:
        primary.tool = "+".join(tools)
    # message 追加其他工具的发现
    other_msgs = [f"[{f.tool}] {f.title}" for f in sorted_f[1:]]
    if other_msgs:
        primary.message = f"{primary.message}\n\n关联发现:\n" + "\n".join(other_msgs)
    return primary
