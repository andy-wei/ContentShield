"""数据集溯源：样本哈希、来源标注、版本追踪。

用于：
- 跨次扫描去重（同一样本不同次扫描可对比）
- 数据集版本间差异分析
- 问题样本溯源到原始来源
"""

from __future__ import annotations

import hashlib


def compute_record_hash(text: str) -> str:
    """计算样本内容哈希（SHA256 前 32 字符）。

    用于：
    - 去重：相同内容相同哈希
    - 溯源：定位同一样本在不同扫描/版本中的位置
    """
    return hashlib.sha256(text.encode("utf-8")).hexdigest()[:32]


def compute_dataset_fingerprint(records: list[str]) -> str:
    """计算整个数据集的指纹（所有样本哈希的哈希）。

    用于版本对比：两个数据集指纹相同则内容完全一致。
    """
    if not records:
        return ""
    # 对每条样本取哈希，排序后再哈希（顺序无关）
    hashes = sorted(compute_record_hash(r) for r in records)
    combined = "|".join(hashes)
    return hashlib.sha256(combined.encode("utf-8")).hexdigest()[:32]


def diff_datasets(old_records: list[str], new_records: list[str]) -> dict:
    """对比两个版本的数据集，返回新增/删除/修改的样本。

    Returns:
        {
            "added": [hash, ...],      # 新版本新增的样本
            "removed": [hash, ...],    # 新版本删除的样本
            "unchanged": [hash, ...],  # 两版本都有的样本
            "added_count": int,
            "removed_count": int,
            "unchanged_count": int,
        }
    """
    old_hashes = {compute_record_hash(r) for r in old_records}
    new_hashes = {compute_record_hash(r) for r in new_records}

    added = new_hashes - old_hashes
    removed = old_hashes - new_hashes
    unchanged = old_hashes & new_hashes

    return {
        "added": sorted(added),
        "removed": sorted(removed),
        "unchanged": sorted(unchanged),
        "added_count": len(added),
        "removed_count": len(removed),
        "unchanged_count": len(unchanged),
    }
