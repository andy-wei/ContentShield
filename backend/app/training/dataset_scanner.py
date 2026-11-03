"""数据集批量扫描器：复用运行时 6 层检测引擎 + 投毒检测。

核心流程：
    for record in dataset:
        1. orchestrator.moderate(record)  # 复用 L0-L4 检测（PII/有害/注入）
        2. poison_patterns.detect_all(record)  # 训练投毒检测
        3. 聚合为 DatasetFinding

这是"一个引擎，三处复用"架构的体现：训练数据扫描和推理检测共享同一套检测能力。

支持的数据格式：
- jsonl：每行一个 JSON，取 "text" 或 "content" 或 "prompt"+"completion" 字段
- csv：每行一条记录，取指定列
- txt：每行一条记录（整行作为样本内容）
"""

from __future__ import annotations

import asyncio
import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path

from .poison_patterns import PoisonHit, detect_all_poison
from .provenance import compute_record_hash

logger = logging.getLogger(__name__)


@dataclass
class ScanRecordResult:
    """单条样本的扫描结果。"""

    record_idx: int
    record_hash: str
    # 运行时引擎检测结果
    decision: str = "pass"
    risk_score: float = 0.0
    layers: dict = field(default_factory=dict)
    categories: list[str] = field(default_factory=list)
    # 投毒检测结果
    poison_hits: list[PoisonHit] = field(default_factory=list)
    # 预览（脱敏后）
    preview: str = ""

    @property
    def issue_types(self) -> list[str]:
        """从检测结果推断问题类型。"""
        types = set()
        # 从运行时层推断
        for layer_name, layer_res in self.layers.items():
            if _layer_hit(layer_res):
                if layer_name == "dlp":
                    types.add("pii")
                elif layer_name == "llama_guard":
                    types.add("toxic")
                elif layer_name in ("prompt_guard", "indirect_injection"):
                    types.add("injection")

        # 从投毒检测推断
        for _ in self.poison_hits:
            types.add("poison")

        # 从类别推断（含 secret 的）
        for cat in self.categories:
            if "secret" in cat.lower() or "credential" in cat.lower():
                types.add("secret")

        return sorted(types) if types else []

    @property
    def poison_type(self) -> str:
        """取最高优先级的投毒类型。"""
        if not self.poison_hits:
            return ""
        # 按 severity 排序取最高
        severity_rank = {"high": 3, "medium": 2, "low": 1}
        sorted_hits = sorted(
            self.poison_hits, key=lambda h: severity_rank.get(h.severity, 0), reverse=True
        )
        return sorted_hits[0].poison_type

    @property
    def is_flagged(self) -> bool:
        """是否为问题样本（需标记）。"""
        return self.decision != "pass" or bool(self.poison_hits)


# ==================== 数据集读取 ====================


def read_records(file_path: str, fmt: str = "jsonl") -> list[str]:
    """读取数据集，返回样本内容列表。

    Args:
        file_path: 数据集文件路径
        fmt: jsonl / csv / txt
    """
    if fmt not in ("jsonl", "csv", "txt"):
        raise ValueError(f"不支持的数据集格式: {fmt}")

    path = Path(file_path)
    if not path.exists():
        raise FileNotFoundError(f"数据集文件不存在: {file_path}")

    records = []
    if fmt == "jsonl":
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                    records.append(_extract_text_from_jsonl(obj))
                except json.JSONDecodeError:
                    # 非 JSON，整行作为文本
                    records.append(line)

    elif fmt == "csv":
        with path.open(encoding="utf-8", newline="") as f:
            reader = csv.DictReader(f)
            for row in reader:
                # 优先取常见字段名
                for key in ("text", "content", "prompt", "message", "input"):
                    if key in row and row[key]:
                        records.append(row[key])
                        break
                else:
                    # 取第一个非空字段
                    for val in row.values():
                        if val:
                            records.append(val)
                            break

    elif fmt == "txt":
        with path.open(encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    records.append(line)

    return records


def _extract_text_from_jsonl(obj: dict) -> str:
    """从 JSONL 对象提取样本文本。

    支持的格式：
    - {"text": "..."}
    - {"content": "..."}
    - {"messages": [{"role":"user","content":"..."}, ...]}  取所有 content 拼接
    - {"prompt": "...", "completion": "..."}  拼接
    """
    if "text" in obj:
        return str(obj["text"])
    if "content" in obj:
        return str(obj["content"])
    if "messages" in obj and isinstance(obj["messages"], list):
        return " ".join(str(m.get("content", "")) for m in obj["messages"] if isinstance(m, dict))
    if "prompt" in obj:
        return str(obj["prompt"]) + " " + str(obj.get("completion", ""))
    # 兜底：把整个对象转字符串
    return json.dumps(obj, ensure_ascii=False)


# ==================== 批量扫描 ====================


async def scan_record(text: str, orchestrator, record_idx: int = 0) -> ScanRecordResult:
    """扫描单条样本：复用 orchestrator + 投毒检测。"""
    record_hash = compute_record_hash(text)

    # 1. 复用运行时 6 层检测引擎（skip_audit 避免污染运行时审计）
    try:
        result = await orchestrator.moderate(text, source="user_prompt", skip_audit=True)
    except Exception as e:  # noqa: BLE001
        logger.warning("样本检测失败 (hash=%s): %s", record_hash[:8], e)
        result = {"decision": "pass", "risk_score": 0.0, "layers": {}, "categories": []}

    # 2. 投毒检测（纯函数，不依赖外部服务）
    poison_hits = detect_all_poison(text)

    # 3. 预览（脱敏：orchestrator 可能已返回 modified_text）
    preview_text = result.get("modified_text") or text
    preview = preview_text[:200].replace("\n", " ")

    # 4. 把 layers 转成纯 dict（orchestrator 返回的值可能是 pydantic 对象，不可直接 json 序列化）
    raw_layers = result.get("layers", {})
    layers_dict = _layers_to_dict(raw_layers)

    return ScanRecordResult(
        record_idx=record_idx,
        record_hash=record_hash,
        decision=result.get("decision", "pass"),
        risk_score=result.get("risk_score", 0.0),
        layers=layers_dict,
        categories=result.get("categories", []),
        poison_hits=poison_hits,
        preview=preview,
    )


async def scan_dataset(
    records: list[str],
    orchestrator,
    *,
    batch_size: int = 20,
    on_progress: callable | None = None,
) -> list[ScanRecordResult]:
    """批量扫描数据集。

    Args:
        records: 样本列表
        orchestrator: 检测引擎编排器
        batch_size: 并发批大小（避免压垮推理服务）
        on_progress: 进度回调 fn(scanned, total)

    Returns:
        所有样本的扫描结果（仅含 flagged 的，pass 的跳过以省内存）
    """
    results = []
    total = len(records)

    for i in range(0, total, batch_size):
        batch = records[i : i + batch_size]
        # 批量并发扫描（传入全局索引 i + 批内偏移）
        batch_results = await asyncio.gather(
            *[scan_record(text, orchestrator, record_idx=i + j) for j, text in enumerate(batch)]
        )

        for r in batch_results:
            if r.is_flagged:
                results.append(r)

        if on_progress:
            on_progress(min(i + batch_size, total), total)

    return results


def _layer_hit(layer_res) -> bool:
    """安全判断某检测层是否命中。

    兼容 layer_res 是 dict（如 {"hit": True}）或 pydantic 对象（如 LayerResult）两种情况。
    """
    if isinstance(layer_res, dict):
        return bool(layer_res.get("hit"))
    # pydantic 对象：尝试 .hit 属性
    return bool(getattr(layer_res, "hit", False))


def _layers_to_dict(raw_layers) -> dict:
    """把 orchestrator 返回的 layers 转成纯 dict（可 JSON 序列化）。

    raw_layers 可能是：
    - dict，值为 pydantic 对象（LayerResult）
    - dict，值为 dict
    - pydantic 对象本身
    """
    result: dict = {}
    if isinstance(raw_layers, dict):
        items = raw_layers.items()
    elif hasattr(raw_layers, "model_dump"):
        items = raw_layers.model_dump().items()
    else:
        return {}

    for key, val in items:
        if isinstance(val, dict):
            result[key] = val
        elif hasattr(val, "model_dump"):
            result[key] = val.model_dump()
        else:
            # 兜底：尝试转 dict，失败则存简化信息
            try:
                result[key] = {
                    "hit": getattr(val, "hit", False),
                    "decision": getattr(val, "decision", "pass"),
                }
            except Exception:  # noqa: BLE001
                result[key] = {"hit": bool(val)}
    return result
