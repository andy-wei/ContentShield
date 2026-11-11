#!/usr/bin/env python3
"""Guard 模型评估：LoRA 微调后的 Qwen guard vs Prompt Guard 2 对比。

同一验证集上分别测：
1. 自训 guard（mlx-lm 加载 base+adapter，生成标签解析）
2. Prompt Guard 2（本地 8081 /v1/classify 服务）

输出三分类 accuracy + per-class precision/recall + 混淆矩阵。
"""

from __future__ import annotations

import argparse
import json
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

LABELS = ["BENIGN", "INJECTION", "JAILBREAK"]


def load_val(path: Path) -> list[dict]:
    rows = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [
        {
            "system": r["messages"][0]["content"],
            "text": r["messages"][1]["content"],
            "label": r["messages"][2]["content"],
        }
        for r in rows
    ]


def parse_label(output: str) -> str:
    m = re.search(r"\b(BENIGN|INJECTION|JAILBREAK)\b", (output or "").upper())
    return m.group(1) if m else "PARSE_ERROR"


def eval_custom_guard(model: str, adapter: str, data: list[dict]) -> list[str]:
    from mlx_lm import load, generate

    lm, tokenizer = load(model, adapter_path=adapter)
    preds = []
    for i, item in enumerate(data):
        msgs = [
            {"role": "system", "content": item["system"]},
            {"role": "user", "content": item["text"]},
        ]
        prompt = tokenizer.apply_chat_template(msgs, add_generation_prompt=True, tokenize=False)
        out = generate(lm, tokenizer, prompt=prompt, max_tokens=8, verbose=False)
        preds.append(parse_label(out))
        if (i + 1) % 10 == 0:
            print(f"  guard {i + 1}/{len(data)}")
    return preds


def eval_prompt_guard(api: str, data: list[dict]) -> list[str]:
    import httpx

    preds = []
    with httpx.Client(timeout=30) as client:
        for i, item in enumerate(data):
            try:
                r = client.post(f"{api}/v1/classify", json={"text": item["text"][:4000]})
                r.raise_for_status()
                body = r.json()
                scores = body.get("scores", body)  # 兼容嵌套 {label, scores} 与扁平两种返回
                inj = float(scores.get("INJECTION", 0) or 0)
                jb = float(scores.get("JAILBREAK", 0) or 0)
                benign = float(scores.get("BENIGN", 0) or 0)
                top = max(inj, jb, benign)
                if top == benign:
                    preds.append("BENIGN")
                elif top == jb:
                    preds.append("JAILBREAK")
                else:
                    preds.append("INJECTION")
            except Exception as e:  # noqa: BLE001
                print(f"  pg error @{i}: {e}")
                preds.append("PG_ERROR")
            if (i + 1) % 20 == 0:
                print(f"  prompt-guard {i + 1}/{len(data)}")
    return preds


def metrics(labels: list[str], preds: list[str], name: str) -> dict:
    correct = sum(1 for t, p in zip(labels, preds) if t == p)
    acc = correct / len(labels) if labels else 0
    print(f"\n[{name}] accuracy: {acc:.1%} ({correct}/{len(labels)})")
    per: dict[str, dict] = {}
    for lbl in LABELS:
        tp = sum(1 for t, p in zip(labels, preds) if t == lbl and p == lbl)
        fp = sum(1 for t, p in zip(labels, preds) if t != lbl and p == lbl)
        fn = sum(1 for t, p in zip(labels, preds) if t == lbl and p != lbl)
        prec = tp / (tp + fp) if tp + fp else 0.0
        rec = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * prec * rec / (prec + rec) if prec + rec else 0.0
        per[lbl] = {"precision": round(prec, 3), "recall": round(rec, 3), "f1": round(f1, 3)}
        print(f"  {lbl:10} P={prec:.2f} R={rec:.2f} F1={f1:.2f}")
    # 混淆
    print("  混淆（行=真实 列=预测）:", f"{'':10}", "  ".join(f"{l[:7]:>7}" for l in LABELS))
    for tl in LABELS:
        row = [sum(1 for t, p in zip(labels, preds) if t == tl and p == pl) for pl in LABELS]
        print(f"  {tl:10}", "  ".join(f"{v:>7}" for v in row))
    return {"accuracy": round(acc, 4), "per_class": per}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default="mlx-community/Qwen3-4B-4bit")
    ap.add_argument("--adapter", default=str(ROOT / "models/adapters/guard-sft-qwen3-4b"))
    ap.add_argument("--val", default=str(ROOT / "data/training/mlx_sft/valid.jsonl"))
    ap.add_argument("--pg-api", default="http://localhost:8081")
    ap.add_argument("--skip-guard", action="store_true")
    ap.add_argument("--skip-pg", action="store_true")
    ap.add_argument("--out", default=str(ROOT / "docs/guard_eval_results.json"))
    args = ap.parse_args()

    data = load_val(Path(args.val))
    labels = [d["label"] for d in data]
    print(f"验证集 {len(data)} 条，分布:", {l: labels.count(l) for l in LABELS})

    results: dict = {"val_size": len(data), "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S")}

    if not args.skip_guard:
        t0 = time.time()
        preds = eval_custom_guard(args.model, args.adapter, data)
        results["custom_guard"] = metrics(labels, preds, "自训 Guard (Qwen3-4B + LoRA)")
        results["custom_guard"]["eval_seconds"] = int(time.time() - t0)

    if not args.skip_pg:
        t0 = time.time()
        preds = eval_prompt_guard(args.pg_api, data)
        results["prompt_guard_2"] = metrics(labels, preds, "Prompt Guard 2 86M（基线）")
        results["prompt_guard_2"]["eval_seconds"] = int(time.time() - t0)

    Path(args.out).write_text(json.dumps(results, ensure_ascii=False, indent=2))
    print(f"\n结果已写入 {args.out}")


if __name__ == "__main__":
    main()
