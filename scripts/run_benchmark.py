#!/usr/bin/env python3
"""ContentShield 检测引擎基准测试。

两个基准（可复现，遵守 AGENTS.md 原则 28：机制结论必须实验验证）：

1. 引擎基准（默认）：
   - 拦截率：AdvBench 100 条有害请求中 decision ∈ {block, modify} 的比例
   - 检出率：含 warn 的检出比例
   - 误拦率/误报率：自建 100 条中英干净集中 decision ≠ pass 的比例
     （block/modify = 硬误拦；含 warn = 总误报）
   - 延迟：P50 / P95 / P99
   - 命中类别分布 Top 10
2. 红队 ASR 基准（--asr，可选）：AdvBench 全量打目标模型测攻击成功率

用法：
  python3 scripts/run_benchmark.py                     # 引擎基准
  python3 scripts/run_benchmark.py --asr --target-model qwen:7b   # 附加红队 ASR
"""

from __future__ import annotations

import argparse
import asyncio
import json
import statistics
import sys
import time
from pathlib import Path

import httpx

DEFAULT_API = "http://localhost:8000"


def load_jsonl(path: Path) -> list[dict]:
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def percentile(sorted_vals: list[float], p: float) -> int:
    if not sorted_vals:
        return 0
    idx = min(len(sorted_vals) - 1, int(len(sorted_vals) * p / 100))
    return int(sorted_vals[idx])


async def moderate_one(client: httpx.AsyncClient, api: str, text: str) -> dict:
    """单次审核请求，429 限流时指数退避重试。"""
    for attempt in range(4):
        r = await client.post(f"{api}/api/moderate", json={"text": text, "source": "test"})
        if r.status_code == 429:
            await asyncio.sleep(2 ** attempt)  # 1s/2s/4s/8s 退避
            continue
        r.raise_for_status()
        return r.json()
    raise RuntimeError("rate limited after retries")


async def boost_rate_limit(client: httpx.AsyncClient, api: str) -> int:
    """跑基准前临时调高 /api 限流（跑完恢复），返回原值。"""
    r = await client.get(f"{api}/api/config/security")
    r.raise_for_status()
    original = r.json()["rate_limit_api"]
    if original < 1000:
        cfg = r.json()
        cfg["rate_limit_api"] = 1000
        put = await client.put(f"{api}/api/config/security", json=cfg)
        put.raise_for_status()
        print(f"限流临时调高: {original} → 1000 req/min（跑完恢复）")
    return original


async def restore_rate_limit(client: httpx.AsyncClient, api: str, original: int) -> None:
    r = await client.get(f"{api}/api/config/security")
    r.raise_for_status()
    cfg = r.json()
    if cfg["rate_limit_api"] != original:
        cfg["rate_limit_api"] = original
        put = await client.put(f"{api}/api/config/security", json=cfg)
        put.raise_for_status()
        print(f"限流已恢复: {original} req/min")


async def run_engine_bench(api: str, harmful: list[dict], benign: list[dict], concurrency: int) -> dict:
    sem = asyncio.Semaphore(concurrency)
    latencies: list[float] = []

    async def one(item: dict) -> dict:
        async with sem:
            t0 = time.perf_counter()
            try:
                res = await moderate_one(client, api, item["text"])
            except Exception as e:  # noqa: BLE001
                return {"text": item["text"], "decision": "ERROR", "categories": [], "err": str(e)[:100]}
            latencies.append((time.perf_counter() - t0) * 1000)
            return {
                "text": item["text"],
                "decision": res["decision"],
                "categories": res.get("categories", []),
            }

    async with httpx.AsyncClient(timeout=120) as client:
        original_rate = await boost_rate_limit(client, api)
        try:
            print(f"引擎基准：有害 {len(harmful)} 条 / 干净 {len(benign)} 条，并发 {concurrency}")
            harm_results = await asyncio.gather(*[one(x) for x in harmful])
            ben_results = await asyncio.gather(*[one(x) for x in benign])
        finally:
            await restore_rate_limit(client, api, original_rate)

    # 有害集统计
    harm_block = sum(1 for r in harm_results if r["decision"] in ("block", "modify"))
    harm_detect = sum(1 for r in harm_results if r["decision"] != "pass")
    harm_err = sum(1 for r in harm_results if r["decision"] == "ERROR")
    missed = [r for r in harm_results if r["decision"] == "pass"]

    # 干净集统计
    ben_block = sum(1 for r in ben_results if r["decision"] in ("block", "modify"))
    ben_flag = sum(1 for r in ben_results if r["decision"] != "pass")
    false_positives = [r for r in ben_results if r["decision"] != "pass"]

    # 类别分布
    cat_count: dict[str, int] = {}
    for r in harm_results:
        for c in r["categories"]:
            cat_count[c] = cat_count.get(c, 0) + 1
    top_cats = sorted(cat_count.items(), key=lambda x: -x[1])[:10]

    lat_sorted = sorted(latencies)
    result = {
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "dataset": {"harmful": len(harmful), "benign": len(benign)},
        "harmful": {
            "block_rate": round(harm_block / len(harmful), 4),
            "detect_rate": round(harm_detect / len(harmful), 4),
            "errors": harm_err,
            "missed_samples": [
                {"text": r["text"][:80]} for r in missed[:20]
            ],
        },
        "benign": {
            "hard_false_block_rate": round(ben_block / len(benign), 4),
            "flag_rate_incl_warn": round(ben_flag / len(benign), 4),
            "flagged_samples": [
                {"text": r["text"][:60], "decision": r["decision"], "categories": r["categories"]}
                for r in false_positives[:20]
            ],
        },
        "latency_ms": {
            "p50": percentile(lat_sorted, 50),
            "p95": percentile(lat_sorted, 95),
            "p99": percentile(lat_sorted, 99),
            "mean": int(statistics.mean(latencies)) if latencies else 0,
        },
        "top_categories": top_cats,
    }
    return result


def print_report(r: dict) -> None:
    print("\n===== ContentShield 引擎基准结果 =====")
    print(f"有害集（AdvBench {r['dataset']['harmful']} 条）")
    print(f"  拦截率 (block+modify): {r['harmful']['block_rate']:.1%}")
    print(f"  检出率 (含 warn):     {r['harmful']['detect_rate']:.1%}")
    if r["harmful"]["errors"]:
        print(f"  ⚠ 请求错误: {r['harmful']['errors']} 条")
    for s in r["harmful"]["missed_samples"][:8]:
        print(f"    漏过: {s['text']}")
    print(f"干净集（{r['dataset']['benign']} 条）")
    print(f"  硬误拦率 (block/modify): {r['benign']['hard_false_block_rate']:.1%}")
    print(f"  总误报率 (含 warn):      {r['benign']['flag_rate_incl_warn']:.1%}")
    for s in r["benign"]["flagged_samples"]:
        print(f"    - [{s['decision']}] {s['text']}")
    print(f"延迟: P50={r['latency_ms']['p50']}ms P95={r['latency_ms']['p95']}ms "
          f"P99={r['latency_ms']['p99']}ms mean={r['latency_ms']['mean']}ms")
    print("命中类别 Top:", ", ".join(f"{c}({n})" for c, n in r["top_categories"]))


async def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--api", default=DEFAULT_API)
    ap.add_argument("--harmful", default="data/benchmarks/advbench_100.jsonl")
    ap.add_argument("--benign", default="data/benchmarks/benign_100.jsonl")
    ap.add_argument("--concurrency", type=int, default=5)
    ap.add_argument("--out", default="docs/benchmark_results.json")
    ap.add_argument("--asr", action="store_true", help="附加红队 ASR 基准（需 --target-model）")
    ap.add_argument("--target-model", default="qwen:7b")
    ap.add_argument("--target-base-url", default="http://host.docker.internal:11434/v1")
    args = ap.parse_args()

    root = Path(__file__).resolve().parent.parent
    harmful = load_jsonl(root / args.harmful)
    benign = load_jsonl(root / args.benign)

    result = await run_engine_bench(args.api, harmful, benign, args.concurrency)
    print_report(result)
    Path(root / args.out).write_text(json.dumps(result, ensure_ascii=False, indent=2))
    print(f"\n结果已写入 {args.out}")

    if args.asr:
        print(f"\n红队 ASR 基准：AdvBench 打 {args.target_model}（通过红队 API，Celery 异步）")
        print("  请用 Web UI 或 API 发起 campaign 后查看 ASR；"
              "示例：POST /api/redteam/campaigns target.model=" + args.target_model)


if __name__ == "__main__":
    asyncio.run(main())
