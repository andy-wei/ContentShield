"""cs-scan CLI：本地跑扫描工具 + 上传结果到平台。

用法（CI 中）：
    cs-scan --target . --tools bandit,gitleaks,pip-audit \\
            --server http://contentshield:8000 --gate

流程：
1. 在本地工作目录跑指定的扫描工具（bandit/gitleaks/pip-audit/npm/trivy fs）
2. 把 finding 上传到平台（POST /api/scan/upload）
3. 可选：查询门禁结果，失败则退出码 1（CI 阻断）

安装后提供命令 cs-scan：
    pip install -e ".[dev]"
    cs-scan --help
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path


# 支持直接 python -m app.scan.cli 运行
def main() -> int:
    parser = argparse.ArgumentParser(
        prog="cs-scan",
        description="本地跑安全扫描工具并上传结果到 ContentShield 平台",
    )
    parser.add_argument(
        "--target",
        default=".",
        help="扫描目标路径（默认当前目录）",
    )
    parser.add_argument(
        "--tools",
        default="bandit,gitleaks,pip-audit",
        help="逗号分隔的工具列表（默认 bandit,gitleaks,pip-audit）",
    )
    parser.add_argument(
        "--server",
        default=os.environ.get("CS_SERVER", "http://localhost:8000"),
        help="ContentShield 平台地址（默认 $CS_SERVER 或 http://localhost:8000）",
    )
    parser.add_argument(
        "--target-name",
        default=None,
        help="目标名称（默认用目录名）",
    )
    parser.add_argument(
        "--gate",
        action="store_true",
        help="查询门禁结果，失败则退出码 1（CI 阻断）",
    )
    parser.add_argument(
        "--policy-id",
        type=int,
        default=None,
        help="门禁策略 ID（不指定则用默认策略）",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="只跑扫描不上传，结果打印到 stdout",
    )
    args = parser.parse_args()

    workdir = os.path.abspath(args.target)
    tools = [t.strip() for t in args.tools.split(",") if t.strip()]

    print(f"🔍 cs-scan: 扫描 {workdir}")
    print(f"   工具: {', '.join(tools)}")

    # 延迟导入（避免 argparse --help 时加载全部模块）
    from .tools import get_adapter

    all_findings = []
    for tool_name in tools:
        adapter = get_adapter(tool_name)
        if not adapter:
            print(f"   ⚠️  未知工具 {tool_name}，跳过", file=sys.stderr)
            continue
        if not adapter.is_available():
            print(f"   ⚠️  工具 {tool_name} 不可用（未安装），跳过", file=sys.stderr)
            continue
        try:
            print(f"   ▶️  运行 {tool_name} ...")
            raw_findings = adapter.run(workdir)
            all_findings.extend(raw_findings)
            print(f"   ✅ {tool_name}: 发现 {len(raw_findings)} 条")
        except Exception as e:  # noqa: BLE001
            print(f"   ❌ {tool_name} 失败: {e}", file=sys.stderr)

    print(f"\n📊 合计 {len(all_findings)} 条 finding")

    # 按严重度统计
    sev_counts: dict[str, int] = {}
    for f in all_findings:
        sev_counts[f.severity] = sev_counts.get(f.severity, 0) + 1
    for sev in ["critical", "high", "medium", "low", "info"]:
        if sev in sev_counts:
            print(f"   {sev}: {sev_counts[sev]}")

    if args.dry_run:
        print("\n--dry-run 模式，不上传结果")
        return 0

    # 上传到平台
    import httpx

    target_name = args.target_name or Path(workdir).name
    upload_req = {
        "target_name": target_name,
        "target_type": "path",
        "location": workdir,
        "ref": "main",
        "commit": "",
        "tools": tools,
        "findings": [
            {
                "tool": f.tool,
                "severity": f.severity,
                "category": f.category,
                "rule_id": f.rule_id,
                "cve": f.cve,
                "title": f.title,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "fix": f.fix,
            }
            for f in all_findings
        ],
    }

    print(f"\n📤 上传到 {args.server}/api/scan/upload ...")
    try:
        resp = httpx.post(
            f"{args.server}/api/scan/upload",
            json=upload_req,
            timeout=30,
        )
        resp.raise_for_status()
        job = resp.json()
        job_id = job["id"]
        print(f"   ✅ 已上传，任务 ID: {job_id}")
    except Exception as e:  # noqa: BLE001
        print(f"   ❌ 上传失败: {e}", file=sys.stderr)
        return 2

    # 门禁判定
    if args.gate:
        print(f"\n🛡️  查询门禁结果 (policy_id={args.policy_id}) ...")
        try:
            params = {"policy_id": args.policy_id} if args.policy_id else {}
            gate_resp = httpx.get(
                f"{args.server}/api/scan/jobs/{job_id}/gate",
                params=params,
                timeout=10,
            )
            gate_resp.raise_for_status()
            gate = gate_resp.json()
            if gate["passed"]:
                print(f"   ✅ 门禁通过 (策略: {gate['policy_name']})")
                return 0
            else:
                print(f"   ❌ 门禁失败 (策略: {gate['policy_name']})")
                for reason in gate["reasons"]:
                    print(f"      - {reason}")
                return 1
        except Exception as e:  # noqa: BLE001
            print(f"   ⚠️  门禁查询失败: {e}", file=sys.stderr)
            return 0

    return 0


if __name__ == "__main__":
    sys.exit(main())
