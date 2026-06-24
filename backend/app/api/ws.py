"""WebSocket：检测进度推送（Playground 实时展示各层结果）。

协议：
- 客户端发送: {"text": "...", "source": "user_prompt"}
- 服务端依次推送各层完成事件，最后推送 done
"""
from __future__ import annotations

import asyncio
import json
import logging
import time

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from ..engine.detectors.base import BaseDetector
from ..engine.orchestrator import LAYER_WEIGHTS, orchestrator

logger = logging.getLogger(__name__)
router = APIRouter(tags=["websocket"])


async def _detect_layer(
    ws: WebSocket, detector: BaseDetector, text: str, source: str
) -> dict:
    """跑单层并推送进度。"""
    t0 = time.perf_counter()
    try:
        r = await detector.detect(text, source=source)
    except Exception as e:  # noqa: BLE001
        r = None
        await ws.send_json(
            {"event": "layer_error", "layer": detector.name, "error": str(e)}
        )
        return {"name": detector.name, "decision": "skipped", "hit": False, "details": {}}
    payload = r.to_dict()
    payload["elapsed_ms"] = int((time.perf_counter() - t0) * 1000)
    await ws.send_json({"event": "layer_done", "layer": detector.name, "result": payload})
    return payload


@router.websocket("/ws/moderate")
async def ws_moderate(ws: WebSocket) -> None:
    await ws.accept()
    try:
        while True:
            raw = await ws.receive_text()
            try:
                msg = json.loads(raw)
            except json.JSONDecodeError:
                await ws.send_json({"event": "error", "error": "invalid json"})
                continue

            text = msg.get("text", "")
            source = msg.get("source", "user_prompt")
            if not text.strip():
                await ws.send_json({"event": "error", "error": "empty text"})
                continue

            await ws.send_json({"event": "start", "text_len": len(text)})
            t0 = time.perf_counter()

            # 并行跑四层，但每层完成即推送
            tasks = [
                _detect_layer(ws, d, text, source) for d in orchestrator.detectors
            ]
            layer_results = await asyncio.gather(*tasks)

            # 融合
            decision = "pass"
            for r in layer_results:
                if r["decision"] == "block":
                    decision = "block"
                    break
                if r["decision"] == "warn" and decision == "pass":
                    decision = "warn"

            risk = 0.0
            categories: list[str] = []
            for r in layer_results:
                if not r.get("hit"):
                    continue
                weight = LAYER_WEIGHTS.get(r["name"], 0.25)
                layer_score = max(
                    (h["score"] for h in r.get("hits", [])), default=0.5
                )
                risk += weight * layer_score
                for h in r.get("hits", []):
                    categories.append(h["category"])
            risk = min(risk, 1.0)

            await ws.send_json(
                {
                    "event": "done",
                    "decision": decision,
                    "risk_score": round(risk, 4),
                    "categories": categories,
                    "total_ms": int((time.perf_counter() - t0) * 1000),
                }
            )
    except WebSocketDisconnect:
        logger.debug("WS disconnected")
    except Exception as e:  # noqa: BLE001
        logger.exception("WS error")
        try:
            await ws.send_json({"event": "error", "error": str(e)})
        except Exception:  # noqa: BLE001
            pass
