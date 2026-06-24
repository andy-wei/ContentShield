"""Prompt Guard 2 86M 独立推理服务。

架构说明：
  Llama-Guard-4 是生成式模型，用 llama.cpp 跑。
  但 Prompt Guard 2 86M 是 DeBERTa-v2 分类模型（输出 3 个概率），
  llama.cpp 不支持，必须用 Python transformers 库。

本服务：
  - 用 transformers 加载模型（Apple Silicon 用 MPS Metal 加速）
  - 暴露 /v1/classify 端点，返回 BENIGN/INJECTION/JAILBREAK 概率
  - 由 backend 的 prompt_guard.py detector 调用

启动：
  python3 inference/prompt_guard_server.py --model models/Llama-Prompt-Guard-2-86M --port 8081
"""
from __future__ import annotations

import argparse
import logging
import time

import torch
import uvicorn
from fastapi import FastAPI
from pydantic import BaseModel
from transformers import AutoModelForSequenceClassification, AutoTokenizer

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger("prompt-guard-server")

app = FastAPI(title="Prompt Guard 2 Server", version="0.1.0")

# 标签顺序（DeBERTa 分类头）
LABELS = ["BENIGN", "INJECTION", "JAILBREAK"]

# 全局模型（启动时加载）
_tokenizer = None
_model = None
_device = None


class ClassifyRequest(BaseModel):
    text: str


class ClassifyResponse(BaseModel):
    label: str
    scores: dict  # {"BENIGN": 0.99, "INJECTION": 0.001, "JAILBREAK": 0.009}
    latency_ms: int


@app.on_event("startup")
def _load():
    global _tokenizer, _model, _device
    # 选设备：优先 MPS（Apple Metal），回退 CPU
    if torch.backends.mps.is_available():
        _device = "mps"
    elif torch.cuda.is_available():
        _device = "cuda"
    else:
        _device = "cpu"
    logger.info("加载模型，device=%s ...", _device)
    t0 = time.perf_counter()
    _tokenizer = AutoTokenizer.from_pretrained(MODEL_PATH)
    _model = AutoModelForSequenceClassification.from_pretrained(MODEL_PATH).to(_device)
    _model.eval()
    logger.info("模型加载完成，用时 %.1fs", time.perf_counter() - t0)


@app.get("/health")
def health():
    return {"status": "ok" if _model is not None else "loading"}


@app.post("/v1/classify", response_model=ClassifyResponse)
def classify(req: ClassifyRequest):
    t0 = time.perf_counter()
    inputs = _tokenizer(
        req.text, return_tensors="pt", truncation=True, max_length=512
    ).to(_device)
    with torch.no_grad():
        logits = _model(**inputs).logits
    probs = torch.softmax(logits, dim=-1)[0]
    scores = {LABELS[i]: round(p.item(), 6) for i, p in enumerate(probs)}
    label = max(scores, key=scores.get)
    return ClassifyResponse(
        label=label,
        scores=scores,
        latency_ms=int((time.perf_counter() - t0) * 1000),
    )


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--model", default="models/Llama-Prompt-Guard-2-86M")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=8081)
    args = parser.parse_args()

    MODEL_PATH = args.model
    logger.info("Prompt Guard 2 Server | model=%s port=%d", MODEL_PATH, args.port)
    uvicorn.run(app, host=args.host, port=args.port, log_level="warning")
