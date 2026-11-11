#!/usr/bin/env bash
# Guard 模型 SFT LoRA 训练（Apple Silicon / MLX）
# 数据：data/training/mlx_sft/{train,valid}.jsonl（489 条三分类）
# 底座：mlx-community/Qwen3-4B-4bit
set -euo pipefail

PROJECT_DIR="$(cd "$(dirname "$0")/.." && pwd)"
PY=/Users/wayne/miniconda3/bin/python
MODEL="${MODEL:-$PROJECT_DIR/models/qwen3-1.7b-4bit-mlx}"
ADAPTER="$PROJECT_DIR/models/adapters/guard-sft-qwen3-1.7b"
DATA="$PROJECT_DIR/data/training/mlx_sft"

mkdir -p "$ADAPTER"

"$PY" -m mlx_lm.lora \
  --model "$MODEL" \
  --train \
  --data "$DATA" \
  --fine-tune-type lora \
  --num-layers 16 \
  --batch-size 4 \
  --iters "${ITERS:-400}" \
  --learning-rate 1e-5 \
  --steps-per-report 20 \
  --steps-per-eval 100 \
  --adapter-path "$ADAPTER" \
  2>&1 | tee /tmp/guard_sft_train.log | tail -40
