#!/usr/bin/env bash
# =============================================================================
# 模型下载脚本
# 用法：
#   ./scripts/download_models.sh prompt-guard     # 仅下载 Prompt Guard 2（所有 profile 都需要）
#   ./scripts/download_models.sh llama-guard-gpu  # 下载 Llama-Guard-4 原始权重（vLLM 用）
#   ./scripts/download_models.sh llama-guard-cpu  # 下载 Llama-Guard-4 GGUF（CPU 用）
#   ./scripts/download_models.sh all              # 全部
# =============================================================================
set -euo pipefail

MODELS_DIR="${MODELS_DIR:-./models}"
mkdir -p "$MODELS_DIR"

if ! command -v huggingface-cli >/dev/null 2>&1; then
  echo "❌ 未安装 huggingface-cli，请先运行: pip install -U 'huggingface_hub[cli]'"
  exit 1
fi

download_prompt_guard() {
  echo "⬇️  下载 Prompt Guard 2 86M（GGUF Q8）..."
  # Prompt Guard 2 官方仓库无 GGUF，从社区镜像下载；若无则用原始权重
  huggingface-cli download \
    "meta-llama/Llama-Prompt-Guard-2-86M" \
    --local-dir "$MODELS_DIR/Llama-Prompt-Guard-2-86M" \
    --local-dir-use-symlinks False || true
  echo "✅ Prompt Guard 2 已下载到 $MODELS_DIR/Llama-Prompt-Guard-2-86M"
  echo "   注意：GGUF 量化版需用 llama.cpp 的 convert_hf_to_gguf.py 转换，"
  echo "   或从社区仓库（如 bartowski）下载现成 .gguf 文件。"
}

download_llama_guard_gpu() {
  echo "⬇️  下载 Llama-Guard-4-12B（原始权重，vLLM 用）..."
  echo "   ⚠️  需要 HuggingFace Llama 模型访问授权，请先 huggingface-cli login"
  huggingface-cli download \
    "meta-llama/Llama-Guard-4-12B" \
    --local-dir "$MODELS_DIR/Llama-Guard-4-12B" \
    --local-dir-use-symlinks False
  echo "✅ Llama-Guard-4-12B 已下载到 $MODELS_DIR/Llama-Guard-4-12B"
}

download_llama_guard_cpu() {
  echo "⬇️  下载 Llama-Guard-4-12B GGUF（INT4，CPU 用）..."
  echo "   请从社区 GGUF 仓库下载 Q4_K_M 版本（约 7GB），例如："
  echo "   huggingface-cli download unsloth/Llama-Guard-4-12B-GGUF \\
       llama-guard-4-12b-Q4_K_M.gguf \\
       --local-dir $MODELS_DIR"
  echo "   下载后将 .gguf 文件置于 $MODELS_DIR/ 并命名为 llama-guard-4-12b-Q4_K_M.gguf"
}

case "${1:-help}" in
  prompt-guard)
    download_prompt_guard
    ;;
  llama-guard-gpu)
    download_llama_guard_gpu
    ;;
  llama-guard-cpu)
    download_llama_guard_cpu
    ;;
  all)
    download_prompt_guard
    download_llama_guard_gpu
    ;;
  *)
    echo "用法: $0 {prompt-guard|llama-guard-gpu|llama-guard-cpu|all}"
    echo "模型目录: MODELS_DIR=$MODELS_DIR"
    exit 1
    ;;
esac
