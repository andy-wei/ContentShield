# llama.cpp 服务：CPU（或可选 GPU）跑 GGUF 量化模型
# 用于两个用途：
#   1) Prompt Guard 2 86M（提示词注入/越狱检测，所有 profile 共用，CPU 足够）
#   2) Llama-Guard-4-12B GGUF（local-cpu profile）
# 模型通过卷挂载到 /models
FROM ghcr.io/ggml-org/llama.cpp:server

# 环境变量由 docker-compose 注入：MODEL_PATH / N_THREADS / PORT / CONTEXT_SIZE
ENV HOST=0.0.0.0
EXPOSE 8080

# llama-server 开启 OpenAI 兼容 API
# --jinja 让其支持 chat template（Prompt Guard 2 需要 [INST] 模板）
CMD ["sh", "-c", "llama-server \
    --model $MODEL_PATH \
    --host $HOST \
    --port $PORT \
    --threads $N_THREADS \
    --ctx-size $CONTEXT_SIZE \
    --jinja \
    --alias $(basename $MODEL_PATH .gguf)"]
