# vLLM 服务：本地 GPU 跑 Llama-Guard-4-12B
# 模型通过卷挂载到 /models，无需打进镜像
FROM vllm/vllm-openai:latest

ENV HOST=0.0.0.0
ENV PORT=8000

# 模型路径、名称、显存占比、上下文长度由 docker-compose 注入：
#   MODEL_PATH / MODEL_NAME / GPU_MEM_UTIL / MAX_MODEL_LEN / API_KEY / PORT
EXPOSE 8000

# vLLM 官方镜像入口为 vllm serve；这里用环境变量拼参数
# -dt 限制输出 token（Llama-Guard 输出极短），--enable-auto-tool-choice 关闭工具调用干扰
CMD ["sh", "-c", "python3 -m vllm.entrypoints.openai.api_server \
    --host $HOST --port $PORT \
    --model $MODEL_PATH \
    --served-model-name $MODEL_NAME \
    --gpu-memory-utilization $GPU_MEM_UTIL \
    --max-model-len $MAX_MODEL_LEN \
    --dtype auto \
    --api-key $API_KEY \
    --trust-remote-code"]
