# ContentShield 后端镜像
FROM python:3.12-slim

WORKDIR /app

# 不装额外系统包（避免 apt 网络问题）；健康检查用 Python urllib

# 先装依赖（利用 Docker 层缓存）
COPY pyproject.toml ./
RUN pip install --no-cache-dir -e ".[postgres]" || pip install --no-cache-dir .

# 复制业务代码
COPY app ./app

# 数据目录（SQLite + 词库挂载点）
RUN mkdir -p /app/data
VOLUME /app/data

EXPOSE 8000

# 健康检查（用 Python，不依赖 curl）
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=3)" || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
