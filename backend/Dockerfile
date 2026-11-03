# ContentShield 后端镜像（同时作为 celery-worker 镜像）
# 用 public.ecr.aws 镜像（国内可达，与 docker.io/library/python 内容一致）
FROM public.ecr.aws/docker/library/python:3.12-slim

WORKDIR /app

# 切换为国内 debian 镜像源（避免构建时 502/超时），再安装系统依赖
RUN sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list.d/debian.sources 2>/dev/null \
    || sed -i 's|deb.debian.org|mirrors.tuna.tsinghua.edu.cn|g' /etc/apt/sources.list 2>/dev/null \
    || true
# 系统依赖：git（扫描时 clone 仓库）、curl（下载工具）
# hadolint ignore=DL3008
RUN apt-get update && apt-get install -y --no-install-recommends \
        git \
        curl \
        ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# 安装扫描工具（bandit/pip-audit 走 pip；gitleaks/trivy 走二进制）
# bandit + pip-audit 通过 pyproject 的 dev 依赖装，这里单独装确保生产也有
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple bandit pip-audit

# gitleaks（密钥扫描）— 按目标架构选择二进制
ARG GITLEAKS_VERSION=8.21.2
RUN ARCH=$(case "$(uname -m)" in x86_64) echo "x64";; aarch64|arm64) echo "arm64";; *) echo "x64";; esac) \
    && curl -sSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_${ARCH}.tar.gz" \
    | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks

# trivy（镜像/文件系统漏洞扫描）— 体积较大，按需启用。
# 安装脚本会自动检测架构；网络不稳定时允许失败（适配器运行时会检测可用性）
RUN curl -sfL https://raw.githubusercontent.com/aquasecurity/trivy/main/contrib/install.sh \
    | sh -s -- -b /usr/local/bin v0.55.0 \
    || echo "warn: trivy 安装失败，镜像扫描功能将不可用（其他工具不受影响）"

# 先装 Python 依赖（利用 Docker 层缓存）
COPY pyproject.toml ./
RUN pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple -e ".[postgres]" || pip install --no-cache-dir -i https://pypi.tuna.tsinghua.edu.cn/simple .

# 复制业务代码
COPY app ./app

# 数据目录（SQLite + 词库挂载点）
RUN mkdir -p /app/data
VOLUME /app/data

EXPOSE 8000

# 健康检查（用 Python，不依赖 curl）
HEALTHCHECK --interval=30s --timeout=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8000/healthz', timeout=3)" || exit 1

# 默认启动 API；celery-worker 服务用 command 覆盖
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
