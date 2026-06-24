"""应用配置：从环境变量加载，所有项有合理默认值。"""
from __future__ import annotations

from functools import lru_cache
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """全局配置，对应 .env 文件。"""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
        case_sensitive=False,
    )

    # ---- 通用 ----
    env: str = "dev"
    tz: str = "Asia/Shanghai"
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # ---- 推理后端 ----
    inference_profile: Literal["cloud", "local-gpu", "local-cpu"] = "cloud"

    # cloud
    llama_guard_cloud_base_url: str = "https://openrouter.ai/api/v1"
    llama_guard_cloud_api_key: str = ""
    llama_guard_cloud_model: str = "meta-llama/llama-guard-4-12b"

    # vllm
    vllm_base_url: str = "http://vllm:8001"
    vllm_api_key: str = "not-needed"
    vllm_model: str = "meta-llama/Llama-Guard-4-12B"

    # llama-cpp
    llama_cpp_base_url: str = "http://llama-cpp-guard:8080"
    llama_cpp_api_key: str = "not-needed"
    llama_cpp_model: str = "llama-guard-4-12b"

    # prompt guard 2
    prompt_guard_backend: Literal["llama-cpp", "vllm", "off"] = "llama-cpp"
    prompt_guard_base_url: str = "http://llama-cpp-pg:8080"
    prompt_guard_api_key: str = "not-needed"
    prompt_guard_model: str = "meta-llama/Llama-Prompt-Guard-2-86M"

    # ---- L4 交叉验证（OpenAI Compatible 通用大模型，补 Llama-Guard-4 盲区）----
    # 默认 off，配置 API Key 后启用。用于检测 HAP/恶意代码/越狱等复杂威胁。
    cross_verify_backend: Literal["openai", "off"] = "off"
    cross_verify_base_url: str = "https://api.openai.com/v1"
    cross_verify_api_key: str = ""
    cross_verify_model: str = "gpt-4o-mini"

    # ---- 网关代理 ----
    gateway_enabled: bool = True
    gateway_upstream_base_url: str = "https://api.openai.com/v1"
    gateway_upstream_api_key: str = ""
    gateway_upstream_model: str = "gpt-4o-mini"
    gateway_mode: Literal["pre", "post", "both"] = "both"
    gateway_api_keys: str = ""

    # ---- 策略阈值 ----
    prompt_guard_injection_threshold: float = 0.5
    prompt_guard_jailbreak_threshold: float = 0.5
    # 间接注入检测（更敏感，因为常伪装在网页内容中）
    indirect_injection_threshold: float = 0.3
    indirect_injection_patterns: bool = True
    audit_redact_pii: bool = True
    audit_retention_days: int = 90
    stats_lookback_days: int = 30
    # 流式响应后置检测
    stream_post_check: bool = True

    # ---- NHI 身份与凭据管理 ----
    # Fernet 主密钥（base64）。空字符串=开发模式（降级 anonymous，不鉴权）。
    # 生成方式：python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    encryption_key: str = ""
    jwt_algorithm: str = "HS256"
    access_token_ttl_minutes: int = 15
    refresh_token_ttl_days: int = 7
    jwt_issuer: str = "contentshield"

    # ---- 数据库 ----
    database_url: str = "sqlite+aiosqlite:///./data/contentshield.db"

    # ---- 路径 ----
    data_dir: str = "./data"

    # ---- 便利属性 ----
    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def gateway_api_key_list(self) -> list[str]:
        return [k.strip() for k in self.gateway_api_keys.split(",") if k.strip()]


@lru_cache
def get_settings() -> Settings:
    return Settings()


settings = get_settings()
