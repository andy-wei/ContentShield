"""Fernet 对称加密：用于加密存储 NHI 的 client_secret 和上游凭据。

主密钥从 ENCRYPTION_KEY 环境变量加载。未配置时进入"开发模式"，
encrypt/decrypt 退化为 no-op（明文存储，仅用于本地测试）。
"""
from __future__ import annotations

import hashlib
import logging
import secrets

from cryptography.fernet import Fernet

from ..config import settings

logger = logging.getLogger(__name__)

_fernet: Fernet | None = None


def _init_fernet() -> Fernet | None:
    """从配置初始化 Fernet。未配置则返回 None（开发模式）。"""
    key = settings.encryption_key.strip()
    if not key:
        return None
    try:
        return Fernet(key.encode())
    except Exception as e:  # noqa: BLE001
        logger.error("ENCRYPTION_KEY 无效，将进入开发模式: %s", e)
        return None


def _get_fernet() -> Fernet | None:
    global _fernet
    if _fernet is None:
        _fernet = _init_fernet()
    return _fernet


def is_encryption_enabled() -> bool:
    """是否启用了加密（配置了有效的 ENCRYPTION_KEY）。"""
    return _get_fernet() is not None


def encrypt(plaintext: str) -> str:
    """加密明文，返回可存储的字符串。

    开发模式（未配置密钥）返回原文 + 前缀标记。
    """
    if not plaintext:
        return ""
    f = _get_fernet()
    if f is None:
        return f"PLAIN:{plaintext}"  # 开发模式明文（带标记便于识别）
    return f.encrypt(plaintext.encode()).decode()


def decrypt(ciphertext: str) -> str:
    """解密密文，返回明文。

    开发模式自动去除 PLAIN: 前缀。
    """
    if not ciphertext:
        return ""
    if ciphertext.startswith("PLAIN:"):
        return ciphertext[6:]
    f = _get_fernet()
    if f is None:
        return ciphertext  # 兜底
    return f.decrypt(ciphertext.encode()).decode()


def generate_client_secret() -> str:
    """生成 32 字节 URL-safe 随机 client_secret。"""
    return secrets.token_urlsafe(32)


def generate_client_id(prefix: str = "agent") -> str:
    """生成带前缀的 client_id，如 agent-a1b2c3d4。"""
    return f"{prefix}-{secrets.token_hex(4)}"


def generate_jti() -> str:
    """生成 JWT ID（唯一标识）。"""
    return secrets.token_urlsafe(16)


def hash_token(token: str) -> str:
    """SHA256 哈希（用于 refresh_token 比对，原文不入库）。"""
    return hashlib.sha256(token.encode()).hexdigest()
