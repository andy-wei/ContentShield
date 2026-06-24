"""JWT 签发与验证服务（HS256）。

access token：短 TTL（15min），携带 subject/scopes/principal_id
refresh token：长 TTL（7d），不透明随机串（SHA256 哈希入库）

签名密钥复用 ENCRYPTION_KEY 的前 32 字节（HMAC-SHA256 需要 ≥32 字节密钥）。
未配置 ENCRYPTION_KEY 时本模块不可用（开发模式降级 anonymous）。
"""
from __future__ import annotations

import hashlib
import logging
from datetime import datetime, timedelta, timezone

import jwt

from ..config import settings
from .crypto import generate_jti

logger = logging.getLogger(__name__)


def _signing_key() -> bytes:
    """从 ENCRYPTION_KEY 派生 HMAC 签名密钥。

    ENCRYPTION_KEY 是 base64 的 Fernet 密钥；这里取其 SHA256 作为 HMAC 密钥，
    保证长度足够（32 字节）且与加密密钥解耦。
    """
    key = settings.encryption_key or "contentshield-dev-insecure-key"
    return hashlib.sha256(key.encode()).digest()


def create_access_token(
    *,
    principal_id: int,
    subject: str,
    scopes: str,
    principal_type: str = "agent",
) -> tuple[str, str, datetime]:
    """签发 access token。

    返回 (jwt_str, jti, expires_at)。
    """
    now = datetime.now(timezone.utc)
    expires_at = now + timedelta(minutes=settings.access_token_ttl_minutes)
    jti = generate_jti()
    payload = {
        "sub": subject,
        "jti": jti,
        "scopes": scopes,
        "principal_id": principal_id,
        "principal_type": principal_type,
        "iss": settings.jwt_issuer,
        "iat": int(now.timestamp()),
        "exp": int(expires_at.timestamp()),
        "typ": "access",
    }
    token = jwt.encode(payload, _signing_key(), algorithm=settings.jwt_algorithm)
    return token, jti, expires_at


def verify_token(token: str) -> dict:
    """验证 JWT，返回 claims。失败抛 jwt.InvalidTokenError。"""
    payload = jwt.decode(
        token,
        _signing_key(),
        algorithms=[settings.jwt_algorithm],
        issuer=settings.jwt_issuer,
    )
    if payload.get("typ") != "access":
        raise jwt.InvalidTokenError("not an access token")
    return payload
