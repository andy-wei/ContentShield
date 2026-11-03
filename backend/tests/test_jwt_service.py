"""JWT 服务测试：签发与验证、过期、签名密钥派生。

不依赖 DB。需要设置 ENCRYPTION_KEY（conftest 已置空，这里临时注入）。
"""

from __future__ import annotations

import hashlib

import jwt
import pytest


@pytest.fixture
def with_encryption_key(monkeypatch):
    """临时注入一个 ENCRYPTION_KEY，让 JWT 签名可用。"""
    from app.config import settings

    monkeypatch.setattr(settings, "encryption_key", "test-encryption-key-for-jwt-1234567890")
    yield


class TestCreateAccessToken:
    def test_creates_valid_token(self, with_encryption_key):
        from app.security.jwt_service import create_access_token

        token, jti, expires_at = create_access_token(
            principal_id=1, subject="agent-x", scopes="read"
        )

        assert isinstance(token, str)
        assert token.count(".") == 2  # JWT 三段式
        assert isinstance(jti, str) and len(jti) > 0
        assert expires_at is not None

    def test_token_carries_claims(self, with_encryption_key):
        from app.security.jwt_service import create_access_token, verify_token

        token, jti, _ = create_access_token(
            principal_id=42, subject="agent-foo", scopes="read,write", principal_type="service"
        )

        claims = verify_token(token)
        assert claims["sub"] == "agent-foo"
        assert claims["principal_id"] == 42
        assert claims["scopes"] == "read,write"
        assert claims["principal_type"] == "service"
        assert claims["jti"] == jti
        assert claims["typ"] == "access"
        assert claims["iss"]  # 签发者非空


class TestVerifyToken:
    def test_valid_token_roundtrip(self, with_encryption_key):
        from app.security.jwt_service import create_access_token, verify_token

        token, _, _ = create_access_token(principal_id=1, subject="s", scopes="")
        claims = verify_token(token)
        assert claims["sub"] == "s"

    def test_expired_token_rejected(self, with_encryption_key, monkeypatch):
        from app.config import settings

        # 设 TTL 为负值让 token 立刻过期
        monkeypatch.setattr(settings, "access_token_ttl_minutes", -10)
        from app.security.jwt_service import create_access_token

        token, _, _ = create_access_token(principal_id=1, subject="s", scopes="")

        from app.security.jwt_service import verify_token

        with pytest.raises(jwt.ExpiredSignatureError):
            verify_token(token)

    def test_wrong_signature_rejected(self, with_encryption_key, monkeypatch):
        from app.security.jwt_service import create_access_token, verify_token

        token, _, _ = create_access_token(principal_id=1, subject="s", scopes="")

        # 换密钥
        from app.config import settings

        monkeypatch.setattr(settings, "encryption_key", "a-completely-different-key-9876543210")

        with pytest.raises(jwt.InvalidTokenError):
            verify_token(token)

    def test_non_access_token_rejected(self, with_encryption_key):
        """typ != access 的 token 应被拒绝（防 refresh 当 access 用）。"""
        # 手工构造一个 typ=refresh 的 token
        import datetime

        from app.config import settings
        from app.security.jwt_service import _signing_key, verify_token

        payload = {
            "sub": "s",
            "jti": "x",
            "iss": settings.jwt_issuer,
            "exp": int(datetime.datetime.now(datetime.UTC).timestamp()) + 100,
            "typ": "refresh",
        }
        token = jwt.encode(payload, _signing_key(), algorithm=settings.jwt_algorithm)

        with pytest.raises(jwt.InvalidTokenError):
            verify_token(token)

    def test_malformed_token_rejected(self, with_encryption_key):
        from app.security.jwt_service import verify_token

        with pytest.raises(jwt.InvalidTokenError):
            verify_token("not.a.jwt")
        with pytest.raises(jwt.InvalidTokenError):
            verify_token("garbage")


class TestSigningKey:
    def test_signing_key_derived_from_encryption_key(self, with_encryption_key, monkeypatch):
        """签名密钥 = SHA256(ENCRYPTION_KEY)，且与加密密钥解耦。"""
        from app.config import settings
        from app.security.jwt_service import _signing_key

        sk = _signing_key()
        expected = hashlib.sha256(settings.encryption_key.encode()).digest()
        assert sk == expected
