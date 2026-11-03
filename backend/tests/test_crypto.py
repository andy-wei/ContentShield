"""加密服务测试：Fernet 加解密、开发模式降级、随机串生成。"""

from __future__ import annotations

import hashlib
import re

import pytest
from cryptography.fernet import Fernet


@pytest.fixture
def with_real_key(monkeypatch):
    """注入一个真实有效的 Fernet 密钥。"""
    from app.config import settings

    key = Fernet.generate_key().decode()
    monkeypatch.setattr(settings, "encryption_key", key)
    yield


class TestEncryptDecrypt:
    def test_dev_mode_returns_plain_prefixed(self):
        """开发模式（无 key）：encrypt 返回 PLAIN: 前缀。"""
        # conftest 已把 encryption_key 设为空字符串
        from app.security import crypto

        crypto._fernet = None

        result = crypto.encrypt("hello")
        assert result == "PLAIN:hello"

    def test_dev_mode_decrypt_strips_prefix(self):
        from app.security import crypto

        crypto._fernet = None

        assert crypto.decrypt("PLAIN:hello") == "hello"

    def test_empty_string(self):
        from app.security import crypto

        crypto._fernet = None

        assert crypto.encrypt("") == ""
        assert crypto.decrypt("") == ""

    def test_roundtrip_with_real_key(self, with_real_key):
        from app.security import crypto

        crypto._fernet = None  # 重置以重新初始化

        plaintext = "sk-super-secret-api-key-12345"
        ciphertext = crypto.encrypt(plaintext)

        # 密文应不同于明文
        assert ciphertext != plaintext
        assert not ciphertext.startswith("PLAIN:")
        # 解密回来应一致
        assert crypto.decrypt(ciphertext) == plaintext

    def test_different_encryptions_differ(self, with_real_key):
        """Fernet 每次加密结果不同（含随机 IV）。"""
        from app.security import crypto

        crypto._fernet = None

        c1 = crypto.encrypt("same")
        c2 = crypto.encrypt("same")
        assert c1 != c2
        # 但解密都还原
        assert crypto.decrypt(c1) == crypto.decrypt(c2) == "same"

    def test_unicode(self, with_real_key):
        from app.security import crypto

        crypto._fernet = None

        text = "中文密钥🔑"
        assert crypto.decrypt(crypto.encrypt(text)) == text

    def test_is_encryption_enabled_dev_mode(self):
        from app.security import crypto

        crypto._fernet = None

        assert crypto.is_encryption_enabled() is False

    def test_is_encryption_enabled_with_key(self, with_real_key):
        from app.security import crypto

        crypto._fernet = None

        assert crypto.is_encryption_enabled() is True


class TestGenerators:
    def test_generate_client_secret_is_url_safe(self):
        from app.security.crypto import generate_client_secret

        s = generate_client_secret()
        assert isinstance(s, str)
        assert len(s) >= 32
        # URL-safe 字符集
        assert re.match(r"^[A-Za-z0-9_-]+$", s)

    def test_generate_client_secret_uniqueness(self):
        from app.security.crypto import generate_client_secret

        secrets = {generate_client_secret() for _ in range(100)}
        assert len(secrets) == 100  # 几乎不可能碰撞

    def test_generate_client_id_has_prefix(self):
        from app.security.crypto import generate_client_id

        cid = generate_client_id()
        assert cid.startswith("agent-")
        # 默认前缀
        assert generate_client_id("service").startswith("service-")

    def test_generate_jti(self):
        from app.security.crypto import generate_jti

        j = generate_jti()
        assert isinstance(j, str) and len(j) > 0

    def test_hash_token_is_sha256(self):
        from app.security.crypto import hash_token

        token = "my-refresh-token"
        h = hash_token(token)
        expected = hashlib.sha256(token.encode()).hexdigest()
        assert h == expected
        assert len(h) == 64  # SHA256 hex 长度
