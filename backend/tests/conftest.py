"""pytest 全局夹具与配置。

测试分层：
1. 纯函数测试（无 DB 依赖）：检测器正则、风险评分、JWT、加密、工具策略 —— CI 稳定快速
2. DB 集成测试（标记 @pytest.mark.asyncio + db_session）：未来扩展

通过环境变量强制开发模式（无 ENCRYPTION_KEY），让纯函数测试无需真实密钥。
"""

from __future__ import annotations

import os

# 必须在导入 app 模块前设置，确保开发模式 + 内存 DB（测试不污染本地 SQLite）
os.environ.setdefault("ENCRYPTION_KEY", "")
# 测试用临时 SQLite（:memory: 最干净；FastAPI lifespan 之外手动 init_db 时生效）
os.environ.setdefault("DATABASE_URL", "sqlite+aiosqlite:///:memory:")

import pytest  # noqa: E402


@pytest.fixture(autouse=True)
def _reset_crypto_singleton():
    """每个测试前重置 crypto 模块的全局 Fernet 单例。

    开发模式下 _fernet 保持 None；若某测试显式注入了密钥，需在测试间隔离。
    """
    from app.security import crypto

    old = crypto._fernet
    crypto._fernet = None  # 强制下次 _get_fernet() 重新初始化
    yield
    crypto._fernet = old
