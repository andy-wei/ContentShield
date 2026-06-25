"""客户端 IP 获取工具（处理反向代理链）。

优先级：X-Forwarded-For（取第一个，最原始客户端）→ X-Real-IP → request.client.host
"""
from __future__ import annotations

from starlette.requests import Request


def get_client_ip(request: Request) -> str:
    """获取真实客户端 IP。

    处理 nginx/docker 反向代理场景下的 X-Forwarded-For 链。
    """
    # X-Forwarded-For: client, proxy1, proxy2 → 取第一个（最原始）
    xff = request.headers.get("x-forwarded-for")
    if xff:
        # 取第一个非空 IP
        for ip in xff.split(","):
            ip = ip.strip()
            if ip:
                return ip

    # X-Real-IP（nginx 常用）
    xri = request.headers.get("x-real-ip")
    if xri:
        return xri.strip()

    # 直连
    if request.client:
        return request.client.host

    return "unknown"
