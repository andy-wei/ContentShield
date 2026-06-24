/** 认证状态管理：存储 NHI token + 自动注入 Authorization 头。

管理 UI 是管理员操作（不强制鉴权），但 token 可选填入用于测试 /v1/* 端点。
 */
import { create } from 'zustand'

const STORAGE_KEY = 'cs_auth_token'

interface AuthState {
  token: string | null
  clientId: string | null
  setToken: (token: string | null, clientId?: string | null) => void
  clear: () => void
}

export const useAuth = create<AuthState>((set) => ({
  token: localStorage.getItem(STORAGE_KEY),
  clientId: localStorage.getItem('cs_client_id'),
  setToken: (token, clientId = null) => {
    if (token) {
      localStorage.setItem(STORAGE_KEY, token)
    } else {
      localStorage.removeItem(STORAGE_KEY)
    }
    if (clientId) localStorage.setItem('cs_client_id', clientId)
    set({ token, clientId: clientId ?? null })
  },
  clear: () => {
    localStorage.removeItem(STORAGE_KEY)
    localStorage.removeItem('cs_client_id')
    set({ token: null, clientId: null })
  },
}))
