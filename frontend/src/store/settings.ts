/** 全局设置 store（推理 profile、健康状态）。 */
import { create } from 'zustand'
import { api } from '../api/client'
import type { HealthStatus } from '../api/types'

interface SettingsState {
  health: HealthStatus | null
  loading: boolean
  refreshHealth: () => Promise<void>
}

export const useSettings = create<SettingsState>((set) => ({
  health: null,
  loading: false,
  refreshHealth: async () => {
    set({ loading: true })
    try {
      const health = await api.health()
      set({ health, loading: false })
    } catch {
      set({ loading: false })
    }
  },
}))
