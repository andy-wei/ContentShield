/** 应用外壳：侧边栏 + 顶栏。 */
import { useEffect } from 'react'
import { NavLink, Outlet } from 'react-router-dom'
import {
  ShieldCheck,
  LayoutDashboard,
  FlaskConical,
  SlidersHorizontal,
  ScrollText,
  Network,
  KeyRound,
  Settings,
} from 'lucide-react'
import { useSettings } from '../store/settings'
import { cn } from '../lib/format'

const navItems = [
  { to: '/', label: '仪表盘', icon: LayoutDashboard, end: true },
  { to: '/playground', label: '检测台', icon: FlaskConical },
  { to: '/rules', label: '策略配置', icon: SlidersHorizontal },
  { to: '/audit', label: '审计日志', icon: ScrollText },
  { to: '/gateway', label: '网关配置', icon: Network },
  { to: '/identities', label: '身份管理', icon: KeyRound },
  { to: '/settings', label: '系统设置', icon: Settings },
]

export function Layout() {
  const { health, refreshHealth } = useSettings()

  useEffect(() => {
    refreshHealth()
    const timer = setInterval(refreshHealth, 30000)
    return () => clearInterval(timer)
  }, [refreshHealth])

  const ok = health?.status === 'ok'
  const profile = health?.inference_profile ?? '-'

  return (
    <div className="flex h-screen overflow-hidden">
      {/* 侧边栏 */}
      <aside className="flex w-60 flex-shrink-0 flex-col border-r border-slate-200 bg-white">
        <div className="flex items-center gap-2 px-5 py-5">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-brand-500 text-white">
            <ShieldCheck size={20} />
          </div>
          <div>
            <div className="text-sm font-bold text-slate-800">ContentShield</div>
            <div className="text-[11px] text-slate-400">内容安全策略引擎</div>
          </div>
        </div>
        <nav className="flex-1 space-y-1 px-3 py-2">
          {navItems.map((item) => (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.end}
              className={({ isActive }) =>
                cn(
                  'flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition-colors',
                  isActive
                    ? 'bg-brand-50 font-medium text-brand-600'
                    : 'text-slate-600 hover:bg-slate-50',
                )
              }
            >
              <item.icon size={17} />
              {item.label}
            </NavLink>
          ))}
        </nav>
        <div className="border-t border-slate-100 p-4 text-xs text-slate-400">
          v0.1.0 · Llama-Guard-4-12B
        </div>
      </aside>

      {/* 主区域 */}
      <div className="flex flex-1 flex-col overflow-hidden">
        {/* 顶栏 */}
        <header className="flex h-14 flex-shrink-0 items-center justify-between border-b border-slate-200 bg-white px-6">
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <span
              className={cn(
                'h-2 w-2 rounded-full',
                ok ? 'bg-emerald-500' : 'bg-rose-500',
              )}
            />
            后端状态: {ok ? '正常' : '异常'}
            <span className="mx-2 text-slate-300">|</span>
            推理后端:
            <span className="font-medium text-slate-700">{profile}</span>
          </div>
        </header>

        {/* 内容 */}
        <main className="flex-1 overflow-auto p-6">
          <Outlet />
        </main>
      </div>
    </div>
  )
}
