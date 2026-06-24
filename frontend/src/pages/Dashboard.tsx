/** 仪表盘：统计卡片 + 趋势图 + 类别/层级分布。 */
import { useQuery } from '@tanstack/react-query'
import {
  Bar,
  BarChart,
  CartesianGrid,
  Cell,
  Legend,
  Line,
  LineChart,
  Pie,
  PieChart,
  ResponsiveContainer,
  Tooltip,
  XAxis,
  YAxis,
} from 'recharts'
import { Activity, AlertOctagon, CheckCircle2, Gauge } from 'lucide-react'
import { api } from '../api/client'
import { Card } from '../components/Card'
import { cn, formatNumber, layerLabel } from '../lib/format'

const PIE_COLORS = ['#f43f5e', '#f59e0b', '#3b82f6', '#10b981', '#8b5cf6', '#ec4899']

export function Dashboard() {
  const { data: overview } = useQuery({
    queryKey: ['stats-overview', 30],
    queryFn: () => api.statsOverview(30),
  })
  const { data: trend } = useQuery({
    queryKey: ['stats-trend', 7],
    queryFn: () => api.statsTrend(7),
  })
  const { data: categories } = useQuery({
    queryKey: ['stats-categories', 30],
    queryFn: () => api.statsCategories(30),
  })
  const { data: layers } = useQuery({
    queryKey: ['stats-layers', 30],
    queryFn: () => api.statsLayers(30),
  })

  const stats = [
    {
      label: '检测总数 (30天)',
      value: formatNumber(overview?.total ?? 0),
      icon: Activity,
      color: 'text-brand-600 bg-brand-50',
    },
    {
      label: '拦截数',
      value: formatNumber(overview?.blocked ?? 0),
      sub: `拦截率 ${((overview?.block_rate ?? 0) * 100).toFixed(1)}%`,
      icon: AlertOctagon,
      color: 'text-rose-600 bg-rose-50',
    },
    {
      label: '通过数',
      value: formatNumber(overview?.passed ?? 0),
      icon: CheckCircle2,
      color: 'text-emerald-600 bg-emerald-50',
    },
    {
      label: '平均延迟',
      value: `${Math.round(overview?.avg_latency_ms ?? 0)} ms`,
      sub: `平均风险 ${(overview?.avg_risk_score ?? 0).toFixed(3)}`,
      icon: Gauge,
      color: 'text-amber-600 bg-amber-50',
    },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold text-slate-800">仪表盘</h1>
        <p className="mt-1 text-sm text-slate-500">近 30 天内容安全检测概览</p>
      </div>

      {/* 统计卡片 */}
      <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-4">
        {stats.map((s) => (
          <Card key={s.label} bodyClassName="flex items-center gap-4">
            <div className={cn('flex h-11 w-11 items-center justify-center rounded-lg', s.color)}>
              <s.icon size={20} />
            </div>
            <div>
              <div className="text-2xl font-bold text-slate-800">{s.value}</div>
              <div className="text-xs text-slate-500">
                {s.label}
                {s.sub && <span className="ml-1 text-slate-400">· {s.sub}</span>}
              </div>
            </div>
          </Card>
        ))}
      </div>

      {/* 趋势图 */}
      <Card title="近 7 天检测趋势" subtitle="每日检测量 / 拦截量">
        <div className="h-72">
          <ResponsiveContainer width="100%" height="100%">
            <LineChart data={trend ?? []}>
              <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
              <XAxis dataKey="date" fontSize={12} stroke="#94a3b8" />
              <YAxis fontSize={12} stroke="#94a3b8" />
              <Tooltip />
              <Legend />
              <Line
                type="monotone"
                dataKey="total"
                name="检测总量"
                stroke="#2f7af0"
                strokeWidth={2}
              />
              <Line
                type="monotone"
                dataKey="blocked"
                name="拦截量"
                stroke="#f43f5e"
                strokeWidth={2}
              />
            </LineChart>
          </ResponsiveContainer>
        </div>
      </Card>

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
        {/* 类别分布 */}
        <Card title="命中类别 Top" subtitle="近 30 天">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={(categories ?? []).slice(0, 8)}
                  dataKey="count"
                  nameKey="category"
                  cx="50%"
                  cy="50%"
                  outerRadius={90}
                  label={(e) => `${e.category}: ${e.count}`}
                  fontSize={11}
                >
                  {(categories ?? []).slice(0, 8).map((_, i) => (
                    <Cell key={i} fill={PIE_COLORS[i % PIE_COLORS.length]} />
                  ))}
                </Pie>
                <Tooltip />
              </PieChart>
            </ResponsiveContainer>
          </div>
        </Card>

        {/* 层级分布 */}
        <Card title="各层命中分布" subtitle="近 30 天">
          <div className="h-72">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart
                data={(layers ?? []).map((l) => ({
                  ...l,
                  label: layerLabel[l.layer] ?? l.layer,
                }))}
              >
                <CartesianGrid strokeDasharray="3 3" stroke="#f1f5f9" />
                <XAxis dataKey="label" fontSize={12} stroke="#94a3b8" />
                <YAxis fontSize={12} stroke="#94a3b8" />
                <Tooltip />
                <Bar dataKey="count" name="命中次数" fill="#2f7af0" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </Card>
      </div>
    </div>
  )
}
