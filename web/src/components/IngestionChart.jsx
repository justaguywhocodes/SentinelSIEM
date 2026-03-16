import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { useThemeStore } from '../stores/themeStore'

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-xs shadow-lg">
      <p className="text-slate-500 dark:text-slate-400 mb-1">{label}</p>
      <div className="flex items-center gap-2">
        <span className="h-2 w-2 rounded-full bg-indigo-500" />
        <span className="text-slate-700 dark:text-slate-300">EPS:</span>
        <span className="font-medium text-slate-800 dark:text-slate-200">{payload[0]?.value?.toLocaleString()}</span>
      </div>
    </div>
  )
}

export default function IngestionChart({ data }) {
  const isDark = useThemeStore((s) => s.isDark())

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
      <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">Ingestion Rate (24h)</h3>
      <ResponsiveContainer width="100%" height={180}>
        <AreaChart data={data} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#334155' : '#e2e8f0'} vertical={false} />
          <XAxis
            dataKey="label"
            tick={{ fontSize: 10, fill: isDark ? '#94a3b8' : '#64748b' }}
            axisLine={{ stroke: isDark ? '#334155' : '#e2e8f0' }}
            tickLine={false}
            interval={5}
          />
          <YAxis
            tick={{ fontSize: 10, fill: isDark ? '#94a3b8' : '#64748b' }}
            axisLine={false}
            tickLine={false}
            width={40}
            tickFormatter={(v) => v >= 1000 ? `${(v / 1000).toFixed(1)}k` : v}
          />
          <Tooltip content={<CustomTooltip />} />
          {/* Anomaly band */}
          <Area
            type="monotone"
            dataKey="upper"
            stackId="band"
            stroke="none"
            fill="transparent"
          />
          <Area
            type="monotone"
            dataKey="lower"
            stackId="band"
            stroke="none"
            fill={isDark ? '#334155' : '#f1f5f9'}
            fillOpacity={0.5}
          />
          {/* Actual EPS */}
          <Area
            type="monotone"
            dataKey="eps"
            stroke={isDark ? '#818cf8' : '#6366f1'}
            fill={isDark ? '#818cf8' : '#6366f1'}
            fillOpacity={0.15}
            strokeWidth={1.5}
          />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
