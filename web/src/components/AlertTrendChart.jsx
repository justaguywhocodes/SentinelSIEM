import { AreaChart, Area, XAxis, YAxis, Tooltip, ResponsiveContainer, CartesianGrid } from 'recharts'
import { useThemeStore } from '../stores/themeStore'

const severityColors = {
  critical: { dark: '#f87171', light: '#dc2626' },
  high: { dark: '#fb923c', light: '#ea580c' },
  medium: { dark: '#fbbf24', light: '#d97706' },
  low: { dark: '#60a5fa', light: '#2563eb' },
}

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-xs shadow-lg">
      <p className="text-slate-500 dark:text-slate-400 mb-1">{label}</p>
      {payload.reverse().map((p) => (
        <div key={p.dataKey} className="flex items-center gap-2">
          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: p.color }} />
          <span className="capitalize text-slate-700 dark:text-slate-300">{p.dataKey}:</span>
          <span className="font-medium text-slate-800 dark:text-slate-200">{p.value}</span>
        </div>
      ))}
    </div>
  )
}

export default function AlertTrendChart({ data }) {
  const isDark = useThemeStore((s) => s.isDark())
  const mode = isDark ? 'dark' : 'light'

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
      <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">Alert Trend (24h)</h3>
      <ResponsiveContainer width="100%" height={200}>
        <AreaChart data={data} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
          <CartesianGrid strokeDasharray="3 3" stroke={isDark ? '#334155' : '#e2e8f0'} vertical={false} />
          <XAxis
            dataKey="hour"
            tick={{ fontSize: 10, fill: isDark ? '#94a3b8' : '#64748b' }}
            axisLine={{ stroke: isDark ? '#334155' : '#e2e8f0' }}
            tickLine={false}
          />
          <YAxis
            tick={{ fontSize: 10, fill: isDark ? '#94a3b8' : '#64748b' }}
            axisLine={false}
            tickLine={false}
            width={30}
          />
          <Tooltip content={<CustomTooltip />} />
          <Area type="monotone" dataKey="low" stackId="1" stroke={severityColors.low[mode]} fill={severityColors.low[mode]} fillOpacity={0.3} strokeWidth={1.5} />
          <Area type="monotone" dataKey="medium" stackId="1" stroke={severityColors.medium[mode]} fill={severityColors.medium[mode]} fillOpacity={0.3} strokeWidth={1.5} />
          <Area type="monotone" dataKey="high" stackId="1" stroke={severityColors.high[mode]} fill={severityColors.high[mode]} fillOpacity={0.3} strokeWidth={1.5} />
          <Area type="monotone" dataKey="critical" stackId="1" stroke={severityColors.critical[mode]} fill={severityColors.critical[mode]} fillOpacity={0.3} strokeWidth={1.5} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}
