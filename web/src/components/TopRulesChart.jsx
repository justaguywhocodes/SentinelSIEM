import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import { useThemeStore } from '../stores/themeStore'

const severityColors = {
  critical: { dark: '#f87171', light: '#dc2626' },
  high: { dark: '#fb923c', light: '#ea580c' },
  medium: { dark: '#fbbf24', light: '#d97706' },
  low: { dark: '#60a5fa', light: '#2563eb' },
}

function CustomTooltip({ active, payload }) {
  if (!active || !payload?.length) return null
  const d = payload[0].payload
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-xs shadow-lg">
      <p className="font-medium text-slate-800 dark:text-slate-200">{d.rule}</p>
      <p className="text-slate-500 dark:text-slate-400">{d.count} alerts · {d.severity}</p>
    </div>
  )
}

export default function TopRulesChart({ data }) {
  const isDark = useThemeStore((s) => s.isDark())
  const mode = isDark ? 'dark' : 'light'

  // Truncate rule names for Y-axis
  const chartData = data.map(d => ({
    ...d,
    shortName: d.rule.length > 25 ? d.rule.slice(0, 25) + '…' : d.rule,
  }))

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
      <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-3">Top 10 Rules</h3>
      <ResponsiveContainer width="100%" height={200}>
        <BarChart data={chartData} layout="vertical" margin={{ top: 0, right: 10, bottom: 0, left: 0 }}>
          <XAxis
            type="number"
            tick={{ fontSize: 10, fill: isDark ? '#94a3b8' : '#64748b' }}
            axisLine={false}
            tickLine={false}
          />
          <YAxis
            type="category"
            dataKey="shortName"
            tick={{ fontSize: 10, fill: isDark ? '#94a3b8' : '#64748b' }}
            axisLine={false}
            tickLine={false}
            width={140}
          />
          <Tooltip content={<CustomTooltip />} cursor={{ fill: isDark ? '#1e293b' : '#f1f5f9' }} />
          <Bar dataKey="count" radius={[0, 3, 3, 0]} barSize={14}>
            {chartData.map((entry, index) => (
              <Cell key={index} fill={severityColors[entry.severity]?.[mode] || severityColors.medium[mode]} />
            ))}
          </Bar>
        </BarChart>
      </ResponsiveContainer>
    </div>
  )
}
