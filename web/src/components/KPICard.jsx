import { Area, AreaChart, ResponsiveContainer } from 'recharts'
import { useThemeStore } from '../stores/themeStore'

const severityColors = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
}

export default function KPICard({ label, value, sparkline, change, severityDots, gauge }) {
  const isDark = useThemeStore((s) => s.isDark())
  const isPositiveGood = label === 'Events/sec' || label === 'Source Health'
  const isNegativeGood = label === 'MTTD' || label === 'MTTR' || label === 'Open Alerts'

  let changeColor = 'text-slate-400'
  if (change > 0) changeColor = isPositiveGood ? 'text-green-500' : 'text-red-400'
  if (change < 0) changeColor = isNegativeGood ? 'text-green-500' : 'text-red-400'

  const sparkColor = isDark ? '#818cf8' : '#6366f1'

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4 flex flex-col justify-between">
      <div className="flex items-start justify-between">
        <div>
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">{label}</p>
          <p className="text-2xl font-bold mt-1 text-slate-900 dark:text-white">
            {typeof value === 'number' ? Intl.NumberFormat('en', { notation: 'compact' }).format(value) : value}
          </p>
        </div>
        {change !== 0 && (
          <span className={`text-xs font-medium ${changeColor}`}>
            {change > 0 ? '↑' : '↓'} {Math.abs(change)}%
          </span>
        )}
      </div>

      {/* Severity dots for Open Alerts */}
      {severityDots && (
        <div className="flex items-center gap-1.5 mt-2">
          {Object.entries(severityDots).map(([sev, count]) => (
            <div key={sev} className="flex items-center gap-0.5">
              <span className={`h-2 w-2 rounded-full ${severityColors[sev]}`} />
              <span className="text-[10px] text-slate-500 dark:text-slate-400">{count}</span>
            </div>
          ))}
        </div>
      )}

      {/* Source health gauge */}
      {gauge && (
        <div className="mt-2">
          <div className="h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
            <div
              className={`h-full rounded-full ${gauge.active === gauge.expected ? 'bg-green-500' : 'bg-amber-500'}`}
              style={{ width: `${(gauge.active / gauge.expected) * 100}%` }}
            />
          </div>
        </div>
      )}

      {/* Sparkline */}
      {sparkline && (
        <div className="mt-2 -mx-1">
          <ResponsiveContainer width="100%" height={32}>
            <AreaChart data={sparkline}>
              <defs>
                <linearGradient id={`spark-${label}`} x1="0" y1="0" x2="0" y2="1">
                  <stop offset="0%" stopColor={sparkColor} stopOpacity={0.3} />
                  <stop offset="100%" stopColor={sparkColor} stopOpacity={0} />
                </linearGradient>
              </defs>
              <Area
                type="monotone"
                dataKey="value"
                stroke={sparkColor}
                strokeWidth={1.5}
                fill={`url(#spark-${label})`}
                dot={false}
              />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      )}
    </div>
  )
}
