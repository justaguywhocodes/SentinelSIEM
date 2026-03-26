import { useState, Fragment } from 'react'
import { Area, AreaChart, ResponsiveContainer } from 'recharts'
import { ChevronRightIcon } from '@heroicons/react/24/outline'
import { useThemeStore } from '../stores/themeStore'

const statusDot = {
  active: 'bg-green-500',
  degraded: 'bg-yellow-500',
  error: 'bg-red-500',
  decommissioned: 'bg-slate-400',
}

const statusLabel = {
  active: 'Active',
  degraded: 'Degraded',
  error: 'Error',
  decommissioned: 'Decommissioned',
}

function formatTimestamp(ts) {
  if (!ts) return '—'
  const d = new Date(ts)
  if (isNaN(d.getTime())) return '—'
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  return `${Math.floor(diff / 3600000)}h ago`
}

function MiniSparkline({ data, color }) {
  return (
    <ResponsiveContainer width={60} height={20}>
      <AreaChart data={data}>
        <Area
          type="monotone"
          dataKey="value"
          stroke={color}
          fill={color}
          fillOpacity={0.2}
          strokeWidth={1}
          dot={false}
        />
      </AreaChart>
    </ResponsiveContainer>
  )
}

function ExpandedRow({ source }) {
  return (
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 p-4">
      <div>
        <p className="text-[10px] uppercase text-slate-500 dark:text-slate-400 font-medium mb-1">Protocol</p>
        <p className="text-xs text-slate-700 dark:text-slate-300">{source.protocol}</p>
      </div>
      <div>
        <p className="text-[10px] uppercase text-slate-500 dark:text-slate-400 font-medium mb-1">Parser</p>
        <p className="text-xs text-slate-700 dark:text-slate-300 font-mono">{source.parser}</p>
      </div>
      <div>
        <p className="text-[10px] uppercase text-slate-500 dark:text-slate-400 font-medium mb-1">Events Today</p>
        <p className="text-xs text-slate-700 dark:text-slate-300">{(source.eventsToday || 0).toLocaleString()}</p>
      </div>
      <div>
        <p className="text-[10px] uppercase text-slate-500 dark:text-slate-400 font-medium mb-1">Avg Latency</p>
        <p className="text-xs text-slate-700 dark:text-slate-300">{source.latencyMs || 0}ms</p>
      </div>
      <div>
        <p className="text-[10px] uppercase text-slate-500 dark:text-slate-400 font-medium mb-1">API Key</p>
        <p className="text-xs text-slate-700 dark:text-slate-300 font-mono">{source.apiKeyPrefix || '—'}</p>
      </div>
      <div>
        <p className="text-[10px] uppercase text-slate-500 dark:text-slate-400 font-medium mb-1">Expected Hosts</p>
        <p className="text-xs text-slate-700 dark:text-slate-300">
          {source.expectedHosts?.length > 0 ? source.expectedHosts.join(', ') : '—'}
        </p>
      </div>
      <div>
        <p className="text-[10px] uppercase text-slate-500 dark:text-slate-400 font-medium mb-1">Description</p>
        <p className="text-xs text-slate-700 dark:text-slate-300">{source.description || '—'}</p>
      </div>
      <div>
        <p className="text-[10px] uppercase text-slate-500 dark:text-slate-400 font-medium mb-1">Tags</p>
        <div className="flex flex-wrap gap-1">
          {(source.tags || []).map(tag => (
            <span key={tag} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
              {tag}
            </span>
          ))}
        </div>
      </div>
    </div>
  )
}

const columns = ['', 'Status', 'Source', 'Type', 'EPS', 'Trend', 'Error %', 'Last Event']

export default function SourceHealthTable({ sources }) {
  const [expandedId, setExpandedId] = useState(null)
  const isDark = useThemeStore((s) => s.isDark())
  const sparkColor = isDark ? '#818cf8' : '#6366f1'

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
              {columns.map(col => (
                <th key={col} className="px-3 py-2 text-left text-[10px] font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap">
                  {col}
                </th>
              ))}
            </tr>
          </thead>
          <tbody>
            {sources.map(src => (
              <Fragment key={src.id}>
                <tr
                  onClick={() => setExpandedId(expandedId === src.id ? null : src.id)}
                  className={`border-b border-slate-100 dark:border-slate-800 cursor-pointer hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors ${
                    src.status === 'error' ? 'bg-red-50/50 dark:bg-red-500/5' : ''
                  } ${expandedId === src.id ? 'bg-slate-50 dark:bg-slate-700/20' : ''}`}
                >
                  <td className="px-3 py-2 w-6">
                    <ChevronRightIcon className={`h-3.5 w-3.5 text-slate-400 transition-transform ${expandedId === src.id ? 'rotate-90' : ''}`} />
                  </td>
                  <td className="px-3 py-2">
                    <div className="flex items-center gap-1.5">
                      <span className={`h-2 w-2 rounded-full ${statusDot[src.status]}`} />
                      <span className="text-[10px] text-slate-500 dark:text-slate-400">{statusLabel[src.status]}</span>
                    </div>
                  </td>
                  <td className="px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-300">{src.name}</td>
                  <td className="px-3 py-2">
                    <span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                      {src.type}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs font-mono text-slate-700 dark:text-slate-300">
                    {(src.eps || 0).toLocaleString()}
                  </td>
                  <td className="px-3 py-2">
                    <MiniSparkline data={src.epsSparkline || []} color={sparkColor} />
                  </td>
                  <td className="px-3 py-2">
                    <span className={`text-xs font-mono ${(src.errorRate || 0) > 1 ? 'text-red-500' : (src.errorRate || 0) > 0 ? 'text-slate-500 dark:text-slate-400' : 'text-green-500'}`}>
                      {(src.errorRate || 0).toFixed(2)}%
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    {formatTimestamp(src.lastEvent)}
                  </td>
                </tr>
                {expandedId === src.id && (
                  <tr className="bg-slate-50/50 dark:bg-slate-700/10">
                    <td colSpan={columns.length} className="border-b border-slate-100 dark:border-slate-800">
                      <ExpandedRow source={src} />
                    </td>
                  </tr>
                )}
              </Fragment>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}
