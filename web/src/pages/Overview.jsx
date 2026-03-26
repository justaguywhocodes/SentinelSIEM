import { useState, useEffect } from 'react'
import { HomeIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'
import KPICard from '../components/KPICard'
import AlertTrendChart from '../components/AlertTrendChart'
import TopRulesChart from '../components/TopRulesChart'
import NDRHostRiskPanel from '../components/NDRHostRiskPanel'
import { api } from '../lib/api'

const emptyKpis = {
  eventsPerSec: { label: 'Events/sec', value: 0, sparkline: [], change: 0 },
  openAlerts: { label: 'Open Alerts', value: 0, sparkline: [], change: 0, severityDots: { critical: 0, high: 0, medium: 0, low: 0 } },
  mttd: { label: 'MTTD', value: '0m', sparkline: [], change: 0 },
  mttr: { label: 'MTTR', value: '0m', sparkline: [], change: 0 },
  sourceHealth: { label: 'Source Health', value: '0/0', sparkline: [], change: 0, gauge: { active: 0, expected: 0 } },
}

function formatTimestamp(ts) {
  if (!ts) return '—'
  const diff = Date.now() - new Date(ts).getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  return `${Math.floor(diff / 3600000)}h ago`
}

const statusDot = {
  healthy: 'bg-green-500',
  degraded: 'bg-yellow-500',
  error: 'bg-red-500',
}

export default function Overview() {
  usePageTitle('Overview')
  const [kpis, setKpis] = useState(emptyKpis)
  const [alertTrend, setAlertTrend] = useState([])
  const [topRules, setTopRules] = useState([])
  const [sourceHealth, setSourceHealth] = useState([])
  const [ndrHostRisk, setNdrHostRisk] = useState([])
  const [ndrSummary, setNdrSummary] = useState({ totalMonitored: 0, critical: 0, high: 0, medium: 0, low: 0 })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    api.get('/dashboard/overview')
      .then((data) => {
        if (data.kpis) setKpis(data.kpis)
        if (data.alertTrend) setAlertTrend(data.alertTrend)
        if (data.topRules) setTopRules(data.topRules)
        if (data.sourceHealth) setSourceHealth(data.sourceHealth)
        if (data.ndrHostRisk) setNdrHostRisk(data.ndrHostRisk)
        if (data.ndrSummary) setNdrSummary(data.ndrSummary)
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-slate-400">Loading dashboard...</div>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <HomeIcon className="h-7 w-7 text-indigo-400" />
        <h1 className="text-2xl font-semibold">Overview</h1>
      </div>

      {/* Row 1 — KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {Object.values(kpis).map((kpi) => (
          <KPICard key={kpi.label} {...kpi} />
        ))}
      </div>

      {/* Row 2 — Alert Trend + Top Rules */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <AlertTrendChart data={alertTrend} />
        <TopRulesChart data={topRules} />
      </div>

      {/* Row 3 — Source Health Summary */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
          <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Source Health</h3>
        </div>
        {sourceHealth.length === 0 ? (
          <div className="px-4 py-8 text-center text-slate-400 text-sm">No sources configured.</div>
        ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                {['Status', 'Source', 'Type', 'EPS', 'Last Event'].map(col => (
                  <th key={col} className="px-3 py-2 text-left text-[10px] font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sourceHealth.map(src => (
                <tr
                  key={src.name}
                  className={`border-b border-slate-100 dark:border-slate-800 ${
                    src.status === 'error' ? 'bg-red-50 dark:bg-red-500/5' : ''
                  }`}
                >
                  <td className="px-3 py-2">
                    <span className={`inline-block h-2 w-2 rounded-full ${statusDot[src.status] || 'bg-slate-400'}`} />
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
                  <td className="px-3 py-2 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    {formatTimestamp(src.lastEvent)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
        )}
      </div>

      {/* Row 4 — NDR Host Risk */}
      <NDRHostRiskPanel hosts={ndrHostRisk} summary={ndrSummary} />
    </div>
  )
}
