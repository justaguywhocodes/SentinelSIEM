import { HomeIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'
import KPICard from '../components/KPICard'
import AlertTrendChart from '../components/AlertTrendChart'
import TopRulesChart from '../components/TopRulesChart'
import NDRHostRiskPanel from '../components/NDRHostRiskPanel'
import { kpiData, alertTrendData, topRulesData, sourceHealthData, ndrHostRiskData, ndrSummary } from '../data/mockDashboard'

function formatTimestamp(ts) {
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
  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <HomeIcon className="h-7 w-7 text-indigo-400" />
        <h1 className="text-2xl font-semibold">Overview</h1>
      </div>

      {/* Row 1 — KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        {Object.values(kpiData).map((kpi) => (
          <KPICard key={kpi.label} {...kpi} />
        ))}
      </div>

      {/* Row 2 — Alert Trend + Top Rules */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        <AlertTrendChart data={alertTrendData} />
        <TopRulesChart data={topRulesData} />
      </div>

      {/* Row 3 — Source Health Summary */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 overflow-hidden">
        <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
          <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">Source Health</h3>
        </div>
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
              {sourceHealthData.map(src => (
                <tr
                  key={src.name}
                  className={`border-b border-slate-100 dark:border-slate-800 ${
                    src.status === 'error' ? 'bg-red-50 dark:bg-red-500/5' : ''
                  }`}
                >
                  <td className="px-3 py-2">
                    <span className={`inline-block h-2 w-2 rounded-full ${statusDot[src.status]}`} />
                  </td>
                  <td className="px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-300">{src.name}</td>
                  <td className="px-3 py-2">
                    <span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                      {src.type}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs font-mono text-slate-700 dark:text-slate-300">
                    {src.eps.toLocaleString()}
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    {formatTimestamp(src.lastEvent)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Row 4 — NDR Host Risk */}
      <NDRHostRiskPanel hosts={ndrHostRiskData} summary={ndrSummary} />
    </div>
  )
}
