import { useState, useMemo } from 'react'
import { ServerStackIcon, PlusIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'
import IngestionChart from '../components/IngestionChart'
import SourceHealthTable from '../components/SourceHealthTable'
import SourceWizard from '../components/SourceWizard'
import ParserTester from '../components/ParserTester'
import { sourceHealthSources, computeSourceKPIs, ingestionChartData } from '../data/mockSources'

const statusDot = {
  active: 'bg-green-500',
  degraded: 'bg-yellow-500',
  error: 'bg-red-500',
}

export default function Sources() {
  usePageTitle('Sources')
  const [wizardOpen, setWizardOpen] = useState(false)
  const [testerOpen, setTesterOpen] = useState(false)
  const kpis = useMemo(() => computeSourceKPIs(sourceHealthSources), [])

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <ServerStackIcon className="h-7 w-7 text-indigo-400" />
          <h1 className="text-2xl font-semibold">Sources</h1>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setTesterOpen(true)}
            className="px-3 py-1.5 text-xs font-medium rounded-lg border border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800 transition-colors"
          >
            Test Parser
          </button>
          <button
            onClick={() => setWizardOpen(true)}
            className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 transition-colors"
          >
            <PlusIcon className="h-4 w-4" />
            Add Source
          </button>
        </div>
      </div>

      {/* KPI Cards */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-3">
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">{kpis.totalEPS.label}</p>
          <p className="text-2xl font-bold mt-1 text-slate-900 dark:text-white">{kpis.totalEPS.value.toLocaleString()}</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">{kpis.activeSources.label}</p>
          <p className="text-2xl font-bold mt-1 text-slate-900 dark:text-white">{kpis.activeSources.value}</p>
          <div className="mt-2 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
            <div
              className={`h-full rounded-full ${kpis.activeSources.gauge.active === kpis.activeSources.gauge.expected ? 'bg-green-500' : 'bg-amber-500'}`}
              style={{ width: `${(kpis.activeSources.gauge.active / kpis.activeSources.gauge.expected) * 100}%` }}
            />
          </div>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">{kpis.errorRate.label}</p>
          <p className="text-2xl font-bold mt-1 text-slate-900 dark:text-white">{kpis.errorRate.value}</p>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">{kpis.degraded.label}</p>
          <div className="flex items-center gap-2 mt-1">
            <span className={`h-2.5 w-2.5 rounded-full ${statusDot.degraded}`} />
            <p className="text-2xl font-bold text-slate-900 dark:text-white">{kpis.degraded.value}</p>
          </div>
        </div>
        <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 p-4">
          <p className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider">{kpis.errors.label}</p>
          <div className="flex items-center gap-2 mt-1">
            <span className={`h-2.5 w-2.5 rounded-full ${statusDot.error}`} />
            <p className="text-2xl font-bold text-slate-900 dark:text-white">{kpis.errors.value}</p>
          </div>
        </div>
      </div>

      {/* Ingestion Rate Chart */}
      <IngestionChart data={ingestionChartData} />

      {/* Source Health Table */}
      <SourceHealthTable sources={sourceHealthSources} />

      {/* Source Wizard Modal */}
      {wizardOpen && <SourceWizard onClose={() => setWizardOpen(false)} />}

      {/* Parser Tester Modal */}
      {testerOpen && <ParserTester onClose={() => setTesterOpen(false)} />}
    </div>
  )
}
