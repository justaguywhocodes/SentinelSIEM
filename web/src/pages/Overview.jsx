import { HomeIcon } from '@heroicons/react/24/outline'

export default function Overview() {
  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <HomeIcon className="h-7 w-7 text-indigo-400" />
        <h1 className="text-2xl font-semibold">Overview</h1>
      </div>
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-5 gap-4">
        {['Events/sec', 'Open Alerts', 'MTTD', 'MTTR', 'Source Health'].map((kpi) => (
          <div key={kpi} className="rounded-lg bg-white border border-slate-200 dark:bg-slate-800 dark:border-slate-700 p-4">
            <p className="text-sm text-slate-400">{kpi}</p>
            <p className="text-2xl font-bold mt-1">—</p>
          </div>
        ))}
      </div>
    </div>
  )
}
