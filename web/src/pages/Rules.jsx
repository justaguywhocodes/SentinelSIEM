import { ShieldCheckIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'

export default function Rules() {
  usePageTitle('Rules')
  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <ShieldCheckIcon className="h-7 w-7 text-indigo-400" />
        <h1 className="text-2xl font-semibold">Rules</h1>
      </div>
      <div className="rounded-lg bg-white border border-slate-200 dark:bg-slate-800 dark:border-slate-700 p-8 text-center text-slate-400">
        Sigma rule management and ATT&CK coverage coming soon.
      </div>
    </div>
  )
}
