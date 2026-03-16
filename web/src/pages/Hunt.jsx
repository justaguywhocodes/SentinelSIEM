import { MagnifyingGlassIcon } from '@heroicons/react/24/outline'

export default function Hunt() {
  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <MagnifyingGlassIcon className="h-7 w-7 text-indigo-400" />
        <h1 className="text-2xl font-semibold">Hunt</h1>
      </div>
      <div className="rounded-lg bg-white border border-slate-200 dark:bg-slate-800 dark:border-slate-700 p-8 text-center text-slate-400">
        Threat hunting query interface coming soon.
      </div>
    </div>
  )
}
