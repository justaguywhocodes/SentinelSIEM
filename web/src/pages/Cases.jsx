import { FolderOpenIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'

export default function Cases() {
  usePageTitle('Cases')
  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <FolderOpenIcon className="h-7 w-7 text-indigo-400" />
        <h1 className="text-2xl font-semibold">Cases</h1>
      </div>
      <div className="rounded-lg bg-white border border-slate-200 dark:bg-slate-800 dark:border-slate-700 p-8 text-center text-slate-400">
        Case management coming soon.
      </div>
    </div>
  )
}
