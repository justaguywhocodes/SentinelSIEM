import { useState } from 'react'
import { ChevronRightIcon, ChevronDownIcon } from '@heroicons/react/24/outline'

function FieldGroup({ field, stats, onFilter }) {
  const [expanded, setExpanded] = useState(false)
  const maxCount = stats.values[0]?.count || 1

  return (
    <div className="border-b border-slate-100 dark:border-slate-700 last:border-b-0">
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex items-center gap-1.5 w-full px-3 py-2 text-left hover:bg-slate-50 dark:hover:bg-slate-800/50"
      >
        {expanded
          ? <ChevronDownIcon className="h-3 w-3 text-slate-400 shrink-0" />
          : <ChevronRightIcon className="h-3 w-3 text-slate-400 shrink-0" />
        }
        <span className="text-xs font-mono text-slate-600 dark:text-slate-300 truncate">{field}</span>
        <span className="text-[10px] text-slate-400 ml-auto shrink-0">{stats.values.length} values</span>
      </button>

      {expanded && (
        <div className="px-3 pb-2 space-y-1">
          {stats.values.map(({ value, count, pct }) => (
            <button
              key={value}
              onClick={() => onFilter(field, value)}
              className="group flex items-center gap-2 w-full text-left"
              title={`${field}: "${value}" (${count} events, ${pct}%)`}
            >
              <div className="flex-1 min-w-0">
                <div className="flex items-center justify-between mb-0.5">
                  <span className="text-[11px] text-slate-700 dark:text-slate-300 truncate group-hover:text-indigo-600 dark:group-hover:text-indigo-400">
                    {value}
                  </span>
                  <span className="text-[10px] text-slate-400 ml-1 shrink-0">{pct}%</span>
                </div>
                <div className="h-1 rounded-full bg-slate-100 dark:bg-slate-700 overflow-hidden">
                  <div
                    className="h-full rounded-full bg-indigo-500/60"
                    style={{ width: `${(count / maxCount) * 100}%` }}
                  />
                </div>
              </div>
            </button>
          ))}
        </div>
      )}
    </div>
  )
}

export default function FieldStatsSidebar({ stats, onFilter }) {
  const fields = Object.entries(stats)

  if (fields.length === 0) {
    return (
      <div className="text-center py-8 text-sm text-slate-400">
        Run a search to see field statistics
      </div>
    )
  }

  return (
    <div className="flex flex-col h-full">
      <h3 className="px-3 py-2 text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider border-b border-slate-200 dark:border-slate-700 shrink-0">
        Fields
      </h3>
      <div className="overflow-y-auto flex-1 min-h-0">
        {fields.map(([field, fieldStats]) => (
          <FieldGroup
            key={field}
            field={field}
            stats={fieldStats}
            onFilter={onFilter}
          />
        ))}
      </div>
    </div>
  )
}
