import { useState } from 'react'
import { ChevronDownIcon, ChevronUpIcon } from '@heroicons/react/24/outline'
import { ShieldExclamationIcon } from '@heroicons/react/24/solid'

function formatTimestamp(ts) {
  const d = new Date(ts)
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return d.toLocaleDateString()
}

function QuadrantBadge({ quadrant }) {
  const config = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
  }
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-medium border uppercase ${config[quadrant] || ''}`}>
      {quadrant}
    </span>
  )
}

function ScoreBar({ score, max = 100 }) {
  let color = 'bg-blue-500'
  if (score >= 80) color = 'bg-red-500'
  else if (score >= 60) color = 'bg-orange-500'
  else if (score >= 40) color = 'bg-yellow-500'

  return (
    <div className="flex items-center gap-2">
      <div className="w-16 h-1.5 rounded-full bg-slate-200 dark:bg-slate-700 overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${(score / max) * 100}%` }} />
      </div>
      <span className="text-xs font-mono text-slate-700 dark:text-slate-300">{score}</span>
    </div>
  )
}

export default function NDRHostRiskPanel({ hosts, summary }) {
  const hasCriticalHigh = hosts.length > 0
  const [expanded, setExpanded] = useState(hasCriticalHigh)

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 overflow-hidden">
      {/* Header */}
      <button
        onClick={() => setExpanded(prev => !prev)}
        className="flex items-center justify-between w-full px-4 py-3 text-left hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors"
      >
        <div className="flex items-center gap-2">
          <ShieldExclamationIcon className="h-5 w-5 text-red-400" />
          <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">NDR Host Risk</h3>
          <span className="text-xs text-slate-400">{summary.totalMonitored} hosts monitored</span>
        </div>
        <div className="flex items-center gap-3">
          {summary.critical > 0 && (
            <span className="text-xs font-medium text-red-400">{summary.critical} Critical</span>
          )}
          {summary.high > 0 && (
            <span className="text-xs font-medium text-orange-400">{summary.high} High</span>
          )}
          {expanded
            ? <ChevronUpIcon className="h-4 w-4 text-slate-400" />
            : <ChevronDownIcon className="h-4 w-4 text-slate-400" />
          }
        </div>
      </button>

      {/* Table */}
      {expanded && (
        <div className="overflow-x-auto border-t border-slate-200 dark:border-slate-700">
          <table className="w-full">
            <thead>
              <tr className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                {['IP', 'Hostname', 'Threat', 'Certainty', 'Quadrant', 'Detections', 'Top Tactic', 'Last Detection'].map(col => (
                  <th key={col} className="px-3 py-2 text-left text-[10px] font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap">
                    {col}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {hosts.map(host => (
                <tr key={host.ip} className="border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors">
                  <td className="px-3 py-2 text-xs font-mono text-slate-700 dark:text-slate-300">{host.ip}</td>
                  <td className="px-3 py-2 text-xs text-slate-700 dark:text-slate-300">{host.hostname}</td>
                  <td className="px-3 py-2"><ScoreBar score={host.threatScore} /></td>
                  <td className="px-3 py-2"><ScoreBar score={host.certaintyScore} /></td>
                  <td className="px-3 py-2"><QuadrantBadge quadrant={host.quadrant} /></td>
                  <td className="px-3 py-2 text-xs font-medium text-slate-700 dark:text-slate-300 text-center">{host.activeDetections}</td>
                  <td className="px-3 py-2">
                    <span className="text-xs px-1.5 py-0.5 rounded bg-slate-100 dark:bg-slate-700 text-slate-600 dark:text-slate-300">
                      {host.topTactic}
                    </span>
                  </td>
                  <td className="px-3 py-2 text-xs text-slate-500 dark:text-slate-400 whitespace-nowrap">
                    {formatTimestamp(host.lastDetection)}
                  </td>
                </tr>
              ))}
              {hosts.length === 0 && (
                <tr>
                  <td colSpan={8} className="px-4 py-6 text-center text-sm text-slate-400">
                    No hosts in Critical or High quadrants
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
