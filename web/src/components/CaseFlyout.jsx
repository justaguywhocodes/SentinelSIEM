import { useState } from 'react'
import { XMarkIcon } from '@heroicons/react/24/outline'
import { Tab, TabGroup, TabList, TabPanel, TabPanels } from '@headlessui/react'
import SeverityBadge from './SeverityBadge'
import StatusBadge from './StatusBadge'
import CaseTimeline from './CaseTimeline'
import ObservableList from './ObservableList'

function formatTimestamp(ts) {
  const d = new Date(ts)
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return d.toLocaleDateString()
}

const validTransitions = {
  new: ['in_progress'],
  in_progress: ['resolved', 'closed'],
  resolved: ['in_progress', 'closed'],
  closed: ['in_progress'],
}

const resolutionTypes = [
  { value: 'true_positive', label: 'True Positive' },
  { value: 'false_positive', label: 'False Positive' },
  { value: 'benign', label: 'Benign' },
  { value: 'duplicate', label: 'Duplicate' },
]

function OverviewTab({ caseData }) {
  return (
    <div className="space-y-4">
      <div>
        <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Title</h4>
        <p className="text-sm text-slate-800 dark:text-slate-200 font-medium">{caseData.title}</p>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Severity</h4>
          <SeverityBadge severity={caseData.severity} />
        </div>
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Status</h4>
          <StatusBadge status={caseData.status} />
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Assignee</h4>
          <p className="text-sm text-slate-700 dark:text-slate-300">{caseData.assignee || 'Unassigned'}</p>
        </div>
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Created</h4>
          <p className="text-sm text-slate-700 dark:text-slate-300">{formatTimestamp(caseData.created_at)}</p>
        </div>
      </div>

      {caseData.tags && caseData.tags.length > 0 && (
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">MITRE Tags</h4>
          <div className="flex flex-wrap gap-1">
            {caseData.tags.map((tag) => (
              <span key={tag} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300">
                {tag}
              </span>
            ))}
          </div>
        </div>
      )}

      {caseData.resolution && (
        <div>
          <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Resolution</h4>
          <p className="text-sm text-slate-700 dark:text-slate-300">
            <span className="font-medium capitalize">{caseData.resolution.type.replace('_', ' ')}</span>
            {caseData.resolution.notes && <span className="text-slate-500"> — {caseData.resolution.notes}</span>}
          </p>
        </div>
      )}

      <div>
        <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-1">Summary</h4>
        <div className="grid grid-cols-3 gap-2">
          <div className="rounded-lg bg-slate-50 dark:bg-slate-800/50 p-2 text-center">
            <div className="text-lg font-semibold text-slate-800 dark:text-white">{caseData.alert_ids?.length || 0}</div>
            <div className="text-xs text-slate-500">Alerts</div>
          </div>
          <div className="rounded-lg bg-slate-50 dark:bg-slate-800/50 p-2 text-center">
            <div className="text-lg font-semibold text-slate-800 dark:text-white">{caseData.observables?.length || 0}</div>
            <div className="text-xs text-slate-500">Observables</div>
          </div>
          <div className="rounded-lg bg-slate-50 dark:bg-slate-800/50 p-2 text-center">
            <div className="text-lg font-semibold text-slate-800 dark:text-white">{caseData.tags?.length || 0}</div>
            <div className="text-xs text-slate-500">MITRE Tags</div>
          </div>
        </div>
      </div>
    </div>
  )
}

function AlertsTab({ caseData }) {
  const alertIds = caseData.alert_ids || []
  if (alertIds.length === 0) {
    return <p className="text-sm text-slate-400">No alerts linked.</p>
  }

  return (
    <div className="space-y-2">
      <h4 className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider mb-2">
        Linked Alerts ({alertIds.length})
      </h4>
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 divide-y divide-slate-200 dark:divide-slate-700">
        {alertIds.map((id) => (
          <div key={id} className="flex items-center px-3 py-2">
            <a
              href={`/alerts?id=${id}`}
              className="text-sm font-mono text-blue-500 hover:text-blue-400 hover:underline cursor-pointer"
            >
              {id}
            </a>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function CaseFlyout({ caseData, onClose, onStatusChange, onAddComment }) {
  const [commentText, setCommentText] = useState('')
  const [showCloseModal, setShowCloseModal] = useState(false)
  const [resolutionType, setResolutionType] = useState('true_positive')
  const [resolutionNotes, setResolutionNotes] = useState('')

  if (!caseData) return null

  const transitions = validTransitions[caseData.status] || []

  function handleStatusChange(newStatus) {
    if (newStatus === 'closed') {
      setShowCloseModal(true)
      return
    }
    onStatusChange?.(caseData.id, newStatus)
  }

  function handleClose() {
    onStatusChange?.(caseData.id, 'closed', { type: resolutionType, notes: resolutionNotes })
    setShowCloseModal(false)
    setResolutionType('true_positive')
    setResolutionNotes('')
  }

  function handleComment() {
    if (!commentText.trim()) return
    onAddComment?.(caseData.id, commentText.trim())
    setCommentText('')
  }

  return (
    <>
      <div className="fixed inset-y-0 right-0 z-40 w-[520px] max-w-full flex flex-col bg-white dark:bg-slate-900 border-l border-slate-200 dark:border-slate-700 shadow-2xl">
        {/* Header */}
        <div className="flex items-start gap-3 p-4 border-b border-slate-200 dark:border-slate-700">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 mb-1">
              <SeverityBadge severity={caseData.severity} />
              <StatusBadge status={caseData.status} />
            </div>
            <h3 className="text-sm font-semibold text-slate-900 dark:text-white truncate">{caseData.title}</h3>
            <p className="text-xs text-slate-500 dark:text-slate-400 mt-0.5">
              {formatTimestamp(caseData.created_at)} · {caseData.id}
              {caseData.assignee && <span> · Assigned to {caseData.assignee}</span>}
            </p>
          </div>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-white p-1">
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>

        {/* Tabs */}
        <TabGroup className="flex-1 flex flex-col min-h-0">
          <TabList className="flex border-b border-slate-200 dark:border-slate-700 px-4">
            {['Overview', 'Alerts', 'Observables', 'Timeline'].map((tab) => (
              <Tab
                key={tab}
                className={({ selected }) =>
                  `px-3 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors outline-none ${
                    selected
                      ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400'
                      : 'border-transparent text-slate-500 dark:text-slate-400 hover:text-slate-700 dark:hover:text-slate-300'
                  }`
                }
              >
                {tab}
              </Tab>
            ))}
          </TabList>

          <TabPanels className="flex-1 overflow-y-auto p-4">
            <TabPanel><OverviewTab caseData={caseData} /></TabPanel>
            <TabPanel><AlertsTab caseData={caseData} /></TabPanel>
            <TabPanel><ObservableList observables={caseData.observables} /></TabPanel>
            <TabPanel><CaseTimeline timeline={caseData.timeline} /></TabPanel>
          </TabPanels>
        </TabGroup>

        {/* Comment input */}
        <div className="px-4 py-2 border-t border-slate-200 dark:border-slate-700">
          <div className="flex gap-2">
            <input
              type="text"
              value={commentText}
              onChange={(e) => setCommentText(e.target.value)}
              onKeyDown={(e) => e.key === 'Enter' && handleComment()}
              placeholder="Add a comment..."
              className="flex-1 px-3 py-1.5 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 placeholder-slate-400"
            />
            <button
              onClick={handleComment}
              disabled={!commentText.trim()}
              className="px-3 py-1.5 text-sm font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
            >
              Send
            </button>
          </div>
        </div>

        {/* Footer actions */}
        <div className="flex items-center gap-2 p-4 border-t border-slate-200 dark:border-slate-700">
          {transitions.map((status) => {
            const isClose = status === 'closed'
            const isPrimary = status === 'in_progress' && caseData.status === 'new'
            const label = {
              in_progress: 'Start Investigation',
              resolved: 'Mark Resolved',
              closed: 'Close Case',
            }[status] || status

            return (
              <button
                key={status}
                onClick={() => handleStatusChange(status)}
                className={`flex-1 px-3 py-2 text-sm font-medium rounded-lg transition-colors ${
                  isPrimary
                    ? 'bg-indigo-600 text-white hover:bg-indigo-500'
                    : isClose
                    ? 'border border-red-300 dark:border-red-700 text-red-600 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-900/20'
                    : 'border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-800'
                }`}
              >
                {label}
              </button>
            )
          })}
        </div>
      </div>

      {/* Close / Resolution Modal */}
      {showCloseModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/50">
          <div className="bg-white dark:bg-slate-900 rounded-xl border border-slate-200 dark:border-slate-700 shadow-2xl p-6 w-[400px] max-w-[90vw]">
            <h3 className="text-lg font-semibold text-slate-900 dark:text-white mb-4">Close Case</h3>
            <p className="text-sm text-slate-600 dark:text-slate-400 mb-4">Select a resolution type to close this case.</p>

            <div className="space-y-3">
              <div>
                <label className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 block">Resolution Type</label>
                <select
                  value={resolutionType}
                  onChange={(e) => setResolutionType(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 text-sm"
                >
                  {resolutionTypes.map((rt) => (
                    <option key={rt.value} value={rt.value}>{rt.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-sm font-medium text-slate-700 dark:text-slate-300 mb-1 block">Notes (optional)</label>
                <textarea
                  value={resolutionNotes}
                  onChange={(e) => setResolutionNotes(e.target.value)}
                  rows={3}
                  className="w-full px-3 py-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-800 dark:text-slate-200 text-sm"
                  placeholder="Add resolution notes..."
                />
              </div>
            </div>

            <div className="flex justify-end gap-2 mt-4">
              <button
                onClick={() => setShowCloseModal(false)}
                className="px-4 py-2 text-sm font-medium rounded-lg text-slate-600 dark:text-slate-400 hover:bg-slate-100 dark:hover:bg-slate-800 transition-colors"
              >
                Cancel
              </button>
              <button
                onClick={handleClose}
                className="px-4 py-2 text-sm font-medium rounded-lg bg-red-600 text-white hover:bg-red-500 transition-colors"
              >
                Close Case
              </button>
            </div>
          </div>
        </div>
      )}
    </>
  )
}
