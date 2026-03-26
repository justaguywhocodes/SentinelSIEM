import { useState, useEffect, useMemo } from 'react'
import { FolderOpenIcon, FunnelIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
} from '@tanstack/react-table'
import SeverityBadge, { getSeverityBorderClass } from '../components/SeverityBadge'
import StatusBadge from '../components/StatusBadge'
import CaseFlyout from '../components/CaseFlyout'
import { api } from '../lib/api'

function formatTimestamp(ts) {
  const d = new Date(ts)
  const diff = Date.now() - d.getTime()
  if (diff < 60000) return 'just now'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}m ago`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}h ago`
  return d.toLocaleDateString()
}

const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 }

const columns = [
  {
    accessorKey: 'severity',
    header: 'Severity',
    cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
    size: 100,
    sortingFn: (a, b) => (severityOrder[a.original.severity] ?? 99) - (severityOrder[b.original.severity] ?? 99),
  },
  {
    accessorKey: 'title',
    header: 'Title',
    cell: ({ getValue }) => (
      <span className="text-sm font-medium text-slate-800 dark:text-slate-200 truncate block max-w-[280px]" title={getValue()}>
        {getValue()}
      </span>
    ),
    size: 300,
  },
  {
    accessorKey: 'status',
    header: 'Status',
    cell: ({ getValue }) => <StatusBadge status={getValue()} />,
    size: 120,
  },
  {
    accessorKey: 'assignee',
    header: 'Assignee',
    cell: ({ getValue }) => (
      <span className="text-sm text-slate-500 dark:text-slate-400">{getValue() || 'Unassigned'}</span>
    ),
    size: 110,
  },
  {
    id: 'alerts',
    header: 'Alerts',
    accessorFn: (row) => row.alert_ids?.length || 0,
    cell: ({ getValue }) => (
      <span className="text-sm font-mono text-slate-600 dark:text-slate-300">{getValue()}</span>
    ),
    size: 70,
  },
  {
    id: 'observables',
    header: 'IOCs',
    accessorFn: (row) => row.observables?.length || 0,
    cell: ({ getValue }) => (
      <span className="text-sm font-mono text-slate-600 dark:text-slate-300">{getValue()}</span>
    ),
    size: 60,
  },
  {
    id: 'tags',
    header: 'MITRE',
    accessorFn: (row) => row.tags || [],
    cell: ({ getValue }) => {
      const tags = getValue()
      if (!tags.length) return <span className="text-slate-400">—</span>
      return (
        <div className="flex gap-1 flex-wrap max-w-[160px]">
          {tags.slice(0, 2).map((tag) => (
            <span key={tag} className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300">
              {tag.replace('attack.', '')}
            </span>
          ))}
          {tags.length > 2 && (
            <span className="text-xs text-slate-400">+{tags.length - 2}</span>
          )}
        </div>
      )
    },
    size: 160,
    enableSorting: false,
  },
  {
    accessorKey: 'updated_at',
    header: 'Updated',
    cell: ({ getValue }) => (
      <span className="text-sm text-slate-600 dark:text-slate-300" title={new Date(getValue()).toLocaleString()}>
        {formatTimestamp(getValue())}
      </span>
    ),
    size: 100,
  },
]

function FilterDropdown({ label, value, options, onChange }) {
  return (
    <select
      value={value}
      onChange={(e) => onChange(e.target.value)}
      className="px-2.5 py-1.5 rounded-lg text-sm border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300"
    >
      <option value="">{label}</option>
      {options.map((opt) => (
        <option key={opt.value} value={opt.value}>{opt.label}</option>
      ))}
    </select>
  )
}

export default function Cases() {
  const [data, setData] = useState([])

  useEffect(() => {
    api.get('/cases')
      .then((resp) => setData(resp.cases || []))
      .catch(() => {})
  }, [])
  const [sorting, setSorting] = useState([{ id: 'updated_at', desc: true }])
  const [selectedCase, setSelectedCase] = useState(null)

  // Filters
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [assigneeFilter, setAssigneeFilter] = useState('')

  const filteredData = useMemo(() => {
    let result = data
    if (statusFilter) result = result.filter((c) => c.status === statusFilter)
    if (severityFilter) result = result.filter((c) => c.severity === severityFilter)
    if (assigneeFilter) {
      if (assigneeFilter === '__unassigned__') {
        result = result.filter((c) => !c.assignee)
      } else {
        result = result.filter((c) => c.assignee === assigneeFilter)
      }
    }
    return result
  }, [data, statusFilter, severityFilter, assigneeFilter])

  const assignees = useMemo(() => {
    const unique = [...new Set(data.map((c) => c.assignee).filter(Boolean))]
    return [
      { value: '__unassigned__', label: 'Unassigned' },
      ...unique.sort().map((a) => ({ value: a, label: a })),
    ]
  }, [data])

  const openCount = useMemo(() => data.filter((c) => c.status !== 'closed').length, [data])

  usePageTitle(`Cases (${openCount})`)

  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: (row) => row.id,
  })

  function handleStatusChange(id, newStatus, resolution) {
    const now = new Date().toISOString()

    // Persist to API.
    const updateBody = { status: newStatus }
    if (newStatus === 'closed' && resolution) {
      updateBody.resolution = resolution
    }
    api.put(`/cases/${id}`, updateBody).catch((err) => {
      console.error('Failed to update case:', err)
    })

    setData((prev) =>
      prev.map((c) => {
        if (c.id !== id) return c
        const updated = {
          ...c,
          status: newStatus,
          updated_at: now,
          timeline: [
            ...(c.timeline || []),
            { timestamp: now, author: 'you', action_type: 'status_change', content: { from: c.status, to: newStatus } },
          ],
        }
        if (newStatus === 'closed' && resolution) {
          updated.resolution = resolution
          updated.closed_at = now
          updated.timeline = [
            ...updated.timeline,
            { timestamp: now, author: 'you', action_type: 'resolution', content: resolution },
          ]
        }
        if (newStatus === 'in_progress' && (c.status === 'resolved' || c.status === 'closed')) {
          updated.resolution = null
          updated.closed_at = null
        }
        return updated
      })
    )
    setSelectedCase((prev) => {
      if (!prev || prev.id !== id) return prev
      const c = data.find((x) => x.id === id)
      if (!c) return prev
      const updated = {
        ...c,
        status: newStatus,
        updated_at: now,
        timeline: [
          ...c.timeline,
          { timestamp: now, author: 'you', action_type: 'status_change', content: { from: c.status, to: newStatus } },
        ],
      }
      if (newStatus === 'closed' && resolution) {
        updated.resolution = resolution
        updated.closed_at = now
        updated.timeline.push({ timestamp: now, author: 'you', action_type: 'resolution', content: resolution })
      }
      if (newStatus === 'in_progress' && (c.status === 'resolved' || c.status === 'closed')) {
        updated.resolution = null
        updated.closed_at = null
      }
      return updated
    })
  }

  function handleAddComment(id, text) {
    const now = new Date().toISOString()
    const entry = { timestamp: now, author: 'you', action_type: 'comment', content: { text } }

    // Persist to API.
    api.post(`/cases/${id}/comments`, { text }).catch((err) => {
      console.error('Failed to add comment:', err)
    })

    setData((prev) =>
      prev.map((c) =>
        c.id === id
          ? { ...c, updated_at: now, timeline: [...(c.timeline || []), entry] }
          : c
      )
    )
    setSelectedCase((prev) => {
      if (!prev || prev.id !== id) return prev
      return { ...prev, updated_at: now, timeline: [...(prev.timeline || []), entry] }
    })
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <FolderOpenIcon className="h-7 w-7 text-indigo-400" />
          <h1 className="text-2xl font-semibold">Cases</h1>
          <span className="text-sm text-slate-500 dark:text-slate-400">({filteredData.length})</span>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 mb-4 flex-wrap">
        <FunnelIcon className="h-4 w-4 text-slate-400" />
        <FilterDropdown
          label="All Statuses"
          value={statusFilter}
          onChange={setStatusFilter}
          options={[
            { value: 'new', label: 'New' },
            { value: 'in_progress', label: 'In Progress' },
            { value: 'resolved', label: 'Resolved' },
            { value: 'closed', label: 'Closed' },
          ]}
        />
        <FilterDropdown
          label="All Severities"
          value={severityFilter}
          onChange={setSeverityFilter}
          options={[
            { value: 'critical', label: 'Critical' },
            { value: 'high', label: 'High' },
            { value: 'medium', label: 'Medium' },
            { value: 'low', label: 'Low' },
          ]}
        />
        <FilterDropdown
          label="All Assignees"
          value={assigneeFilter}
          onChange={setAssigneeFilter}
          options={assignees}
        />
        {(statusFilter || severityFilter || assigneeFilter) && (
          <button
            onClick={() => { setStatusFilter(''); setSeverityFilter(''); setAssigneeFilter('') }}
            className="text-xs text-indigo-400 hover:text-indigo-300"
          >
            Clear filters
          </button>
        )}
      </div>

      {/* Table */}
      <div className="rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              {table.getHeaderGroups().map((headerGroup) => (
                <tr key={headerGroup.id} className="bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
                  {headerGroup.headers.map((header) => (
                    <th
                      key={header.id}
                      onClick={header.column.getCanSort() ? header.column.getToggleSortingHandler() : undefined}
                      className={`px-3 py-2.5 text-left text-xs font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider ${
                        header.column.getCanSort() ? 'cursor-pointer select-none hover:text-slate-700 dark:hover:text-slate-200' : ''
                      }`}
                      style={{ width: header.getSize() }}
                    >
                      <div className="flex items-center gap-1">
                        {flexRender(header.column.columnDef.header, header.getContext())}
                        {header.column.getIsSorted() === 'asc' && ' \u2191'}
                        {header.column.getIsSorted() === 'desc' && ' \u2193'}
                      </div>
                    </th>
                  ))}
                </tr>
              ))}
            </thead>
            <tbody className="divide-y divide-slate-100 dark:divide-slate-800">
              {table.getRowModel().rows.map((row) => (
                <tr
                  key={row.id}
                  onClick={() => setSelectedCase(row.original)}
                  className={`cursor-pointer transition-colors border-l-[3px] ${
                    getSeverityBorderClass(row.original.severity)
                  } ${
                    selectedCase?.id === row.id
                      ? 'bg-indigo-50 dark:bg-indigo-500/10'
                      : 'bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                  }`}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td key={cell.id} className="px-3 py-2.5 whitespace-nowrap">
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
              {table.getRowModel().rows.length === 0 && (
                <tr>
                  <td colSpan={columns.length} className="px-4 py-8 text-center text-slate-400">
                    No cases match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Flyout */}
      <CaseFlyout
        caseData={selectedCase}
        onClose={() => setSelectedCase(null)}
        onStatusChange={handleStatusChange}
        onAddComment={handleAddComment}
      />

      {/* Backdrop for flyout */}
      {selectedCase && (
        <div
          className="fixed inset-0 z-30 bg-black/20 lg:hidden"
          onClick={() => setSelectedCase(null)}
        />
      )}
    </div>
  )
}
