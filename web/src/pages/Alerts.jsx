import { useState, useEffect, useMemo } from 'react'
import { useSearchParams } from 'react-router-dom'
import { BellAlertIcon, FunnelIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  getFilteredRowModel,
  flexRender,
} from '@tanstack/react-table'
import SeverityBadge, { getSeverityBorderClass } from '../components/SeverityBadge'
import StatusBadge from '../components/StatusBadge'
import AlertFlyout from '../components/AlertFlyout'
import { api } from '../lib/api'

function flattenObject(obj, skipKeys = [], prefix = '') {
  const entries = []
  for (const [k, v] of Object.entries(obj || {})) {
    if (skipKeys.includes(k)) continue
    const key = prefix ? `${prefix}.${k}` : k
    if (v && typeof v === 'object' && !Array.isArray(v)) {
      entries.push(...flattenObject(v, skipKeys, key))
    } else if (Array.isArray(v)) {
      // Flatten arrays of objects, join arrays of primitives.
      const hasObjects = v.some((item) => item && typeof item === 'object')
      if (hasObjects) {
        v.forEach((item, i) => {
          if (item && typeof item === 'object') {
            entries.push(...flattenObject(item, skipKeys, `${key}[${i}]`))
          } else if (item !== null && item !== undefined) {
            entries.push({ field: `${key}[${i}]`, value: String(item) })
          }
        })
      } else {
        const joined = v.filter((x) => x !== null && x !== undefined).join(', ')
        if (joined) entries.push({ field: key, value: joined })
      }
    } else if (v !== null && v !== undefined && v !== '') {
      entries.push({ field: key, value: String(v) })
    }
  }
  return entries
}

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
    id: 'select',
    header: ({ table }) => (
      <input
        type="checkbox"
        checked={table.getIsAllRowsSelected()}
        onChange={table.getToggleAllRowsSelectedHandler()}
        className="rounded border-slate-400 dark:border-slate-600"
      />
    ),
    cell: ({ row }) => (
      <input
        type="checkbox"
        checked={row.getIsSelected()}
        onChange={row.getToggleSelectedHandler()}
        className="rounded border-slate-400 dark:border-slate-600"
      />
    ),
    size: 40,
    enableSorting: false,
  },
  {
    accessorKey: 'severity',
    header: 'Severity',
    cell: ({ getValue }) => <SeverityBadge severity={getValue()} />,
    size: 100,
    sortingFn: (a, b) => (severityOrder[a.original.severity] ?? 99) - (severityOrder[b.original.severity] ?? 99),
  },
  {
    accessorKey: 'timestamp',
    header: 'Time',
    cell: ({ getValue }) => (
      <span className="text-sm text-slate-600 dark:text-slate-300" title={new Date(getValue()).toLocaleString()}>
        {formatTimestamp(getValue())}
      </span>
    ),
    size: 100,
  },
  {
    accessorKey: 'ruleName',
    header: 'Rule Name',
    cell: ({ getValue }) => (
      <span className="text-sm font-medium text-slate-800 dark:text-slate-200 truncate block max-w-[200px]" title={getValue()}>
        {getValue()}
      </span>
    ),
    size: 220,
  },
  {
    accessorKey: 'sourceIp',
    header: 'Source IP',
    cell: ({ getValue }) => (
      <span className="text-sm font-mono text-slate-600 dark:text-slate-300">{getValue() || '—'}</span>
    ),
    size: 130,
  },
  {
    accessorKey: 'destinationIp',
    header: 'Dest IP',
    cell: ({ getValue }) => (
      <span className="text-sm font-mono text-slate-600 dark:text-slate-300">{getValue() || '—'}</span>
    ),
    size: 130,
  },
  {
    accessorKey: 'user',
    header: 'User',
    cell: ({ getValue }) => (
      <span className="text-sm text-slate-600 dark:text-slate-300">{getValue() || '—'}</span>
    ),
    size: 100,
  },
  {
    accessorKey: 'mitreTactic',
    header: 'MITRE Tactic',
    cell: ({ getValue }) => (
      <span className="inline-flex items-center px-1.5 py-0.5 rounded text-xs font-medium bg-slate-100 text-slate-600 dark:bg-slate-700 dark:text-slate-300">
        {getValue()}
      </span>
    ),
    size: 140,
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

export default function Alerts() {
  usePageTitle('Alerts')
  const [searchParams] = useSearchParams()
  const [data, setData] = useState([])
  const [pendingAlertId] = useState(() => searchParams.get('id'))

  useEffect(() => {
    api.get('/alerts?size=1000')
      .then((resp) => {
        const mapped = (resp.alerts || []).map((a, i) => ({
          id: a._id || `alert-${i}`,
          _id: a._id,
          _index: a._index,
          severity: a.event?.severity || a.rule?.severity || 'low',
          timestamp: a['@timestamp'] || '',
          ruleName: a.rule?.name || '—',
          ruleDescription: a.rule?.description || '',
          sourceIp: a.source?.ip || '',
          destinationIp: a.destination?.ip || '',
          user: a.user?.name || '',
          mitreTactic: a.threat?.tactic?.name || '',
          mitreTechniqueId: a.threat?.technique?.id || '',
          status: a.event?.outcome || 'new',
          assignee: a.assignee || null,
          events: flattenObject(a, ['raw', '_raw']),
          relatedEvents: [],
          _raw: a,
        }))
        setData(mapped)
      })
      .catch(() => {})
  }, [])
  const [sorting, setSorting] = useState([{ id: 'timestamp', desc: true }])
  const [rowSelection, setRowSelection] = useState({})
  const [selectedAlert, setSelectedAlert] = useState(null)

  // Auto-select alert from URL ?id= parameter.
  useEffect(() => {
    if (!pendingAlertId || selectedAlert) return
    if (data.length > 0) {
      const match = data.find((a) => a.id === pendingAlertId || a._id === pendingAlertId)
      if (match) {
        setSelectedAlert(match)
        return
      }
    }
    // Not in current page — fetch directly.
    api.get(`/alerts/${pendingAlertId}`).then((a) => {
      if (a && a._id) {
        setSelectedAlert({
          id: a._id,
          _id: a._id,
          _index: a._index,
          severity: a.event?.severity || a.rule?.severity || 'low',
          timestamp: a['@timestamp'] || '',
          ruleName: a.rule?.name || '—',
          ruleDescription: a.rule?.description || '',
          sourceIp: a.source?.ip || '',
          destinationIp: a.destination?.ip || '',
          user: a.user?.name || '',
          mitreTactic: a.threat?.tactic?.name || '',
          mitreTechniqueId: a.threat?.technique?.id || '',
          status: a.event?.outcome || 'new',
          assignee: a.assignee || null,
          events: flattenObject(a, ['raw', '_raw']),
          relatedEvents: [],
          _raw: a,
        })
      }
    }).catch(() => {})
  }, [pendingAlertId, data, selectedAlert])

  // Filters
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [tacticFilter, setTacticFilter] = useState('')

  const filteredData = useMemo(() => {
    let result = data
    if (statusFilter) result = result.filter((a) => a.status === statusFilter)
    if (severityFilter) result = result.filter((a) => a.severity === severityFilter)
    if (tacticFilter) result = result.filter((a) => a.mitreTactic === tacticFilter)
    return result
  }, [data, statusFilter, severityFilter, tacticFilter])

  const tactics = useMemo(() => {
    const unique = [...new Set(data.map((a) => a.mitreTactic))]
    return unique.sort().map((t) => ({ value: t, label: t }))
  }, [data])

  const table = useReactTable({
    data: filteredData,
    columns,
    state: { sorting, rowSelection },
    onSortingChange: setSorting,
    onRowSelectionChange: setRowSelection,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: (row) => row.id,
  })

  const selectedCount = Object.keys(rowSelection).length

  function updateAlertStatus(id, newStatus) {
    const alert = data.find((a) => a.id === id)
    if (alert && alert._id && alert._index) {
      api.patch(`/alerts/${encodeURIComponent(alert._index)}/${encodeURIComponent(alert._id)}`, { status: newStatus }).catch(() => {})
    }
    setData((prev) => prev.map((a) => a.id === id ? { ...a, status: newStatus } : a))
    setSelectedAlert((prev) => prev && prev.id === id ? { ...prev, status: newStatus } : prev)
  }

  function handleAcknowledge(id) { updateAlertStatus(id, 'acknowledged') }

  function handleEscalate(id) {
    const alert = data.find((a) => a.id === id)
    if (!alert) return
    updateAlertStatus(id, 'escalated')
    // Create a case from this alert.
    const caseBody = {
      title: alert.ruleName || 'Escalated Alert',
      severity: typeof alert.severity === 'number'
        ? ({ 1: 'critical', 2: 'high', 3: 'medium', 4: 'low', 5: 'low' }[alert.severity] || 'medium')
        : (alert.severity || 'medium'),
      alert_ids: alert._id ? [alert._id] : [],
    }
    api.post('/cases', caseBody).catch((err) => {
      console.error('Failed to create case:', err)
    })
  }

  function handleCloseAlert(id) { updateAlertStatus(id, 'closed') }

  function handleBulkAcknowledge() {
    const ids = new Set(Object.keys(rowSelection))
    const targets = data.filter((a) => ids.has(a.id) && a._id && a._index)
    if (targets.length > 0) {
      api.post('/alerts/bulk-update', {
        status: 'acknowledged',
        alerts: targets.map((a) => ({ _id: a._id, _index: a._index })),
      }).catch(() => {})
    }
    setData((prev) => prev.map((a) => ids.has(a.id) && a.status === 'new' ? { ...a, status: 'acknowledged' } : a))
    setRowSelection({})
  }

  function handleBulkClose() {
    const ids = new Set(Object.keys(rowSelection))
    const targets = data.filter((a) => ids.has(a.id) && a._id && a._index)
    if (targets.length > 0) {
      api.post('/alerts/bulk-update', {
        status: 'closed',
        alerts: targets.map((a) => ({ _id: a._id, _index: a._index })),
      }).catch(() => {})
    }
    setData((prev) => prev.map((a) => ids.has(a.id) && a.status !== 'closed' ? { ...a, status: 'closed' } : a))
    setRowSelection({})
  }

  return (
    <div>
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <BellAlertIcon className="h-7 w-7 text-indigo-400" />
          <h1 className="text-2xl font-semibold">Alerts</h1>
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
            { value: 'acknowledged', label: 'Acknowledged' },
            { value: 'in_progress', label: 'In Progress' },
            { value: 'escalated', label: 'Escalated' },
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
          label="All Tactics"
          value={tacticFilter}
          onChange={setTacticFilter}
          options={tactics}
        />
        {(statusFilter || severityFilter || tacticFilter) && (
          <button
            onClick={() => { setStatusFilter(''); setSeverityFilter(''); setTacticFilter('') }}
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
                        {header.column.getIsSorted() === 'asc' && ' ↑'}
                        {header.column.getIsSorted() === 'desc' && ' ↓'}
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
                  onClick={() => setSelectedAlert(row.original)}
                  className={`cursor-pointer transition-colors border-l-[3px] ${
                    getSeverityBorderClass(row.original.severity)
                  } ${
                    selectedAlert?.id === row.id
                      ? 'bg-indigo-50 dark:bg-indigo-500/10'
                      : 'bg-white dark:bg-slate-900 hover:bg-slate-50 dark:hover:bg-slate-800/50'
                  }`}
                >
                  {row.getVisibleCells().map((cell) => (
                    <td
                      key={cell.id}
                      className="px-3 py-2.5 whitespace-nowrap"
                      onClick={cell.column.id === 'select' ? (e) => e.stopPropagation() : undefined}
                    >
                      {flexRender(cell.column.columnDef.cell, cell.getContext())}
                    </td>
                  ))}
                </tr>
              ))}
              {table.getRowModel().rows.length === 0 && (
                <tr>
                  <td colSpan={columns.length} className="px-4 py-8 text-center text-slate-400">
                    No alerts match the current filters.
                  </td>
                </tr>
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* Bulk actions bar */}
      {selectedCount > 0 && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-30 flex items-center gap-3 px-4 py-3 rounded-xl bg-slate-800 dark:bg-slate-700 text-white shadow-2xl border border-slate-600">
          <span className="text-sm font-medium">{selectedCount} alert{selectedCount > 1 ? 's' : ''} selected</span>
          <div className="h-4 w-px bg-slate-600" />
          <button onClick={handleBulkAcknowledge} className="text-sm px-3 py-1 rounded-md hover:bg-slate-700 dark:hover:bg-slate-600 transition-colors">
            Acknowledge
          </button>
          <button onClick={handleBulkClose} className="text-sm px-3 py-1 rounded-md hover:bg-slate-700 dark:hover:bg-slate-600 transition-colors">
            Close
          </button>
          <button onClick={() => setRowSelection({})} className="text-sm px-3 py-1 rounded-md text-slate-400 hover:text-white transition-colors">
            Cancel
          </button>
        </div>
      )}

      {/* Flyout */}
      <AlertFlyout
        alert={selectedAlert}
        onClose={() => setSelectedAlert(null)}
        onAcknowledge={handleAcknowledge}
        onEscalate={handleEscalate}
        onCloseAlert={handleCloseAlert}
      />

      {/* Backdrop for flyout */}
      {selectedAlert && (
        <div
          className="fixed inset-0 z-30 bg-black/20 lg:hidden"
          onClick={() => setSelectedAlert(null)}
        />
      )}
    </div>
  )
}
