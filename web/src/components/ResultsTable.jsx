import { useState, useMemo, useCallback, Fragment } from 'react'
import {
  useReactTable,
  getCoreRowModel,
  getSortedRowModel,
  flexRender,
} from '@tanstack/react-table'
import { Tab, TabGroup, TabList, TabPanel, TabPanels } from '@headlessui/react'
import { ChevronRightIcon, ChevronDownIcon } from '@heroicons/react/24/outline'

const displayColumns = [
  { field: '@timestamp', label: 'Timestamp', size: 110 },
  { field: 'event.action', label: 'Action', size: 130 },
  { field: 'source.ip', label: 'Src IP', size: 115 },
  { field: 'destination.ip', label: 'Dst IP', size: 115 },
  { field: 'user.name', label: 'User', size: 90 },
  { field: 'host.name', label: 'Host', size: 100 },
  { field: 'process.name', label: 'Process', size: 110 },
  { field: 'message', label: 'Message', size: 280 },
]

function ExpandedRow({ row }) {
  return (
    <TabGroup>
      <TabList className="flex border-b border-slate-200 dark:border-slate-700 px-3">
        {['Table', 'JSON', 'Raw'].map((tab) => (
          <Tab
            key={tab}
            className={({ selected }) =>
              `px-3 py-1.5 text-xs font-medium border-b-2 -mb-px transition-colors outline-none ${
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

      <TabPanels className="p-3">
        {/* Table view */}
        <TabPanel>
          <div className="rounded border border-slate-200 dark:border-slate-700 divide-y divide-slate-200 dark:divide-slate-700">
            {Object.entries(row).filter(([k]) => !k.startsWith('_')).map(([key, val]) => (
              <div key={key} className="flex text-xs">
                <span className="w-44 shrink-0 px-2 py-1.5 font-mono text-slate-500 dark:text-slate-400 bg-slate-50 dark:bg-slate-800/50 truncate" title={key}>
                  {key}
                </span>
                <span className="flex-1 px-2 py-1.5 font-mono text-slate-800 dark:text-slate-200 truncate" title={String(val)}>
                  {String(val ?? '')}
                </span>
              </div>
            ))}
          </div>
        </TabPanel>

        {/* JSON view */}
        <TabPanel>
          <pre className="text-xs font-mono text-slate-700 dark:text-slate-300 bg-slate-50 dark:bg-slate-900 rounded p-3 overflow-auto max-h-64 whitespace-pre-wrap">
            {JSON.stringify(row, null, 2)}
          </pre>
        </TabPanel>

        {/* Raw view */}
        <TabPanel>
          <pre className="text-xs font-mono text-slate-600 dark:text-slate-400 bg-slate-50 dark:bg-slate-900 rounded p-3 overflow-auto max-h-64 whitespace-pre-wrap break-all">
            {Object.entries(row).filter(([k]) => !k.startsWith('_')).map(([k, v]) => `${k}=${JSON.stringify(v)}`).join(' ')}
          </pre>
        </TabPanel>
      </TabPanels>
    </TabGroup>
  )
}

export default function ResultsTable({ data, pageSize, onPageSizeChange, onContextMenu }) {
  const [sorting, setSorting] = useState([])
  const [expandedRows, setExpandedRows] = useState({})

  const toggleExpanded = useCallback((id) => {
    setExpandedRows(prev => ({ ...prev, [id]: !prev[id] }))
  }, [])

  const columns = useMemo(() => [
    {
      id: 'expand',
      header: '',
      cell: ({ row }) => (
        <button
          onClick={(e) => { e.stopPropagation(); toggleExpanded(row.original._id) }}
          className="p-0.5 text-slate-400 hover:text-slate-600 dark:hover:text-slate-200"
        >
          {expandedRows[row.original._id]
            ? <ChevronDownIcon className="h-3.5 w-3.5" />
            : <ChevronRightIcon className="h-3.5 w-3.5" />
          }
        </button>
      ),
      size: 30,
      enableSorting: false,
    },
    ...displayColumns.map(({ field, label, size }) => ({
      id: field,
      header: label,
      accessorFn: (row) => row[field],
      cell: ({ getValue, row, column }) => {
        const val = getValue()
        return (
          <span
            className="text-xs font-mono text-slate-700 dark:text-slate-300 truncate block cursor-default"
            title={String(val ?? '')}
            onContextMenu={(e) => {
              e.preventDefault()
              onContextMenu?.({ x: e.clientX, y: e.clientY, field: column.id, value: val, row: row.original })
            }}
          >
            {field === '@timestamp'
              ? new Date(val).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit', fractionalSecondDigits: 3 })
              : String(val ?? '—')
            }
          </span>
        )
      },
      size,
    })),
  ], [expandedRows, toggleExpanded, onContextMenu])

  const table = useReactTable({
    data,
    columns,
    state: { sorting },
    onSortingChange: setSorting,
    getCoreRowModel: getCoreRowModel(),
    getSortedRowModel: getSortedRowModel(),
    getRowId: (row) => row._id,
  })

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden flex flex-col h-full">
      {/* Header bar */}
      <div className="flex items-center justify-between px-3 py-2 bg-slate-50 dark:bg-slate-800/50 border-b border-slate-200 dark:border-slate-700">
        <span className="text-xs text-slate-500 dark:text-slate-400">
          {data.length.toLocaleString()} events
        </span>
        <div className="flex items-center gap-2">
          <span className="text-xs text-slate-400">Rows per page:</span>
          <select
            value={pageSize}
            onChange={(e) => onPageSizeChange(Number(e.target.value))}
            className="text-xs px-1.5 py-0.5 rounded border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300"
          >
            {[25, 50, 100, 200].map(n => (
              <option key={n} value={n}>{n}</option>
            ))}
          </select>
        </div>
      </div>

      {/* Scrollable table */}
      <div className="overflow-auto flex-1 min-h-0">
        <table className="w-full">
          <thead className="sticky top-0 z-10">
            {table.getHeaderGroups().map(headerGroup => (
              <tr key={headerGroup.id} className="border-b border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800">
                {headerGroup.headers.map(header => (
                  <th
                    key={header.id}
                    onClick={header.column.getCanSort() ? header.column.getToggleSortingHandler() : undefined}
                    className={`px-2 py-1.5 text-left text-[10px] font-medium text-slate-500 dark:text-slate-400 uppercase tracking-wider whitespace-nowrap ${
                      header.column.getCanSort() ? 'cursor-pointer select-none hover:text-slate-700 dark:hover:text-slate-200' : ''
                    }`}
                    style={{ width: header.getSize() }}
                  >
                    <span className="flex items-center gap-0.5">
                      {flexRender(header.column.columnDef.header, header.getContext())}
                      {header.column.getIsSorted() === 'asc' && ' ↑'}
                      {header.column.getIsSorted() === 'desc' && ' ↓'}
                    </span>
                  </th>
                ))}
              </tr>
            ))}
          </thead>
          <tbody>
            {table.getRowModel().rows.map(row => {
              const isExpanded = expandedRows[row.id]
              return (
                <Fragment key={row.id}>
                  <tr
                    onClick={() => toggleExpanded(row.id)}
                    className="cursor-pointer border-b border-slate-100 dark:border-slate-800 hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
                  >
                    {row.getVisibleCells().map(cell => (
                      <td
                        key={cell.id}
                        className="px-2 py-1 whitespace-nowrap"
                        style={{ width: cell.column.getSize() }}
                      >
                        {flexRender(cell.column.columnDef.cell, cell.getContext())}
                      </td>
                    ))}
                  </tr>
                  {isExpanded && (
                    <tr>
                      <td colSpan={columns.length} className="p-0 bg-slate-50/50 dark:bg-slate-800/30 border-b border-slate-200 dark:border-slate-700">
                        <ExpandedRow row={row.original} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>

      {data.length === 0 && (
        <div className="px-4 py-12 text-center text-sm text-slate-400">
          No results. Run a search to see events.
        </div>
      )}
    </div>
  )
}
