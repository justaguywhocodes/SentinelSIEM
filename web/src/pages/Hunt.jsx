import { useState, useMemo, useCallback, useEffect } from 'react'
import { useSearchParams } from 'react-router-dom'
import { MagnifyingGlassIcon } from '@heroicons/react/24/outline'
import usePageTitle from '../hooks/usePageTitle'
import { subDays } from 'date-fns'
import QueryBar from '../components/QueryBar'
import TimePicker from '../components/TimePicker'
import ResultsHistogram from '../components/ResultsHistogram'
import ResultsTable from '../components/ResultsTable'
import FieldStatsSidebar from '../components/FieldStatsSidebar'
import ContextMenu from '../components/ContextMenu'
import { generateHistogramBuckets, computeFieldStats } from '../data/mockHuntResults'
import { api } from '../lib/api'

export default function Hunt() {
  usePageTitle('Hunt')
  const [searchParams, setSearchParams] = useSearchParams()
  const [query, setQuery] = useState(searchParams.get('q') || '')
  const [timeRange, setTimeRange] = useState({ from: subDays(new Date(), 1), to: new Date() })
  const [refreshInterval, setRefreshInterval] = useState(0)
  const [isSearching, setIsSearching] = useState(false)
  const [results, setResults] = useState([])
  const [pageSize, setPageSize] = useState(100)
  const [contextMenu, setContextMenu] = useState(null)
  const [showFieldStats, setShowFieldStats] = useState(true)
  const [histogramCollapsed, setHistogramCollapsed] = useState(false)
  const [histogramHeight, setHistogramHeight] = useState(120)

  const histogram = useMemo(() => generateHistogramBuckets(results), [results])
  const fieldStats = useMemo(() => computeFieldStats(results), [results])

  const handleSearch = useCallback(() => {
    if (!query.trim()) return
    setIsSearching(true)
    api.post('/query', { query: query.trim(), size: pageSize })
      .then((resp) => {
        const hits = (resp.hits || []).map((hit, i) => {
          const doc = typeof hit === 'string' ? JSON.parse(hit) : hit
          return { _id: doc._id || `evt-${i}`, _index: doc._index || '', ...doc }
        })
        setResults(hits)
      })
      .catch(() => setResults([]))
      .finally(() => setIsSearching(false))
  }, [query, pageSize])

  // Auto-search when arriving with ?q= parameter.
  useEffect(() => {
    const q = searchParams.get('q')
    if (q && results.length === 0) {
      handleSearch()
      setSearchParams({}, { replace: true })
    }
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  const handleBrushZoom = useCallback((brushRange) => {
    setTimeRange(brushRange)
  }, [])

  const handleFieldFilter = useCallback((field, value) => {
    setQuery(prev => {
      const filter = `${field}: "${value}"`
      return prev ? `${prev} AND ${filter}` : filter
    })
  }, [])

  const handleContextMenuAction = useCallback((item) => {
    if (item.action === 'filter_in') {
      handleFieldFilter(contextMenu.field, contextMenu.value)
    } else if (item.action === 'filter_out') {
      setQuery(prev => {
        const filter = `NOT ${contextMenu.field}: "${contextMenu.value}"`
        return prev ? `${prev} AND ${filter}` : filter
      })
    } else if (item.action === 'copy') {
      navigator.clipboard?.writeText(String(contextMenu.value))
    } else if (item.action === 'external' && item.url) {
      window.open(item.url, '_blank', 'noopener')
    } else if (item.action === 'search_all' || item.action === 'search_user' || item.action === 'search_auth') {
      setQuery(`${contextMenu.field}: "${contextMenu.value}"`)
    }
  }, [contextMenu, handleFieldFilter])

  return (
    <div className="flex flex-col h-full min-h-0">
      {/* Header */}
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-3">
          <MagnifyingGlassIcon className="h-7 w-7 text-indigo-400" />
          <h1 className="text-2xl font-semibold">Hunt</h1>
          {results.length > 0 && (
            <span className="text-sm text-slate-500 dark:text-slate-400">
              ({results.length.toLocaleString()} events)
            </span>
          )}
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => setShowFieldStats(prev => !prev)}
            className={`px-2.5 py-1.5 text-xs font-medium rounded-lg border transition-colors ${
              showFieldStats
                ? 'border-indigo-500 text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-500/10'
                : 'border-slate-200 dark:border-slate-700 text-slate-600 dark:text-slate-400 hover:bg-slate-50 dark:hover:bg-slate-800'
            }`}
          >
            Fields
          </button>
        </div>
      </div>

      {/* Query bar + Time picker */}
      <div className="space-y-2 mb-4">
        <QueryBar
          value={query}
          onChange={setQuery}
          onSearch={handleSearch}
          isSearching={isSearching}
        />
        <TimePicker
          range={timeRange}
          onRangeChange={setTimeRange}
          refreshInterval={refreshInterval}
          onRefreshChange={setRefreshInterval}
        />
      </div>

      {/* Results area */}
      {results.length > 0 && (
        <div className="mb-4">
          <ResultsHistogram
            data={histogram}
            onBrushChange={handleBrushZoom}
            height={histogramHeight}
            onHeightChange={setHistogramHeight}
            collapsed={histogramCollapsed}
            onToggleCollapse={() => setHistogramCollapsed(prev => !prev)}
          />
        </div>
      )}

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Field stats sidebar */}
        {showFieldStats && (
          <div className="w-48 xl:w-56 shrink-0 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 overflow-hidden">
            <FieldStatsSidebar stats={fieldStats} onFilter={handleFieldFilter} />
          </div>
        )}

        {/* Results table */}
        <div className="flex-1 min-w-0 min-h-0">
          <ResultsTable
            data={results}
            pageSize={pageSize}
            onPageSizeChange={setPageSize}
            onContextMenu={setContextMenu}
          />
        </div>
      </div>

      {/* Context menu */}
      {contextMenu && (
        <ContextMenu
          x={contextMenu.x}
          y={contextMenu.y}
          field={contextMenu.field}
          value={contextMenu.value}
          onClose={() => setContextMenu(null)}
          onAction={handleContextMenuAction}
        />
      )}
    </div>
  )
}
