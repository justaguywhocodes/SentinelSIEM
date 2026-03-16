import { useCallback } from 'react'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Brush, CartesianGrid } from 'recharts'
import { format } from 'date-fns'
import { ChevronUpIcon, ChevronDownIcon } from '@heroicons/react/24/outline'
import { useThemeStore } from '../stores/themeStore'

function CustomTooltip({ active, payload, label }) {
  if (!active || !payload?.length) return null
  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 px-3 py-2 text-xs shadow-lg">
      <p className="text-slate-500 dark:text-slate-400">{format(new Date(label), 'MMM d, HH:mm:ss')}</p>
      <p className="font-medium text-slate-800 dark:text-slate-200">{payload[0].value.toLocaleString()} events</p>
    </div>
  )
}

export default function ResultsHistogram({ data, onBrushChange, height, onHeightChange, collapsed, onToggleCollapse }) {
  const isDark = useThemeStore((s) => s.isDark())

  const handleBrushChange = useCallback((brushArea) => {
    if (!brushArea || brushArea.startIndex === undefined) return
    const from = new Date(data[brushArea.startIndex].time)
    const to = new Date(data[brushArea.endIndex].time)
    onBrushChange?.({ from, to })
  }, [data, onBrushChange])

  if (!data || data.length === 0) return null

  const totalEvents = data.reduce((sum, b) => sum + b.count, 0)

  const handleDragStart = useCallback((e) => {
    e.preventDefault()
    const startY = e.clientY
    const startHeight = height

    function onMouseMove(moveEvent) {
      const delta = moveEvent.clientY - startY
      const newHeight = Math.max(60, Math.min(300, startHeight + delta))
      onHeightChange?.(newHeight)
    }

    function onMouseUp() {
      document.removeEventListener('mousemove', onMouseMove)
      document.removeEventListener('mouseup', onMouseUp)
      document.body.style.cursor = ''
      document.body.style.userSelect = ''
    }

    document.body.style.cursor = 'row-resize'
    document.body.style.userSelect = 'none'
    document.addEventListener('mousemove', onMouseMove)
    document.addEventListener('mouseup', onMouseUp)
  }, [height, onHeightChange])

  return (
    <div className="rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 overflow-hidden">
      {/* Header — always visible, acts as collapse toggle */}
      <button
        onClick={onToggleCollapse}
        className="flex items-center justify-between w-full px-4 py-2 text-left hover:bg-slate-50 dark:hover:bg-slate-700/30 transition-colors"
      >
        <h3 className="text-sm font-medium text-slate-700 dark:text-slate-300">
          {totalEvents.toLocaleString()} events over time
        </h3>
        <div className="flex items-center gap-2">
          {!collapsed && <span className="text-xs text-slate-400">Drag to zoom</span>}
          {collapsed
            ? <ChevronDownIcon className="h-4 w-4 text-slate-400" />
            : <ChevronUpIcon className="h-4 w-4 text-slate-400" />
          }
        </div>
      </button>

      {/* Chart — collapsible */}
      {!collapsed && (
        <>
          <div className="px-4 pb-1">
            <ResponsiveContainer width="100%" height={height}>
              <BarChart data={data} margin={{ top: 0, right: 0, bottom: 0, left: 0 }}>
                <CartesianGrid
                  strokeDasharray="3 3"
                  stroke={isDark ? '#334155' : '#e2e8f0'}
                  vertical={false}
                />
                <XAxis
                  dataKey="time"
                  tickFormatter={(v) => format(new Date(v), 'HH:mm')}
                  tick={{ fontSize: 10, fill: isDark ? '#94a3b8' : '#64748b' }}
                  axisLine={{ stroke: isDark ? '#334155' : '#e2e8f0' }}
                  tickLine={false}
                />
                <YAxis
                  tick={{ fontSize: 10, fill: isDark ? '#94a3b8' : '#64748b' }}
                  axisLine={false}
                  tickLine={false}
                  width={35}
                />
                <Tooltip content={<CustomTooltip />} />
                <Bar
                  dataKey="count"
                  fill={isDark ? '#818cf8' : '#6366f1'}
                  radius={[2, 2, 0, 0]}
                />
                <Brush
                  dataKey="time"
                  height={20}
                  stroke={isDark ? '#475569' : '#cbd5e1'}
                  fill={isDark ? '#1e293b' : '#f8fafc'}
                  tickFormatter={(v) => format(new Date(v), 'HH:mm')}
                  onChange={handleBrushChange}
                />
              </BarChart>
            </ResponsiveContainer>
          </div>

          {/* Drag handle */}
          <div
            onMouseDown={handleDragStart}
            className="h-1.5 cursor-row-resize group flex items-center justify-center hover:bg-slate-100 dark:hover:bg-slate-700/50 transition-colors"
          >
            <div className="w-8 h-0.5 rounded-full bg-slate-300 dark:bg-slate-600 group-hover:bg-indigo-400 transition-colors" />
          </div>
        </>
      )}
    </div>
  )
}
