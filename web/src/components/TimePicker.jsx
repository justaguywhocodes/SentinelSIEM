import { useState, Fragment } from 'react'
import { Popover, PopoverButton, PopoverPanel, Transition } from '@headlessui/react'
import { ClockIcon, CalendarIcon } from '@heroicons/react/24/outline'
import { format, subMinutes, subHours, subDays } from 'date-fns'
import { DayPicker } from 'react-day-picker'
import 'react-day-picker/style.css'

const quickRanges = [
  { label: '15m', fn: () => subMinutes(new Date(), 15) },
  { label: '1h', fn: () => subHours(new Date(), 1) },
  { label: '4h', fn: () => subHours(new Date(), 4) },
  { label: '24h', fn: () => subDays(new Date(), 1) },
  { label: '7d', fn: () => subDays(new Date(), 7) },
  { label: '30d', fn: () => subDays(new Date(), 30) },
]

const refreshOptions = [
  { label: 'Off', value: 0 },
  { label: '10s', value: 10000 },
  { label: '30s', value: 30000 },
  { label: '1m', value: 60000 },
  { label: '5m', value: 300000 },
]

export default function TimePicker({ range, onRangeChange, refreshInterval, onRefreshChange }) {
  const [activeQuick, setActiveQuick] = useState('24h')
  const [showAbsolute, setShowAbsolute] = useState(false)
  const [absFrom, setAbsFrom] = useState(range.from)
  const [absTo, setAbsTo] = useState(range.to)

  function handleQuickSelect(item) {
    setActiveQuick(item.label)
    setShowAbsolute(false)
    onRangeChange({ from: item.fn(), to: new Date() })
  }

  function handleAbsoluteApply(close) {
    onRangeChange({ from: absFrom, to: absTo })
    setActiveQuick(null)
    close()
  }

  const displayLabel = activeQuick
    ? `Last ${activeQuick}`
    : `${format(range.from, 'MMM d HH:mm')} — ${format(range.to, 'MMM d HH:mm')}`

  return (
    <div className="flex items-center gap-2">
      {/* Quick range buttons */}
      <div className="flex items-center rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 overflow-hidden">
        {quickRanges.map((item) => (
          <button
            key={item.label}
            onClick={() => handleQuickSelect(item)}
            className={`px-2.5 py-1.5 text-xs font-medium transition-colors ${
              activeQuick === item.label
                ? 'bg-indigo-600 text-white'
                : 'text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'
            }`}
          >
            {item.label}
          </button>
        ))}
      </div>

      {/* Absolute date picker */}
      <Popover className="relative">
        <PopoverButton className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700">
          <CalendarIcon className="h-3.5 w-3.5" />
          <span>{displayLabel}</span>
        </PopoverButton>

        <Transition
          as={Fragment}
          enter="transition ease-out duration-100"
          enterFrom="opacity-0 translate-y-1"
          enterTo="opacity-100 translate-y-0"
          leave="transition ease-in duration-75"
          leaveFrom="opacity-100 translate-y-0"
          leaveTo="opacity-0 translate-y-1"
        >
          <PopoverPanel className="absolute right-0 z-50 mt-2 w-auto rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-xl p-4">
            {({ close }) => (
              <div className="space-y-3">
                <div className="flex gap-4">
                  <div>
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">From</label>
                    <DayPicker
                      mode="single"
                      selected={absFrom}
                      onSelect={(d) => d && setAbsFrom(d)}
                      className="text-sm"
                    />
                    <input
                      type="time"
                      value={format(absFrom, 'HH:mm')}
                      onChange={(e) => {
                        const [h, m] = e.target.value.split(':')
                        const d = new Date(absFrom)
                        d.setHours(+h, +m)
                        setAbsFrom(d)
                      }}
                      className="mt-1 w-full px-2 py-1 text-sm rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300"
                    />
                  </div>
                  <div>
                    <label className="text-xs font-medium text-slate-500 dark:text-slate-400 uppercase">To</label>
                    <DayPicker
                      mode="single"
                      selected={absTo}
                      onSelect={(d) => d && setAbsTo(d)}
                      className="text-sm"
                    />
                    <input
                      type="time"
                      value={format(absTo, 'HH:mm')}
                      onChange={(e) => {
                        const [h, m] = e.target.value.split(':')
                        const d = new Date(absTo)
                        d.setHours(+h, +m)
                        setAbsTo(d)
                      }}
                      className="mt-1 w-full px-2 py-1 text-sm rounded border border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-900 text-slate-700 dark:text-slate-300"
                    />
                  </div>
                </div>
                <div className="flex justify-end">
                  <button
                    onClick={() => handleAbsoluteApply(close)}
                    className="px-4 py-1.5 text-sm font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-500"
                  >
                    Apply
                  </button>
                </div>
              </div>
            )}
          </PopoverPanel>
        </Transition>
      </Popover>

      {/* Auto-refresh */}
      <Popover className="relative">
        <PopoverButton className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-xs text-slate-600 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700">
          <ClockIcon className="h-3.5 w-3.5" />
          <span>{refreshOptions.find(r => r.value === refreshInterval)?.label || 'Off'}</span>
        </PopoverButton>

        <Transition
          as={Fragment}
          enter="transition ease-out duration-100"
          enterFrom="opacity-0 translate-y-1"
          enterTo="opacity-100 translate-y-0"
          leave="transition ease-in duration-75"
          leaveFrom="opacity-100 translate-y-0"
          leaveTo="opacity-0 translate-y-1"
        >
          <PopoverPanel className="absolute right-0 z-50 mt-2 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-xl py-1">
            {refreshOptions.map((opt) => (
              <button
                key={opt.value}
                onClick={() => onRefreshChange(opt.value)}
                className={`block w-full px-4 py-1.5 text-left text-sm ${
                  refreshInterval === opt.value
                    ? 'text-indigo-600 dark:text-indigo-400 bg-indigo-50 dark:bg-indigo-500/10'
                    : 'text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </PopoverPanel>
        </Transition>
      </Popover>
    </div>
  )
}
