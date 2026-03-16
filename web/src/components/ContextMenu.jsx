import { useEffect, useRef } from 'react'
import {
  MagnifyingGlassPlusIcon,
  MagnifyingGlassMinusIcon,
  ClipboardDocumentIcon,
  ArrowTopRightOnSquareIcon,
  GlobeAltIcon,
} from '@heroicons/react/24/outline'

function isIp(value) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(value)
}

function isHash(value) {
  return /^[a-f0-9]{32,64}$/i.test(value)
}

function isUsername(field) {
  return field === 'user.name' || field === 'user.domain'
}

function getActions(field, value) {
  const actions = []

  // Universal actions
  actions.push(
    { label: 'Filter in (+)', icon: MagnifyingGlassPlusIcon, action: 'filter_in' },
    { label: 'Filter out (−)', icon: MagnifyingGlassMinusIcon, action: 'filter_out' },
  )

  // IP-specific
  if (isIp(value)) {
    actions.push(
      { type: 'divider' },
      { label: 'Search all events', icon: MagnifyingGlassPlusIcon, action: 'search_all' },
      { label: 'VirusTotal lookup', icon: GlobeAltIcon, action: 'external', url: `https://www.virustotal.com/gui/ip-address/${value}` },
      { label: 'AbuseIPDB lookup', icon: GlobeAltIcon, action: 'external', url: `https://www.abuseipdb.com/check/${value}` },
      { label: 'Shodan lookup', icon: GlobeAltIcon, action: 'external', url: `https://www.shodan.io/host/${value}` },
    )
  }

  // Hash-specific
  if (isHash(value)) {
    actions.push(
      { type: 'divider' },
      { label: 'Search across endpoints', icon: MagnifyingGlassPlusIcon, action: 'search_all' },
      { label: 'VirusTotal lookup', icon: GlobeAltIcon, action: 'external', url: `https://www.virustotal.com/gui/search/${value}` },
    )
  }

  // Username-specific
  if (isUsername(field)) {
    actions.push(
      { type: 'divider' },
      { label: 'Search all activity', icon: MagnifyingGlassPlusIcon, action: 'search_user' },
      { label: 'View auth events', icon: ArrowTopRightOnSquareIcon, action: 'search_auth' },
    )
  }

  actions.push(
    { type: 'divider' },
    { label: 'Copy value', icon: ClipboardDocumentIcon, action: 'copy' },
  )

  return actions
}

export default function ContextMenu({ x, y, field, value, onClose, onAction }) {
  const ref = useRef(null)

  useEffect(() => {
    function handleClickOutside(e) {
      if (ref.current && !ref.current.contains(e.target)) {
        onClose()
      }
    }
    function handleEscape(e) {
      if (e.key === 'Escape') onClose()
    }
    document.addEventListener('mousedown', handleClickOutside)
    document.addEventListener('keydown', handleEscape)
    return () => {
      document.removeEventListener('mousedown', handleClickOutside)
      document.removeEventListener('keydown', handleEscape)
    }
  }, [onClose])

  // Adjust position to stay within viewport
  const style = {
    position: 'fixed',
    left: Math.min(x, window.innerWidth - 240),
    top: Math.min(y, window.innerHeight - 300),
    zIndex: 100,
  }

  const actions = getActions(field, value)

  return (
    <div ref={ref} style={style} className="w-56 rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 shadow-xl py-1">
      {/* Header */}
      <div className="px-3 py-2 border-b border-slate-100 dark:border-slate-700">
        <p className="text-xs text-slate-400 truncate">{field}</p>
        <p className="text-sm font-mono text-slate-800 dark:text-slate-200 truncate">{String(value)}</p>
      </div>

      {actions.map((item, i) => {
        if (item.type === 'divider') {
          return <div key={i} className="my-1 border-t border-slate-100 dark:border-slate-700" />
        }
        const Icon = item.icon
        return (
          <button
            key={i}
            onClick={() => {
              onAction(item)
              onClose()
            }}
            className="flex items-center gap-2 w-full px-3 py-1.5 text-sm text-slate-700 dark:text-slate-300 hover:bg-slate-50 dark:hover:bg-slate-700 text-left"
          >
            <Icon className="h-4 w-4 text-slate-400 shrink-0" />
            {item.label}
          </button>
        )
      })}
    </div>
  )
}
