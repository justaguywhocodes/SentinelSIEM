import { useState } from 'react'
import { XMarkIcon, PlayIcon } from '@heroicons/react/24/outline'
import { parsersByType } from '../data/mockSources'

// Flatten all parsers into a sorted list
const allParsers = [...new Set(Object.values(parsersByType).flat())].sort()

// Mock ECS output for demo
function mockParseResult(parser, sampleLog) {
  if (!sampleLog.trim()) return { success: false, error: 'Empty sample log' }

  // Simulate a parse error for obviously bad input
  if (sampleLog.length < 10) {
    return { success: false, error: `Parser "${parser}" could not extract fields from input: too short` }
  }

  return {
    success: true,
    ecsOutput: {
      '@timestamp': new Date().toISOString(),
      'event.kind': 'event',
      'event.category': 'network',
      'event.type': 'info',
      'event.action': 'log',
      'source.ip': '192.168.1.' + Math.floor(Math.random() * 254 + 1),
      'source.port': Math.floor(Math.random() * 60000 + 1024),
      'destination.ip': '10.1.2.' + Math.floor(Math.random() * 254 + 1),
      'destination.port': [80, 443, 22, 3389][Math.floor(Math.random() * 4)],
      'host.name': 'parsed-host',
      'source_type': parser,
      'raw': sampleLog,
    },
  }
}

export default function ParserTester({ onClose }) {
  const [parser, setParser] = useState(allParsers[0] || '')
  const [sampleLog, setSampleLog] = useState('')
  const [result, setResult] = useState(null)
  const [testing, setTesting] = useState(false)

  const handleBackdropClick = () => {
    if (!sampleLog.trim()) onClose()
  }

  const handleTest = () => {
    setTesting(true)
    // Simulate API delay
    setTimeout(() => {
      setResult(mockParseResult(parser, sampleLog))
      setTesting(false)
    }, 300)
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/50" onClick={handleBackdropClick} />
      <div className="relative w-full max-w-xl mx-4 rounded-xl border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-900 shadow-2xl max-h-[85vh] flex flex-col">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-slate-200 dark:border-slate-700">
          <h2 className="text-lg font-semibold text-slate-800 dark:text-white">Parser Tester</h2>
          <button onClick={onClose} className="text-slate-400 hover:text-slate-600 dark:hover:text-slate-300">
            <XMarkIcon className="h-5 w-5" />
          </button>
        </div>

        {/* Content */}
        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          {/* Parser selector */}
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Parser</label>
            <select
              value={parser}
              onChange={e => { setParser(e.target.value); setResult(null) }}
              className="w-full px-3 py-2 text-sm rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500"
            >
              {allParsers.map(p => <option key={p} value={p}>{p}</option>)}
            </select>
          </div>

          {/* Sample log input */}
          <div>
            <label className="block text-xs font-medium text-slate-700 dark:text-slate-300 mb-1">Sample Log</label>
            <textarea
              value={sampleLog}
              onChange={e => { setSampleLog(e.target.value); setResult(null) }}
              rows={5}
              placeholder="Paste a sample log line here..."
              className="w-full px-3 py-2 text-sm font-mono rounded-lg border border-slate-200 dark:border-slate-700 bg-white dark:bg-slate-800 text-slate-700 dark:text-slate-300 focus:outline-none focus:ring-2 focus:ring-indigo-500 resize-none"
            />
          </div>

          {/* Test button */}
          <button
            onClick={handleTest}
            disabled={testing || !sampleLog.trim()}
            className="flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg bg-indigo-600 text-white hover:bg-indigo-700 disabled:opacity-50 disabled:cursor-not-allowed transition-colors"
          >
            <PlayIcon className="h-4 w-4" />
            {testing ? 'Testing...' : 'Test Parser'}
          </button>

          {/* Results */}
          {result && (
            <div className={`rounded-lg border p-4 ${
              result.success
                ? 'border-green-200 dark:border-green-500/30 bg-green-50 dark:bg-green-500/5'
                : 'border-red-200 dark:border-red-500/30 bg-red-50 dark:bg-red-500/5'
            }`}>
              <p className={`text-sm font-medium mb-2 ${
                result.success ? 'text-green-700 dark:text-green-400' : 'text-red-700 dark:text-red-400'
              }`}>
                {result.success ? 'Parse Successful' : 'Parse Failed'}
              </p>

              {result.success && result.ecsOutput && (
                <div className="space-y-1">
                  {Object.entries(result.ecsOutput).map(([key, val]) => (
                    <div key={key} className="flex gap-2 text-xs">
                      <span className="font-mono text-slate-500 dark:text-slate-400 min-w-[140px] shrink-0">{key}</span>
                      <span className="font-mono text-slate-700 dark:text-slate-300 break-all">
                        {typeof val === 'object' ? JSON.stringify(val) : String(val)}
                      </span>
                    </div>
                  ))}
                </div>
              )}

              {!result.success && result.error && (
                <p className="text-xs font-mono text-red-600 dark:text-red-400">{result.error}</p>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
