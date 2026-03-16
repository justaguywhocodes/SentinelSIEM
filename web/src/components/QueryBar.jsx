import { useCallback, useMemo } from 'react'
import CodeMirror from '@uiw/react-codemirror'
import { autocompletion } from '@codemirror/autocomplete'
import { oneDark } from '@codemirror/theme-one-dark'
import { EditorView } from '@codemirror/view'
import { PlayIcon } from '@heroicons/react/24/solid'
import { fieldNames } from '../data/mockHuntResults'
import { useThemeStore } from '../stores/themeStore'

const lightTheme = EditorView.theme({
  '&': { backgroundColor: '#ffffff', color: '#0f172a' },
  '.cm-gutters': { backgroundColor: '#f8fafc', borderRight: '1px solid #e2e8f0' },
  '.cm-activeLineGutter': { backgroundColor: '#f1f5f9' },
  '.cm-activeLine': { backgroundColor: '#f1f5f9' },
  '&.cm-focused .cm-cursor': { borderLeftColor: '#6366f1' },
  '&.cm-focused .cm-selectionBackground, .cm-selectionBackground': { backgroundColor: '#c7d2fe' },
})

function fieldCompletion(context) {
  const word = context.matchBefore(/[\w.]*/)
  if (!word || (word.from === word.to && !context.explicit)) return null

  const options = fieldNames.map(name => ({
    label: name,
    type: 'variable',
    boost: name.startsWith(word.text) ? 1 : 0,
  }))

  // Add operators
  const operators = ['AND', 'OR', 'NOT', 'EXISTS', ':', '>=', '<=', '>', '<', '!=']
  operators.forEach(op => {
    options.push({ label: op, type: 'keyword' })
  })

  return { from: word.from, options, validFor: /[\w.]*/ }
}

export default function QueryBar({ value, onChange, onSearch, isSearching }) {
  const isDark = useThemeStore((s) => s.isDark())

  const extensions = useMemo(() => [
    autocompletion({ override: [fieldCompletion] }),
    EditorView.lineWrapping,
    EditorView.domEventHandlers({
      keydown(event, view) {
        if ((event.metaKey || event.ctrlKey) && event.key === 'Enter') {
          event.preventDefault()
          onSearch?.()
          return true
        }
      },
    }),
  ], [onSearch])

  const handleChange = useCallback((val) => {
    onChange?.(val)
  }, [onChange])

  return (
    <div className="flex gap-2">
      <div className="flex-1 rounded-lg border border-slate-200 dark:border-slate-700 overflow-hidden">
        <CodeMirror
          value={value}
          onChange={handleChange}
          height="36px"
          theme={isDark ? oneDark : lightTheme}
          extensions={extensions}
          placeholder='Search events... e.g. event.action: "logon_failure" AND user.name: "admin"'
          basicSetup={{
            lineNumbers: false,
            foldGutter: false,
            highlightActiveLine: false,
          }}
        />
      </div>
      <button
        onClick={onSearch}
        disabled={isSearching}
        className="flex items-center gap-2 px-4 py-1.5 rounded-lg bg-indigo-600 text-white font-medium text-sm hover:bg-indigo-500 disabled:opacity-50 disabled:cursor-not-allowed transition-colors shrink-0"
      >
        <PlayIcon className="h-4 w-4" />
        {isSearching ? 'Searching...' : 'Search'}
      </button>
    </div>
  )
}
