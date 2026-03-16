import { SunIcon, MoonIcon, ComputerDesktopIcon } from '@heroicons/react/24/outline'
import { useThemeStore } from '../stores/themeStore'

const modes = [
  { value: 'dark', icon: MoonIcon, label: 'Dark' },
  { value: 'light', icon: SunIcon, label: 'Light' },
  { value: 'system', icon: ComputerDesktopIcon, label: 'System' },
]

export default function ThemeToggle() {
  const { mode, setMode } = useThemeStore()

  return (
    <div className="flex items-center bg-slate-200 dark:bg-slate-700/50 rounded-lg p-0.5">
      {modes.map((m) => (
        <button
          key={m.value}
          onClick={() => setMode(m.value)}
          title={m.label}
          className={`p-1.5 rounded-md transition-colors ${
            mode === m.value
              ? 'bg-white text-slate-900 dark:bg-slate-600 dark:text-white shadow-sm'
              : 'text-slate-500 hover:text-slate-700 dark:text-slate-400 dark:hover:text-slate-200'
          }`}
        >
          <m.icon className="h-4 w-4" />
        </button>
      ))}
    </div>
  )
}
