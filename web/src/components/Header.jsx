import { Bars3Icon, BellIcon, SparklesIcon } from '@heroicons/react/24/outline'
import { UserCircleIcon } from '@heroicons/react/24/solid'
import ThemeToggle from './ThemeToggle'

export default function Header({ onMobileMenuToggle }) {
  return (
    <header className="sticky top-0 z-30 h-16 flex items-center gap-4 px-4 border-b border-slate-200 bg-white/80 dark:border-slate-700 dark:bg-slate-900/80 backdrop-blur-md">
      {/* Mobile menu button */}
      <button
        onClick={onMobileMenuToggle}
        className="lg:hidden text-slate-400 hover:text-white"
      >
        <Bars3Icon className="h-6 w-6" />
      </button>

      {/* Time range placeholder (left) */}
      <div className="hidden sm:flex items-center gap-2 text-sm text-slate-400">
        <span className="px-3 py-1.5 rounded-md bg-slate-100 border border-slate-200 text-slate-600 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300">
          Last 24 hours
        </span>
      </div>

      {/* Search placeholder (center) */}
      <div className="flex-1 max-w-lg mx-auto">
        <div className="relative">
          <input
            type="text"
            placeholder="Search..."
            disabled
            className="w-full px-4 py-2 rounded-lg bg-slate-100 border border-slate-200 text-slate-600 placeholder-slate-400 dark:bg-slate-800 dark:border-slate-700 dark:text-slate-300 dark:placeholder-slate-500 text-sm cursor-not-allowed opacity-60"
          />
        </div>
      </div>

      {/* Right section */}
      <div className="flex items-center gap-3">
        <ThemeToggle />

        {/* AI assistant placeholder */}
        <button className="text-slate-400 hover:text-indigo-400 transition-colors" title="AI Assistant">
          <SparklesIcon className="h-5 w-5" />
        </button>

        {/* Notifications placeholder */}
        <button className="text-slate-400 hover:text-white transition-colors" title="Notifications">
          <BellIcon className="h-5 w-5" />
        </button>

        {/* User avatar placeholder */}
        <button className="text-slate-400 hover:text-white transition-colors" title="Profile">
          <UserCircleIcon className="h-7 w-7" />
        </button>
      </div>
    </header>
  )
}
