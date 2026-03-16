import { Fragment } from 'react'
import { useNavigate } from 'react-router-dom'
import { Menu, MenuButton, MenuItems, MenuItem, Transition } from '@headlessui/react'
import { UserCircleIcon, Cog6ToothIcon, ArrowRightStartOnRectangleIcon } from '@heroicons/react/24/outline'
import { useAuthStore } from '../stores/authStore'

const roleBadgeColors = {
  admin: 'bg-red-500/20 text-red-400',
  detection_engineer: 'bg-purple-500/20 text-purple-400',
  soc_lead: 'bg-blue-500/20 text-blue-400',
  analyst: 'bg-green-500/20 text-green-400',
  read_only: 'bg-slate-500/20 text-slate-400',
}

const roleLabels = {
  admin: 'Admin',
  detection_engineer: 'Detection Engineer',
  soc_lead: 'SOC Lead',
  analyst: 'Analyst',
  read_only: 'Read Only',
}

export default function UserMenu() {
  const navigate = useNavigate()
  const user = useAuthStore((s) => s.user)
  const logout = useAuthStore((s) => s.logout)

  const handleLogout = async () => {
    await logout()
    navigate('/login', { replace: true })
  }

  const initials = user?.display_name
    ? user.display_name
        .split(' ')
        .map((w) => w[0])
        .join('')
        .toUpperCase()
        .slice(0, 2)
    : '?'

  return (
    <Menu as="div" className="relative">
      <MenuButton className="flex items-center gap-2 text-slate-400 hover:text-white transition-colors">
        <div className="h-7 w-7 rounded-full bg-indigo-600 flex items-center justify-center">
          <span className="text-white text-xs font-semibold">{initials}</span>
        </div>
      </MenuButton>

      <Transition
        as={Fragment}
        enter="transition ease-out duration-100"
        enterFrom="transform opacity-0 scale-95"
        enterTo="transform opacity-100 scale-100"
        leave="transition ease-in duration-75"
        leaveFrom="transform opacity-100 scale-100"
        leaveTo="transform opacity-0 scale-95"
      >
        <MenuItems className="absolute right-0 mt-2 w-56 rounded-lg bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-lg py-1 z-50 focus:outline-none">
          {/* User info header */}
          <div className="px-4 py-3 border-b border-slate-200 dark:border-slate-700">
            <p className="text-sm font-medium text-slate-900 dark:text-white truncate">
              {user?.display_name || 'User'}
            </p>
            <p className="text-xs text-slate-500 dark:text-slate-400 truncate">@{user?.username}</p>
            {user?.role && (
              <span
                className={`inline-block mt-1.5 px-2 py-0.5 rounded text-xs font-medium ${
                  roleBadgeColors[user.role] || 'bg-slate-500/20 text-slate-400'
                }`}
              >
                {roleLabels[user.role] || user.role}
              </span>
            )}
          </div>

          <MenuItem>
            {({ active }) => (
              <button
                onClick={() => navigate('/settings')}
                className={`w-full flex items-center gap-2 px-4 py-2 text-sm ${
                  active
                    ? 'bg-slate-100 dark:bg-slate-700 text-slate-900 dark:text-white'
                    : 'text-slate-700 dark:text-slate-300'
                }`}
              >
                <Cog6ToothIcon className="h-4 w-4" />
                Settings
              </button>
            )}
          </MenuItem>

          <div className="border-t border-slate-200 dark:border-slate-700" />

          <MenuItem>
            {({ active }) => (
              <button
                onClick={handleLogout}
                className={`w-full flex items-center gap-2 px-4 py-2 text-sm ${
                  active
                    ? 'bg-slate-100 dark:bg-slate-700 text-red-500'
                    : 'text-red-500 dark:text-red-400'
                }`}
              >
                <ArrowRightStartOnRectangleIcon className="h-4 w-4" />
                Sign out
              </button>
            )}
          </MenuItem>
        </MenuItems>
      </Transition>
    </Menu>
  )
}
