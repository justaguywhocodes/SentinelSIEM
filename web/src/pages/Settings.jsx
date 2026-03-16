import { useState } from 'react'
import { Cog6ToothIcon, CheckCircleIcon, ExclamationTriangleIcon, ShieldCheckIcon } from '@heroicons/react/24/outline'
import { useAuthStore } from '../stores/authStore'
import { api } from '../lib/api'
import MFAEnrollModal from '../components/MFAEnrollModal'
import usePageTitle from '../hooks/usePageTitle'

const roleBadgeColors = {
  admin: 'bg-red-500/20 text-red-400 border-red-500/30',
  detection_engineer: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  soc_lead: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  analyst: 'bg-green-500/20 text-green-400 border-green-500/30',
  read_only: 'bg-slate-500/20 text-slate-400 border-slate-500/30',
}

const roleLabels = {
  admin: 'Admin',
  detection_engineer: 'Detection Engineer',
  soc_lead: 'SOC Lead',
  analyst: 'Analyst',
  read_only: 'Read Only',
}

function FeedbackMessage({ type, message }) {
  if (!message) return null
  const isError = type === 'error'
  return (
    <div className={`flex items-center gap-2 p-3 rounded-lg text-sm ${
      isError
        ? 'bg-red-500/10 border border-red-500/30 text-red-400'
        : 'bg-green-500/10 border border-green-500/30 text-green-400'
    }`}>
      {isError ? <ExclamationTriangleIcon className="h-5 w-5 shrink-0" /> : <CheckCircleIcon className="h-5 w-5 shrink-0" />}
      <span>{message}</span>
    </div>
  )
}

function ProfileSection() {
  const user = useAuthStore((s) => s.user)
  const fetchProfile = useAuthStore((s) => s.fetchProfile)
  const [displayName, setDisplayName] = useState(user?.display_name || '')
  const [email, setEmail] = useState(user?.email || '')
  const [loading, setLoading] = useState(false)
  const [feedback, setFeedback] = useState({ type: '', message: '' })

  const handleSave = async (e) => {
    e.preventDefault()
    if (!displayName.trim()) {
      setFeedback({ type: 'error', message: 'Display name is required' })
      return
    }

    setLoading(true)
    setFeedback({ type: '', message: '' })
    try {
      await api.put('/auth/profile', { display_name: displayName.trim(), email: email.trim() })
      await fetchProfile()
      setFeedback({ type: 'success', message: 'Profile updated' })
    } catch (err) {
      setFeedback({ type: 'error', message: err.message || 'Update failed' })
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSave} className="space-y-4">
      <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Profile</h3>
      <FeedbackMessage {...feedback} />

      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div>
          <label className="block text-sm font-medium text-slate-600 dark:text-slate-400 mb-1">Username</label>
          <input
            type="text"
            value={user?.username || ''}
            disabled
            className="w-full px-3 py-2 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-500 dark:text-slate-500 text-sm cursor-not-allowed"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-600 dark:text-slate-400 mb-1">Role</label>
          <div className="px-3 py-2">
            <span className={`inline-block px-2.5 py-1 rounded text-xs font-medium border ${
              roleBadgeColors[user?.role] || 'bg-slate-500/20 text-slate-400 border-slate-500/30'
            }`}>
              {roleLabels[user?.role] || user?.role}
            </span>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-600 dark:text-slate-400 mb-1">Display Name</label>
          <input
            type="text"
            value={displayName}
            onChange={(e) => setDisplayName(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>

        <div>
          <label className="block text-sm font-medium text-slate-600 dark:text-slate-400 mb-1">Email</label>
          <input
            type="email"
            value={email}
            onChange={(e) => setEmail(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="user@example.com"
          />
        </div>
      </div>

      <div>
        <button
          type="submit"
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
        >
          {loading ? 'Saving...' : 'Save Changes'}
        </button>
      </div>
    </form>
  )
}

function PasswordSection() {
  const [currentPassword, setCurrentPassword] = useState('')
  const [newPassword, setNewPassword] = useState('')
  const [confirmPassword, setConfirmPassword] = useState('')
  const [loading, setLoading] = useState(false)
  const [feedback, setFeedback] = useState({ type: '', message: '' })

  const handleSubmit = async (e) => {
    e.preventDefault()
    if (!currentPassword || !newPassword) {
      setFeedback({ type: 'error', message: 'All password fields are required' })
      return
    }
    if (newPassword.length < 8) {
      setFeedback({ type: 'error', message: 'New password must be at least 8 characters' })
      return
    }
    if (newPassword !== confirmPassword) {
      setFeedback({ type: 'error', message: 'New passwords do not match' })
      return
    }

    setLoading(true)
    setFeedback({ type: '', message: '' })
    try {
      await api.post('/auth/password', { current_password: currentPassword, new_password: newPassword })
      setCurrentPassword('')
      setNewPassword('')
      setConfirmPassword('')
      setFeedback({ type: 'success', message: 'Password changed successfully' })
    } catch (err) {
      setFeedback({ type: 'error', message: err.status === 401 ? 'Current password is incorrect' : (err.message || 'Password change failed') })
    } finally {
      setLoading(false)
    }
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-4">
      <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Change Password</h3>
      <FeedbackMessage {...feedback} />

      <div className="max-w-sm space-y-3">
        <div>
          <label className="block text-sm font-medium text-slate-600 dark:text-slate-400 mb-1">Current Password</label>
          <input
            type="password"
            autoComplete="current-password"
            value={currentPassword}
            onChange={(e) => setCurrentPassword(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-600 dark:text-slate-400 mb-1">New Password</label>
          <input
            type="password"
            autoComplete="new-password"
            value={newPassword}
            onChange={(e) => setNewPassword(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
            placeholder="Minimum 8 characters"
          />
        </div>
        <div>
          <label className="block text-sm font-medium text-slate-600 dark:text-slate-400 mb-1">Confirm New Password</label>
          <input
            type="password"
            autoComplete="new-password"
            value={confirmPassword}
            onChange={(e) => setConfirmPassword(e.target.value)}
            className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-indigo-500 focus:border-transparent"
          />
        </div>
      </div>

      <div>
        <button
          type="submit"
          disabled={loading}
          className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition-colors disabled:opacity-50"
        >
          {loading ? 'Changing...' : 'Change Password'}
        </button>
      </div>
    </form>
  )
}

function MFASection() {
  const user = useAuthStore((s) => s.user)
  const fetchProfile = useAuthStore((s) => s.fetchProfile)
  const [enrollOpen, setEnrollOpen] = useState(false)
  const [disablePassword, setDisablePassword] = useState('')
  const [showDisable, setShowDisable] = useState(false)
  const [loading, setLoading] = useState(false)
  const [feedback, setFeedback] = useState({ type: '', message: '' })

  const handleDisable = async (e) => {
    e.preventDefault()
    if (!disablePassword) {
      setFeedback({ type: 'error', message: 'Password is required to disable MFA' })
      return
    }

    setLoading(true)
    setFeedback({ type: '', message: '' })
    try {
      await api.del('/auth/me/mfa', { password: disablePassword })
      await fetchProfile()
      setShowDisable(false)
      setDisablePassword('')
      setFeedback({ type: 'success', message: 'Two-factor authentication disabled' })
    } catch (err) {
      setFeedback({ type: 'error', message: err.status === 401 ? 'Invalid password' : (err.message || 'Failed to disable MFA') })
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center gap-3">
        <ShieldCheckIcon className="h-5 w-5 text-indigo-400" />
        <h3 className="text-lg font-semibold text-slate-900 dark:text-white">Two-Factor Authentication</h3>
      </div>

      <FeedbackMessage {...feedback} />

      {user?.mfa_enabled ? (
        <div className="space-y-3">
          <div className="flex items-center gap-2">
            <span className="inline-block h-2 w-2 rounded-full bg-green-400" />
            <span className="text-sm text-green-400 font-medium">MFA is enabled</span>
          </div>

          {!showDisable ? (
            <button
              onClick={() => { setShowDisable(true); setFeedback({ type: '', message: '' }) }}
              className="px-4 py-2 rounded-lg border border-red-500/30 text-red-400 text-sm hover:bg-red-500/10 transition-colors"
            >
              Disable MFA
            </button>
          ) : (
            <form onSubmit={handleDisable} className="max-w-sm space-y-3">
              <div>
                <label className="block text-sm font-medium text-slate-600 dark:text-slate-400 mb-1">
                  Confirm your password to disable MFA
                </label>
                <input
                  type="password"
                  autoFocus
                  value={disablePassword}
                  onChange={(e) => setDisablePassword(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-white dark:bg-slate-900 border border-slate-200 dark:border-slate-700 text-slate-900 dark:text-white text-sm focus:outline-none focus:ring-2 focus:ring-red-500 focus:border-transparent"
                />
              </div>
              <div className="flex gap-2">
                <button
                  type="button"
                  onClick={() => { setShowDisable(false); setDisablePassword('') }}
                  className="px-4 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 text-sm hover:bg-slate-50 dark:hover:bg-slate-700"
                >
                  Cancel
                </button>
                <button
                  type="submit"
                  disabled={loading}
                  className="px-4 py-2 rounded-lg bg-red-600 hover:bg-red-500 text-white text-sm font-medium disabled:opacity-50"
                >
                  {loading ? 'Disabling...' : 'Disable MFA'}
                </button>
              </div>
            </form>
          )}
        </div>
      ) : (
        <div className="space-y-3">
          <p className="text-sm text-slate-500 dark:text-slate-400">
            Add an extra layer of security to your account with a time-based one-time password (TOTP).
          </p>
          <button
            onClick={() => { setEnrollOpen(true); setFeedback({ type: '', message: '' }) }}
            className="px-4 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium transition-colors"
          >
            Enable Two-Factor Auth
          </button>
        </div>
      )}

      <MFAEnrollModal open={enrollOpen} onClose={() => setEnrollOpen(false)} />
    </div>
  )
}

export default function Settings() {
  usePageTitle('Settings')

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <Cog6ToothIcon className="h-7 w-7 text-indigo-400" />
        <h1 className="text-2xl font-semibold">Settings</h1>
      </div>

      <div className="space-y-6">
        {/* Profile */}
        <div className="rounded-lg bg-white border border-slate-200 dark:bg-slate-800 dark:border-slate-700 p-6">
          <ProfileSection />
        </div>

        {/* Password */}
        <div className="rounded-lg bg-white border border-slate-200 dark:bg-slate-800 dark:border-slate-700 p-6">
          <PasswordSection />
        </div>

        {/* MFA */}
        <div className="rounded-lg bg-white border border-slate-200 dark:bg-slate-800 dark:border-slate-700 p-6">
          <MFASection />
        </div>
      </div>
    </div>
  )
}
