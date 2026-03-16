import { Fragment, useState, useRef, useEffect } from 'react'
import { Dialog, DialogPanel, DialogTitle, Transition, TransitionChild } from '@headlessui/react'
import { ShieldCheckIcon, ClipboardDocumentIcon, CheckIcon, ExclamationTriangleIcon } from '@heroicons/react/24/outline'
import { QRCodeSVG } from 'qrcode.react'
import { api } from '../lib/api'
import { useAuthStore } from '../stores/authStore'

export default function MFAEnrollModal({ open, onClose }) {
  const [step, setStep] = useState('loading') // loading | qr | verify | done
  const [secret, setSecret] = useState('')
  const [uri, setUri] = useState('')
  const [code, setCode] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)
  const [copied, setCopied] = useState(false)
  const codeRef = useRef(null)

  // Enroll on open.
  useEffect(() => {
    if (!open) {
      setStep('loading')
      setSecret('')
      setUri('')
      setCode('')
      setError('')
      setCopied(false)
      return
    }

    api.post('/auth/me/mfa/enroll')
      .then((data) => {
        setSecret(data.secret)
        setUri(data.uri)
        setStep('qr')
      })
      .catch((err) => {
        setError(err.message || 'Failed to start MFA enrollment')
        setStep('qr')
      })
  }, [open])

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(secret)
      setCopied(true)
      setTimeout(() => setCopied(false), 2000)
    } catch {}
  }

  const handleVerify = async (e) => {
    if (e) e.preventDefault()
    if (code.length !== 6 || loading) return

    setLoading(true)
    setError('')

    try {
      await api.post('/auth/me/mfa/verify', { code })
      setStep('done')
      // Refresh user profile to reflect mfa_enabled.
      useAuthStore.getState().fetchProfile()
      setTimeout(() => onClose(), 1500)
    } catch (err) {
      setError(err.status === 401 ? 'Invalid code. Please try again.' : 'Verification failed')
      setCode('')
      codeRef.current?.focus()
    } finally {
      setLoading(false)
    }
  }

  const handleCodeChange = (e) => {
    const val = e.target.value.replace(/\D/g, '').slice(0, 6)
    setCode(val)
    setError('')
  }

  // Auto-submit on 6 digits.
  useEffect(() => {
    if (code.length === 6 && step === 'verify') handleVerify()
  }, [code, step])

  return (
    <Transition show={open} as={Fragment}>
      <Dialog onClose={onClose} className="relative z-50">
        <TransitionChild
          as={Fragment}
          enter="ease-out duration-300" enterFrom="opacity-0" enterTo="opacity-100"
          leave="ease-in duration-200" leaveFrom="opacity-100" leaveTo="opacity-0"
        >
          <div className="fixed inset-0 bg-black/50" />
        </TransitionChild>

        <div className="fixed inset-0 flex items-center justify-center p-4">
          <TransitionChild
            as={Fragment}
            enter="ease-out duration-300" enterFrom="opacity-0 scale-95" enterTo="opacity-100 scale-100"
            leave="ease-in duration-200" leaveFrom="opacity-100 scale-100" leaveTo="opacity-0 scale-95"
          >
            <DialogPanel className="w-full max-w-sm rounded-xl bg-white dark:bg-slate-800 border border-slate-200 dark:border-slate-700 shadow-xl p-6">
              {step === 'loading' && (
                <div className="flex justify-center py-8">
                  <div className="h-8 w-8 border-2 border-indigo-500 border-t-transparent rounded-full animate-spin" />
                </div>
              )}

              {step === 'qr' && (
                <div className="space-y-4">
                  <div className="flex items-center gap-3">
                    <ShieldCheckIcon className="h-6 w-6 text-indigo-400" />
                    <DialogTitle className="text-lg font-semibold text-slate-900 dark:text-white">
                      Enable Two-Factor Auth
                    </DialogTitle>
                  </div>

                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    Scan this QR code with your authenticator app (Google Authenticator, Authy, etc.)
                  </p>

                  {error && (
                    <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                      <ExclamationTriangleIcon className="h-5 w-5 shrink-0" />
                      <span>{error}</span>
                    </div>
                  )}

                  {uri && (
                    <div className="flex justify-center p-4 bg-white rounded-lg">
                      <QRCodeSVG value={uri} size={180} />
                    </div>
                  )}

                  {secret && (
                    <div className="space-y-1">
                      <p className="text-xs text-slate-500 dark:text-slate-400">
                        Can't scan? Enter this key manually:
                      </p>
                      <div className="flex items-center gap-2">
                        <code className="flex-1 px-3 py-1.5 rounded bg-slate-100 dark:bg-slate-900 text-sm font-mono text-slate-700 dark:text-slate-300 break-all">
                          {secret}
                        </code>
                        <button
                          onClick={handleCopy}
                          className="p-1.5 rounded hover:bg-slate-100 dark:hover:bg-slate-700 text-slate-400 hover:text-slate-600 dark:hover:text-slate-300"
                          title="Copy"
                        >
                          {copied ? <CheckIcon className="h-4 w-4 text-green-400" /> : <ClipboardDocumentIcon className="h-4 w-4" />}
                        </button>
                      </div>
                    </div>
                  )}

                  <div className="flex gap-2 pt-2">
                    <button
                      onClick={onClose}
                      className="flex-1 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 text-sm hover:bg-slate-50 dark:hover:bg-slate-700"
                    >
                      Cancel
                    </button>
                    <button
                      onClick={() => setStep('verify')}
                      disabled={!uri}
                      className="flex-1 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium disabled:opacity-50"
                    >
                      Next
                    </button>
                  </div>
                </div>
              )}

              {step === 'verify' && (
                <form onSubmit={handleVerify} className="space-y-4">
                  <DialogTitle className="text-lg font-semibold text-slate-900 dark:text-white">
                    Verify Code
                  </DialogTitle>

                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    Enter the 6-digit code from your authenticator app to complete setup.
                  </p>

                  {error && (
                    <div className="flex items-center gap-2 p-3 rounded-lg bg-red-500/10 border border-red-500/30 text-red-400 text-sm">
                      <ExclamationTriangleIcon className="h-5 w-5 shrink-0" />
                      <span>{error}</span>
                    </div>
                  )}

                  <input
                    ref={codeRef}
                    type="text"
                    inputMode="numeric"
                    pattern="[0-9]*"
                    autoFocus
                    value={code}
                    onChange={handleCodeChange}
                    maxLength={6}
                    className="w-full px-4 py-3 rounded-lg bg-slate-100 dark:bg-slate-900 border border-slate-300 dark:border-slate-600 text-slate-900 dark:text-white text-center text-2xl font-mono tracking-[0.5em] focus:outline-none focus:ring-2 focus:ring-indigo-500 placeholder-slate-400 dark:placeholder-slate-600"
                    placeholder="000000"
                  />

                  <div className="flex gap-2">
                    <button
                      type="button"
                      onClick={() => { setStep('qr'); setCode(''); setError('') }}
                      className="flex-1 py-2 rounded-lg border border-slate-300 dark:border-slate-600 text-slate-700 dark:text-slate-300 text-sm hover:bg-slate-50 dark:hover:bg-slate-700"
                    >
                      Back
                    </button>
                    <button
                      type="submit"
                      disabled={code.length !== 6 || loading}
                      className="flex-1 py-2 rounded-lg bg-indigo-600 hover:bg-indigo-500 text-white text-sm font-medium disabled:opacity-50"
                    >
                      {loading ? 'Verifying...' : 'Verify'}
                    </button>
                  </div>
                </form>
              )}

              {step === 'done' && (
                <div className="flex flex-col items-center gap-3 py-4">
                  <CheckIcon className="h-12 w-12 text-green-400" />
                  <p className="text-lg font-semibold text-slate-900 dark:text-white">MFA Enabled</p>
                  <p className="text-sm text-slate-500 dark:text-slate-400">
                    Two-factor authentication is now active on your account.
                  </p>
                </div>
              )}
            </DialogPanel>
          </TransitionChild>
        </div>
      </Dialog>
    </Transition>
  )
}
