const BASE = '/api/v1'

/**
 * Low-level fetch wrapper. Does NOT inject auth headers.
 * Used by the auth store for login/refresh calls.
 */
export async function apiFetch(path, options = {}) {
  const url = `${BASE}${path}`
  const res = await fetch(url, {
    headers: { 'Content-Type': 'application/json', ...options.headers },
    ...options,
  })
  const text = await res.text()
  const data = text ? JSON.parse(text) : null

  if (!res.ok) {
    const err = new Error(data?.error || `Request failed: ${res.status}`)
    err.status = res.status
    err.data = data
    throw err
  }
  return data
}

/**
 * Authenticated fetch wrapper. Injects Bearer token from auth store.
 * Attempts silent refresh on 401 and retries once.
 */
async function authFetch(path, options = {}) {
  // Lazy import to avoid circular dependency.
  const { useAuthStore } = await import('../stores/authStore')
  const state = useAuthStore.getState()

  const makeRequest = (token) =>
    apiFetch(path, {
      ...options,
      headers: {
        ...options.headers,
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
      },
    })

  try {
    return await makeRequest(state.accessToken)
  } catch (err) {
    if (err.status === 401 && state.refreshToken) {
      // Attempt silent refresh and retry.
      try {
        await useAuthStore.getState().silentRefresh()
        const newToken = useAuthStore.getState().accessToken
        return await makeRequest(newToken)
      } catch {
        // Refresh failed — session expired.
        useAuthStore.getState().clearAuth()
        throw err
      }
    }
    throw err
  }
}

export const api = {
  get: (path) => authFetch(path, { method: 'GET' }),
  post: (path, body) => authFetch(path, { method: 'POST', body: JSON.stringify(body) }),
  put: (path, body) => authFetch(path, { method: 'PUT', body: JSON.stringify(body) }),
  del: (path, body) => authFetch(path, { method: 'DELETE', body: body ? JSON.stringify(body) : undefined }),
}
