// All communication with the Flask backend lives here (plain JS so it can be tested without a browser).

export const DEFAULT_BASE = 'http://127.0.0.1:5000'

export class ApiError extends Error {
  constructor(code, message, status = 0) {
    super(message)
    this.name = 'ApiError'
    this.code = code
    this.status = status
  }
}

export function apiBase() {
  if (typeof import.meta !== 'undefined' && import.meta.env) {
    if (import.meta.env.VITE_API_BASE_URL !== undefined && import.meta.env.VITE_API_BASE_URL !== '') {
      return String(import.meta.env.VITE_API_BASE_URL).replace(/\/+$/, '')
    }
    if (import.meta.env.DEV) {
      return DEFAULT_BASE
    }
    return ''
  }
  return DEFAULT_BASE
}

async function request(path, { method = 'GET', body, baseUrl, fetchImpl, timeoutMs = 15000 } = {}) {
  const base = (baseUrl ?? apiBase()).replace(/\/+$/, '')
  const url = base ? `${base}${path}` : path
  const doFetch = fetchImpl || globalThis.fetch
  let res
  try {
    res = await doFetch(url, {
      method,
      headers: body ? { 'Content-Type': 'application/json' } : undefined,
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(timeoutMs),
    })
  } catch (err) {
    if (err && (err.name === 'TimeoutError' || err.name === 'AbortError')) {
      throw new ApiError('timeout', 'The server took too long to answer. Please try again.')
    }
    const target = base || 'the current server'
    throw new ApiError('network_error', `Cannot reach the PhishGuard server at ${target}. Start the backend (python app.py) and check VITE_API_BASE_URL.`)
  }
  let data
  try {
    data = await res.json()
  } catch {
    throw new ApiError('bad_response', 'The server sent a response that could not be read.', res.status)
  }
  if (!res.ok) {
    const e = data && data.error
    throw new ApiError((e && e.code) || 'http_error', (e && e.message) || `Request failed (${res.status}).`, res.status)
  }
  return data
}

export const scanUrl = (url, opts = {}) => request('/api/predict', { ...opts, method: 'POST', body: { url } })
export const getReport = (opts = {}) => request('/api/report', opts)
export const getHealth = (opts = {}) => request('/api/health', opts)
