import axios from 'axios'

// `withCredentials: true` makes the browser send the httpOnly auth cookie on
// every request to the API. Because the browser would also attach that cookie to
// requests forged by another site, the cookie alone is not proof of intent: every
// state-changing request additionally carries an anti-CSRF token in the
// `x-csrf-token` header. Only our own UI can obtain that token (CORS stops other
// origins from reading /csrf-token), and a forged HTML form cannot set headers.
export const api = axios.create({
  baseURL: 'http://localhost:4000/api',
  withCredentials: true
})

const SAFE_METHODS = ['get', 'head', 'options']
// Pre-auth routes run before a session exists; the server exempts them too.
const CSRF_EXEMPT = ['/auth/login', '/auth/register']

let csrfToken = null
let pending = null

// Fetch (once) and cache the token for the current session. Uses the same `api`
// instance; this GET is a safe method, so it does not re-enter the interceptor.
async function getCsrfToken() {
  if (csrfToken) return csrfToken
  if (!pending) {
    pending = api.get('/csrf-token')
      .then(res => { csrfToken = res.data.csrfToken; return csrfToken })
      .finally(() => { pending = null })
  }
  return pending
}

// The token is bound to the session, so forget it whenever the session changes
// (login, register, logout).
export function clearCsrfToken() {
  csrfToken = null
}

api.interceptors.request.use(async (config) => {
  const method = (config.method || 'get').toLowerCase()
  const url = config.url || ''
  if (!SAFE_METHODS.includes(method) && !CSRF_EXEMPT.some(p => url.includes(p))) {
    config.headers.set('x-csrf-token', await getCsrfToken())
  }
  return config
})

// If the token was rejected (e.g. it was issued for an older session), fetch a
// fresh one and retry the request once.
api.interceptors.response.use(undefined, async (error) => {
  const { config, response } = error
  if (response?.status === 403 && response.data?.code === 'EBADCSRFTOKEN' && config && !config._csrfRetried) {
    config._csrfRetried = true
    clearCsrfToken()
    config.headers.set('x-csrf-token', await getCsrfToken())
    return api.request(config)
  }
  return Promise.reject(error)
})
