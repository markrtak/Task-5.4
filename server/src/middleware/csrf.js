import { doubleCsrf } from 'csrf-csrf';

// Anti-CSRF protection using the double-submit-cookie pattern (csrf-csrf).
//
// GET /api/csrf-token hands the client a token AND sets a matching httpOnly
// cookie. On every state-changing request the client must echo the token in the
// `x-csrf-token` header; the middleware checks that the header matches the
// cookie and that its HMAC (keyed by CSRF_SECRET and bound to the current
// session) is valid.
//
// An attacker's page cannot pass this check: it cannot read the token (CORS
// blocks reading our responses, and the cookie is httpOnly), cannot guess it
// (HMAC with a server secret), and a plain HTML <form> cannot set custom headers.
const {
  generateCsrfToken,
  doubleCsrfProtection
} = doubleCsrf({
  // Read lazily so the secret can be supplied after this module is imported.
  getSecret: () => process.env.CSRF_SECRET,
  // Bind each token to the logged-in session (the auth JWT cookie), so a token
  // issued for one session is useless in another.
  getSessionIdentifier: (req) => req.cookies?.token ?? '',
  // Not the default `__Host-` name: browsers reject `__Host-` cookies without
  // `Secure`, and this demo runs over plain http://localhost.
  cookieName: 'x-csrf-token',
  cookieOptions: {
    httpOnly: true,
    sameSite: 'lax',
    secure: process.env.NODE_ENV === 'production',
    path: '/'
  },
  // GET / HEAD / OPTIONS are "safe" and never need a token.
  ignoredMethods: ['GET', 'HEAD', 'OPTIONS'],
  getCsrfTokenFromRequest: (req) => req.headers['x-csrf-token'],
  errorConfig: { statusCode: 403, message: 'Invalid or missing CSRF token', code: 'EBADCSRFTOKEN' }
});

// Pre-auth routes run before a session exists, so there is nothing to bind a
// token to; they stay exempt. Everything else that changes state is protected.
const EXEMPT = new Set(['/api/auth/login', '/api/auth/register']);

export function csrfProtection(req, res, next) {
  if (EXEMPT.has(req.path)) return next();
  return doubleCsrfProtection(req, res, next);
}

// GET /api/csrf-token
export function csrfTokenHandler(req, res) {
  // overwrite: true issues a fresh token tied to the current session (e.g.
  // right after login, when the session identifier has changed).
  const csrfToken = generateCsrfToken(req, res, { overwrite: true });
  res.json({ csrfToken });
}
