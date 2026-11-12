import { rateLimit } from 'express-rate-limit';

// Rate limiting so a single client cannot flood the API (DoS). Each limiter
// counts requests per client IP in a sliding time window and answers
// 429 Too Many Requests once the limit is exceeded, without ever reaching the
// controller (and therefore the database).

function handler(req, res, next, options) {
  res.status(options.statusCode).json({ message: 'Too many requests, please try again later.' });
}

// Reads of the public maintenance list / detail endpoints.
export const maintenanceReadLimiter = rateLimit({
  windowMs: 60 * 1000, // 1 minute
  limit: 20,           // 20 reads per minute per client
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler
});

// Writes (file / edit / delete a request) are rarer and more expensive.
export const maintenanceWriteLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  limit: 10,                // 10 writes per 15 minutes per client
  standardHeaders: 'draft-7',
  legacyHeaders: false,
  handler
});
