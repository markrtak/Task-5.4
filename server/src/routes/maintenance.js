import { Router } from 'express';
import { requireAuth } from '../middleware/auth.js';
import { maintenanceReadLimiter, maintenanceWriteLimiter } from '../middleware/rateLimit.js';
import {
  getAllRequests,
  getRequest,
  createRequest,
  updateRequest,
  deleteRequest
} from '../controllers/maintenanceController.js';

const router = Router();

// Reading is public; writing requires a logged-in user.
//
// Hardened on two fronts:
//   1. CSRF — every write must carry a valid anti-CSRF token in the
//      `x-csrf-token` header. That check is applied app-wide in app.js
//      (csrfProtection), so it also covers these routes; a forged cross-site
//      request that only carries the auth cookie is rejected with 403.
//   2. DoS — every route is rate-limited per client, so a flood is refused
//      with 429 before it reaches the database.
router.get('/', maintenanceReadLimiter, getAllRequests);
router.get('/:id', maintenanceReadLimiter, getRequest);
router.post('/', maintenanceWriteLimiter, requireAuth, createRequest);
router.patch('/:id', maintenanceWriteLimiter, requireAuth, updateRequest);
router.delete('/:id', maintenanceWriteLimiter, requireAuth, deleteRequest);

export default router;
