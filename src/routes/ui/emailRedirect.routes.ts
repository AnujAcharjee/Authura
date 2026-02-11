import { Router } from 'express';
import { AuthApiController } from '../../controllers/api/auth.api.controller.js';
import { authService } from '../../services/auth.service.js';
import { sessionService } from '../../services/session.service.js';
import { AuthZSchema } from '../../validators/auth.validators.js';
import { validateRequest } from '../../middlewares/validateRequest.js';
import { emailVerificationLimiter } from '../../middlewares/rateLimiter.js';

const router = Router();

const controller = new AuthApiController(authService, sessionService);

router.get('/verify', validateRequest(AuthZSchema.verifyEmailSchema), controller.verifyEmail);

router.get('/signin', validateRequest(AuthZSchema.verifySignInSchema), controller.verifySignin);

router.get(
  '/verify/resend',
  emailVerificationLimiter,
  validateRequest(AuthZSchema.resendVerificationEmailSchema),
  controller.resendVerificationEmail,
);

export default router;
