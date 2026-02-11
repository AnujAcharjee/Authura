import { Router } from 'express';
import { AuthApiController } from '../../controllers/api/auth.api.controller.js';
import { authService } from '../../services/auth.service.js';
import { sessionService } from '../../services/session.service.js';
import { AuthZSchema } from '../../validators/auth.validators.js';
import { validateRequest } from '../../middlewares/validateRequest.js';
import { Authentication, Authorize } from '../../middlewares/authMiddleware.js';
import { ROLES } from '../../utils/constant.js';
import { forgotPasswordLimiter, signupLimiter, signinLimiter } from '../../middlewares/rateLimiter.js';

const router = Router();

const controller = new AuthApiController(authService, sessionService);

router.post('/signup', signupLimiter, validateRequest(AuthZSchema.signupSchema), controller.signup);

router.post('/signin', signinLimiter, validateRequest(AuthZSchema.signinSchema), controller.signin);

router.post(
  '/forgot-password',
  forgotPasswordLimiter,
  validateRequest(AuthZSchema.forgotPasswordSchema),
  controller.forgotPassword,
);

router.post(
  '/reset-password',
  validateRequest(AuthZSchema.resetPasswordSchema),
  controller.resetPassword,
);

router.post('/refresh-session', controller.refreshActiveSession);

router.post('/signout', Authentication.ssr, Authorize.role([ROLES.USER]), controller.signout);

export default router;
