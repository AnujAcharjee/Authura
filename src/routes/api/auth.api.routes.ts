import { Router } from 'express';
import { AuthApiController } from '@/controllers/api/auth.api.controller';
import { authService } from '@/services/auth.service';
import { sessionService } from '@/services/session.service';
import { AuthZSchema } from '@/validators/auth.validators';
import { validateRequest } from '@/middlewares/validateRequest';
import { emailVerificationLimiter } from '@/middlewares/rateLimiter';
import { Authentication, Authorize } from '@/middlewares/authMiddleware';
import { ROLES } from '@/utils/constant';

const router = Router();

const controller = new AuthApiController(authService, sessionService);

router.post('/signup', validateRequest(AuthZSchema.signupSchema), controller.signup);
router.get('/verify-email/:token', validateRequest(AuthZSchema.verifyEmailSchema), controller.verifyEmail);
router.get(
  '/email-verification',
  emailVerificationLimiter,
  validateRequest(AuthZSchema.resendVerificationEmailSchema),
  controller.resendVerificationEmail,
);

router.post('/signin', validateRequest(AuthZSchema.signinSchema), controller.signin);
router.get('/verify-signin/:token', validateRequest(AuthZSchema.verifySignInSchema), controller.verifySignin);

router.post('/refresh-session', controller.refreshActiveSession);

router.post('/signout', Authentication.ssr, Authorize.role([ROLES.USER]), controller.signout);

router.post(
  '/mfa',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  validateRequest(AuthZSchema.manageMfaSchema),
  controller.manageMfa,
);

router.post(
  '/forgot-password',
  validateRequest(AuthZSchema.forgotPasswordSchema),
  controller.forgotPassword,
);

router.post(
  '/reset-password',
  validateRequest(AuthZSchema.resetPasswordSchema),
  controller.resetPassword,
);

export default router;
