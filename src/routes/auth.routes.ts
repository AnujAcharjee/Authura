import { Router } from 'express';
import { AuthController } from '@/controllers/auth.controller';
import { AuthService } from '@/services/auth.service';
import {
  signupSchema,
  verifyEmailSchema,
  resendVerificationEmailSchema,
  signinSchema,
  verifySignInSchema,
  forgotPasswordSchema,
  resetPasswordSchema,
} from '@/validators/auth.validators';
import { validateRequest } from '@/middlewares/validateRequest';
import { emailVerificationLimiter } from '@/middlewares/rateLimiter';
import { ensureAuth } from '@/middlewares/authMiddleware';

const router = Router();

const authService = new AuthService();
const authController = new AuthController(authService);

// SIGN-UP
router.post('/signup', validateRequest(signupSchema), authController.signup);
router.get('/verify-email/:token', validateRequest(verifyEmailSchema), authController.verifyEmail);
router.post(
  '/send-email-verification',
  emailVerificationLimiter,
  validateRequest(resendVerificationEmailSchema),
  authController.resendVerificationEmail,
);

// SIGN-IN
router.post('/signin', validateRequest(signinSchema), authController.signin);
router.get('/verify-signin/:token', validateRequest(verifySignInSchema), authController.verifySignin);

// REFRESH SESSION
router.post('/refresh-sess', authController.refreshActiveSession);

// SIGN-OUT
router.post('/signout', ensureAuth, authController.signout);

// RESET PASSWORD
router.post(
  '/forget-password',
  ensureAuth,
  validateRequest(forgotPasswordSchema),
  authController.forgotPassword,
);
router.get('/reset-password', ensureAuth, validateRequest(resetPasswordSchema), authController.resetPassword);

export default router;
