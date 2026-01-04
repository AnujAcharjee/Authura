import { Router } from 'express';
import { AuthController } from '@/controllers/auth.controller';
import { AuthService } from '@/services/auth.service';
import { signupSchema, verifyEmailSchema, resendVerificationEmailSchema } from '@/validators/auth.validators';
import { validateRequest } from '@/middlewares/validateRequest';
import { emailVerificationLimiter } from '@/middlewares/rateLimiter';

const router = Router();

const authService = new AuthService();
const authController = new AuthController(authService);

router.post('/signup', validateRequest(signupSchema), authController.signup);
router.get('/verify-email/:token', validateRequest(verifyEmailSchema), authController.verifyEmail);
router.post(
  '/send-email-verification',
  emailVerificationLimiter,
  validateRequest(resendVerificationEmailSchema),
  authController.resendVerificationEmail,
);

export default router;
