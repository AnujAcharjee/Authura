import { Router } from 'express';
import { PagesUiController } from '@/controllers/ui/pages.ui.controller';
import { oauthService } from '@/services/OAuth.service';
import { Authentication, Authorize } from '@/middlewares/authMiddleware';
import { userService } from '@/services/user.service';
import { clientService } from '@/services/client.service';
import { ROLES } from '@/utils/constant';

const router = Router();

const pagesController = new PagesUiController(userService, clientService, oauthService);

// ------------------- Landing -------------------

router.get('/', pagesController.renderLandingPage);

// ------------------- Auth -------------------

router.get('/signup', pagesController.renderSignupPage);
router.get('/signup/verify', pagesController.renderEmailVerificationPage);
router.get('/signin', pagesController.renderSigninPage);
router.get('/forgot-password', pagesController.renderForgotPasswordPage);
router.get('/reset-password', pagesController.renderResetPasswordPage);
router.get('/reset-password/:token', pagesController.renderResetPasswordPage);
router.get('/user/password', pagesController.renderForgotPasswordPage);

// ------------------- OAuth -------------------

router.get(
  '/oauth/consent',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  pagesController.renderOAuthConsentPage,
);

// ------------------- App -------------------

router.get(
  '/account',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  pagesController.renderAccountDashboard,
);

router.get(
  '/account/:action',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  pagesController.renderAccountConfirmation,
);

// add client
router.get('/client', Authentication.ssr, Authorize.role([ROLES.USER]), pagesController.renderAddClient);

router.get(
  '/client/:client_id',
  Authentication.ssr,
  Authorize.role([ROLES.USER, ROLES.DEVELOPER]),
  Authorize.clientOwnership,
  pagesController.renderClientDashboard,
);

router.get(
  '/client/:client_id/:action',
  Authentication.ssr,
  Authorize.role([ROLES.USER, ROLES.DEVELOPER]),
  Authorize.clientOwnership,
  pagesController.renderClientConfirmation,
);

export default router;
