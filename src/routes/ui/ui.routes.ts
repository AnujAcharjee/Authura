import { Router } from 'express';
import { PagesUiController } from '../../controllers/ui/pages.ui.controller.js';
import { oauthService } from '../../services/OAuth.service.js';
import { Authentication, Authorize } from '../../middlewares/authMiddleware.js';
import { accountService } from '../../services/account.service.js';
import { clientService } from '../../services/client.service.js';
import { ROLES } from '../../utils/constant.js';

const router = Router();

const pagesController = new PagesUiController(accountService, clientService, oauthService);

// ------------------- Landing -------------------

router.get('/', pagesController.renderLandingPage);

// ------------------- Auth -------------------

router.get('/signup', pagesController.renderSignupPage);
router.get('/signup/verify', pagesController.renderEmailVerificationPage);

router.get('/signin', pagesController.renderSigninPage);

router.get('/forgot-password', pagesController.renderForgotPasswordPage);
router.get('/reset-password', pagesController.renderResetPasswordPage);

// ------------------- OAuth -------------------

router.get(
  '/oauth/consent',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  pagesController.renderOAuthConsentPage,
);

router.get(
  '/oauth/consent/:result',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  pagesController.renderOAuthConsentResultPage,
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
