import { Router } from 'express';
import { oauthService } from '@/services/OAuth.service';
import { userService } from '@/services/user.service';
import { OAuthApiController } from '@/controllers/api/OAuth.api.controllers';
import { OAuthZSchema } from '@/validators/OAuth.validator';
import { validateRequest } from '@/middlewares/validateRequest';
import { Authentication, Authorize } from '@/middlewares/authMiddleware';
import { ROLES } from '@/utils/constant';

const router = Router();

const controller = new OAuthApiController(oauthService, userService);

// TODO: implement isolated router for every client
// TODO: ensure a valid client or not in issue token

/**
 * '/authorize (GET)' : Client send req to Authura
 * '/consent (POST)' : /authorize redirects to Authura, if needed
 * '/token (POST)' : Client to Authura to get tokens
 * '/user/:id (POST)' : Client with access token to get info
 */

router.get(
  '/authorize',
  Authentication.ssr,
  validateRequest(OAuthZSchema.authorizeClientSchema),
  controller.authorizeClient,
);

router.post('/token', validateRequest(OAuthZSchema.issueTokensSchema), controller.issueTokens);

router
  .route('/consent')
  .post(
    Authentication.ssr,
    Authorize.role([ROLES.USER]),
    validateRequest(OAuthZSchema.authConsentSchema),
    controller.handleConsentSubmit,
  )
  .get(Authentication.ssr, Authorize.role([ROLES.USER]), controller.getUserConsents);

router.route('/user/:id').get(Authentication.client, controller.getUserInfo);

export default router;
