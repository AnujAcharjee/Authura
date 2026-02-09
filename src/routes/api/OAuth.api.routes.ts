import { Router } from 'express';
import { oauthService } from '../../services/OAuth.service.js';
import { userService } from '../../services/user.service.js';
import { OAuthApiController } from '../../controllers/api/OAuth.api.controllers.js';
import { OAuthZSchema } from '../../validators/OAuth.validator.js';
import { validateRequest } from '../../middlewares/validateRequest.js';
import { Authentication, Authorize } from '../../middlewares/authMiddleware.js';
import { ROLES } from '../../utils/constant.js';

const router = Router();

const controller = new OAuthApiController(oauthService, userService);

// TODO: implement isolated router for every client

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
