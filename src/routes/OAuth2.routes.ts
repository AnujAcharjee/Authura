import { Router } from 'express';
import { OAuth2Service } from '@/services/OAuth2.service';
import { OAuth2Controller } from '@/controllers/OAuth2.controllers';
import {
  registerClientSchema,
  updateRedirectSchema,
  authorizeClientSchema,
  issueTokensSchema,
  jwksSchema,
} from '@/validators/OAuth2.validator';
import { validateRequest } from '@/middlewares/validateRequest';
import { ensureAuth } from '@/middlewares/authMiddleware';

const router = Router();

const service = new OAuth2Service();
const controller = new OAuth2Controller(service);

// CLIENTS
router.post('/clients/register', validateRequest(registerClientSchema), controller.registerClient);
router.post('/clients/update', validateRequest(updateRedirectSchema), controller.updateRedirects);

// JWKS
router.get('/.well-known/jwks.json', validateRequest(jwksSchema), controller.getJwks);

// OIDC
router.get('/authorize', ensureAuth, validateRequest(authorizeClientSchema), controller.authorizeClient);
router.post('/token', validateRequest(issueTokensSchema), controller.issueTokens);

export default router;
