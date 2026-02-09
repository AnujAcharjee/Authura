import { Router } from 'express';
import { clientService } from '../../services/client.service.js';
import { joseService } from '../../services/jose.service.js';
import { userService } from '../../services/user.service.js';
import { ClientController } from '../../controllers/api/client.api.controller.js';
import { ClientZSchema } from '../../validators/client.validators.js';
import { validateRequest } from '../../middlewares/validateRequest.js';
import { Authentication, Authorize } from '../../middlewares/authMiddleware.js';
import { ROLES } from '../../utils/constant.js';

const router = Router();

const controller = new ClientController(clientService, joseService, userService);

// TODO: implement isolated router for every client

router.post(
  '/',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  validateRequest(ClientZSchema.addClientSchema),
  controller.addClient,
);

router
  .route('/:client_id')
  .get(
    Authentication.ssr,
    Authorize.role([ROLES.USER, ROLES.DEVELOPER]),
    Authorize.clientOwnership,
    validateRequest(ClientZSchema.clientIdSchema),
    controller.getClient,
  )
  .delete(
    Authentication.ssr,
    Authorize.role([ROLES.USER, ROLES.DEVELOPER]),
    Authorize.clientOwnership,
    validateRequest(ClientZSchema.clientIdSchema),
    controller.delete,
  )
  .put(
    Authentication.ssr,
    Authorize.role([ROLES.USER, ROLES.DEVELOPER]),
    Authorize.clientOwnership,
    validateRequest(ClientZSchema.clientIdSchema),
    controller.deactivate,
  );

router.post(
  '/:client_id/activate',
  Authentication.ssr,
  Authorize.role([ROLES.USER, ROLES.DEVELOPER]),
  Authorize.clientOwnership,
  validateRequest(ClientZSchema.clientIdSchema),
  controller.activate,
);

router.post(
  '/:client_id/ruri',
  Authentication.ssr,
  Authorize.role([ROLES.USER, ROLES.DEVELOPER]),
  Authorize.clientOwnership,
  validateRequest(ClientZSchema.manageRedirectsSchema),
  controller.manageRedirects,
);

router.post(
  '/rotate-secret',
  Authentication.ssr,
  Authorize.role([ROLES.USER, ROLES.DEVELOPER]),
  Authorize.clientOwnership,
  validateRequest(ClientZSchema.rotateSecretSchema),
  controller.rotateClientSecret,
);

// JWKS
router.get('/.well-known/jwks.json', controller.getJwks);

export default router;
