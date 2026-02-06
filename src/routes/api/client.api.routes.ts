import { Router } from 'express';
import { clientService } from '@/services/client.service';
import { joseService } from '@/services/jose.service';
import { userService } from '@/services/user.service';
import { ClientController } from '@/controllers/api/client.api.controller';
import { ClientZSchema } from '@/validators/client.validators';
import { validateRequest } from '@/middlewares/validateRequest';
import { Authentication, Authorize } from '@/middlewares/authMiddleware';
import { ROLES } from '@/utils/constant';

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
