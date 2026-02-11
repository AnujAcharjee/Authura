import { Router } from 'express';
import { accountService } from '../../services/account.service.js';
import { authService } from '../../services/auth.service.js';
import { AccountApiController } from '../../controllers/api/account.api.controller.js';
import { AccountZSchema } from '../../validators/account.validators.js';
import { validateRequest } from '../../middlewares/validateRequest.js';
import { Authentication, Authorize } from '../../middlewares/authMiddleware.js';
import { ROLES } from '../../utils/constant.js';

const router = Router();

const controller = new AccountApiController(accountService, authService);

router.get(
  '/:user_id',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  validateRequest(AccountZSchema.getProfileSchema),
  controller.getProfile,
);

router
  .route('/')
  .put(
    Authentication.ssr,
    Authorize.role([ROLES.USER]),
    validateRequest(AccountZSchema.updateProfileSchema),
    controller.updateProfile,
  )
  .delete(Authentication.ssr, Authorize.role([ROLES.USER]), controller.delete);

router.post(
  '/mfa',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  validateRequest(AccountZSchema.manageMfaSchema),
  controller.manageMfa,
);

router.post(
  '/change-password',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  validateRequest(AccountZSchema.changePasswordSchema),
  controller.changePassword,
);

router.post('/deactivate', Authentication.ssr, Authorize.role([ROLES.USER]), controller.deactivate);
router.post('/activate', Authentication.ssr, Authorize.role([ROLES.USER]), controller.activate);

export default router;
