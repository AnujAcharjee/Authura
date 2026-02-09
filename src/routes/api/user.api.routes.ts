import { Router } from 'express';
import { userService } from '../../services/user.service.js';
import { UserApiController } from '../../controllers/api/user.api.controller.js';
import { UserZSchema } from '../../validators/user.validators.js';
import { validateRequest } from '../../middlewares/validateRequest.js';
import { Authentication, Authorize } from '../../middlewares/authMiddleware.js';
import { ROLES } from '../../utils/constant.js';

const router = Router();

const controller = new UserApiController(userService);

router.get(
  '/:user_id',
  Authentication.ssr,
  Authorize.role([ROLES.USER]),
  validateRequest(UserZSchema.getProfileSchema),
  controller.getProfile,
);

router
  .route('/')
  .put(
    Authentication.ssr,
    Authorize.role([ROLES.USER]),
    validateRequest(UserZSchema.updateProfileSchema),
    controller.updateProfile,
  )
  .delete(Authentication.ssr, Authorize.role([ROLES.USER]), controller.delete);

router.post('/deactivate', Authentication.ssr, Authorize.role([ROLES.USER]), controller.deactivate);
router.post('/activate', Authentication.ssr, Authorize.role([ROLES.USER]), controller.activate);

export default router;
