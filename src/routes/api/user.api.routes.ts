import { Router } from 'express';
import { userService } from '@/services/user.service';
import { UserApiController } from '@/controllers/api/user.api.controller';
import { UserZSchema } from '@/validators/user.validators';
import { validateRequest } from '@/middlewares/validateRequest';
import { Authentication, Authorize } from '@/middlewares/authMiddleware';
import { ROLES } from '@/utils/constant';

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
