import { BaseController } from '@/controllers/base.controller';
import type { Request, Response, NextFunction } from 'express';
import type { UserService } from '@/services/user.service';

export class UserApiController extends BaseController {
  constructor(private userService: UserService) {
    super();
  }

  getProfile = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const userId = req?.user?.id || req.params?.user_id;
      const data = await this.userService.get(userId);

      return {
        data,
        message: 'User profile fetched successfully',
        successRedirect: '/',
      };
    });
  };

  updateProfile = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const data = await this.userService.update(req.user?.id, req.body.updates);
      return {
        data,
        message: 'User profile updated successfully',
        successRedirect: '/',
      };
    });
  };

  deactivate = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      await this.userService.deactivate(req.user.id);

      // TODO: revoke all sessions

      return {
        message: 'User account deactivated successfully',
        successRedirect: '/',
      };
    });
  };

  delete = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      await this.userService.delete(req.user.id);

      // TODO: revoke all sessions

      return {
        message: 'User account deleted permanently',
        successRedirect: '/',
      };
    });
  };
}
