import { Request, Response, NextFunction } from 'express';
import { AuthService } from '@/services/auth.service';
import { BaseController } from '@/controllers/base.controller';
import { AppError } from '@/utils/appError';

export class AuthController extends BaseController {
  constructor(private authService: AuthService) {
    super();
  }

  signup = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { email, name, password } = req.body;
      return await this.authService.signup({ email, name, password });
    });
  };

  verifyEmail = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { token } = req.params;
      return await this.authService.verifyEmail({ token });
    });
  };

  resendVerificationEmail = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { email } = req.body;
      return await this.authService.resendVerificationEmail({ email });
    });
  };
}
