import { BaseController } from '../base.controller.js';
import { COOKIE_NAMES } from '../../utils/cookies.js';
import { sessionService } from '../../services/session.service.js';
import type { Request, Response, NextFunction } from 'express';
import type { AccountService } from '../../services/account.service.js';
import type { AuthService } from '../../services/auth.service.js';

export class AccountApiController extends BaseController {
  constructor(
    private accountService: AccountService,
    private authService: AuthService,
  ) {
    super();
  }

  getProfile = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const userId = req?.user?.id || req.params?.user_id;
      const data = await this.accountService.get(userId);

      return {
        data,
        message: 'User profile fetched successfully',
        successRedirect: '/',
      };
    });
  };

  updateProfile = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const data = await this.accountService.update(req.user?.id, req.body.updates);
      return {
        data,
        message: 'User profile updated successfully',
        successRedirect: '/',
      };
    });
  };

  changePassword = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { email } = req.body;

      await this.authService.initiateResetPassword(email);

      return {
        message: 'Password reset email sent',
        successRedirect: '/account',
      };
    });
  };

  manageMfa = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { action } = req.body;
      const enable = action === 'enable';

      await this.accountService.manageMfa(req.user.id, enable);

      return {
        message: `Two-factor authentication ${enable ? 'enabled' : 'disabled'} successfully`,
        successRedirect: '/account',
      };
    });
  };

  deactivate = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      await this.accountService.deactivate(req.user.id);

      const isid = req.signedCookies[COOKIE_NAMES.IDENTITY_SESSION];
      const asid = req.signedCookies[COOKIE_NAMES.ACTIVE_SESSION];

      if (isid) {
        await sessionService.revokeIdentitySession(isid);
      }
      if (asid) {
        await sessionService.revokeActiveSession(asid);
      }

      res.clearCookie(COOKIE_NAMES.IDENTITY_SESSION, { signed: true });
      res.clearCookie(COOKIE_NAMES.ACTIVE_SESSION, { signed: true });

      return {
        message: 'User account deactivated successfully',
        successRedirect: '/signin',
      };
    });
  };

  delete = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      await this.accountService.delete(req.user.id);

      const isid = req.signedCookies[COOKIE_NAMES.IDENTITY_SESSION];
      const asid = req.signedCookies[COOKIE_NAMES.ACTIVE_SESSION];

      if (isid) {
        await sessionService.revokeIdentitySession(isid);
      }
      if (asid) {
        await sessionService.revokeActiveSession(asid);
      }

      res.clearCookie(COOKIE_NAMES.IDENTITY_SESSION, { signed: true });
      res.clearCookie(COOKIE_NAMES.ACTIVE_SESSION, { signed: true });

      return {
        message: 'User account deleted permanently',
        successRedirect: '/signin',
      };
    });
  };

  activate = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      await this.accountService.activate(req.user.id);

      return {
        message: 'User account activated successfully',
        successRedirect: '/account',
      };
    });
  };
}
