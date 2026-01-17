import { Request, Response, NextFunction } from 'express';
import { AuthService } from '@/services/auth.service';
import { BaseController } from '@/controllers/base.controller';
import { COOKIE_NAMES } from '@/utils/cookies';
import { ENV } from '@/config/env';

export class AuthController extends BaseController {
  constructor(private authService: AuthService) {
    super();
  }

  private async setSessionCookies(res: Response, isid: string | null, asid: string | null) {
    if (isid) {
      res.cookie(COOKIE_NAMES.IDENTITY_SESSION, isid, {
        httpOnly: true,
        secure: ENV.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: ENV.NODE_ENV === 'production' ? ENV.IDENTITY_SESSION_EX * 1000 : 30 * 24 * 60 * 60 * 1000,
        signed: true,
      });
    }

    if (asid) {
      res.cookie(COOKIE_NAMES.ACTIVE_SESSION, asid, {
        httpOnly: true,
        secure: ENV.NODE_ENV === 'production',
        sameSite: 'lax',
        maxAge: ENV.NODE_ENV === 'production' ? ENV.ACTIVE_SESSION_EX * 1000 : 15 * 60 * 1000,
        signed: true,
      });
    }
  }

  signup = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { email, name, password } = req.body;
      const data = await this.authService.signup({ email, name, password });

      return {
        data,
        message: 'Account created successfully. Please verify your email address.',
      };
    });
  };

  verifyEmail = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { token } = req.params;

      const ids = await this.authService.verifyEmail(token);

      await this.setSessionCookies(res, ids?.identitySessionId, ids?.activeSessionId);

      return {
        data: null,
        message: 'Email verified successfully. You are now signed in.',
      };
    });
  };

  resendVerificationEmail = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { email } = req.body;
      await this.authService.resendVerificationEmail(email);

      return {
        data: null,
        message: 'If an account exists, a verification email has been sent',
      };
    });
  };

  signin = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { email, password } = req.body;

      const vals = await this.authService.signin({ email, password });

      let message: string;
      if (!vals?.mfaEnabled && vals?.identitySessionId && vals?.activeSessionId) {
        await this.setSessionCookies(res, vals?.identitySessionId, vals?.activeSessionId);
        message = `User signed-in successfully`;
      } else {
        message = `Sign-in verification email has been sent to the registered email address`;
      }

      return {
        data: null,
        message,
      };
    });
  };

  verifySignin = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { token } = req.params;

      const ids = await this.authService.verifySignIn(token);

      await this.setSessionCookies(res, ids?.identitySessionId, ids?.activeSessionId);

      return {
        data: null,
        message: `User signed-in successfully`,
      };
    });
  };

  signout = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const isid = req.signedCookies[COOKIE_NAMES.IDENTITY_SESSION];
      const asid = req.signedCookies[COOKIE_NAMES.ACTIVE_SESSION];

      const signoutMsg = await this.authService.signout(isid, asid);

      res.clearCookie(COOKIE_NAMES.IDENTITY_SESSION, { signed: true });
      res.clearCookie(COOKIE_NAMES.ACTIVE_SESSION, { signed: true });

      return {
        data: null,
        message: 'User signed out successfully',
      };
    });
  };

  refreshActiveSession = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const isid = req.signedCookies[COOKIE_NAMES.IDENTITY_SESSION];

      const asid = await this.authService.refreshActiveSession(isid);

      this.setSessionCookies(res, null, asid);

      return {
        data: null,
        message: 'Session refreshed successfully',
      };
    });
  };

  forgotPassword = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { email } = req.body;

      await this.authService.forgotPassword(email);

      return {
        data: null,
        message: 'Password reset email sent',
      };
    });
  };

  resetPassword = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { token } = req.params;
      const { password } = req.body;

      await this.authService.resetPassword(token, password);

      return {
        data: null,
        message: 'Password reset successfully',
      };
    });
  };
}
