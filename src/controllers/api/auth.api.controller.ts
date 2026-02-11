import type { Request, Response, NextFunction } from 'express';
import { BaseController } from '../base.controller.js';
import { COOKIE_NAMES, setSessionCookies } from '../../utils/cookies.js';
import { AppError } from '../../utils/appError.js';
import { ErrorCode } from '../../utils/errorCodes.js';
import type { AuthService } from '../../services/auth.service.js';
import type { SessionService } from '../../services/session.service.js';

/**
 * SIGN UP :
 *  1. get user data
 *  2. create user in db (unique email)
 *  3. send email (email verification)
 *
 * VERIFY EMAIL :
 *  1. update email verified in db
 *  2. set cookies
 *
 * SIGN IN :
 */

export class AuthApiController extends BaseController {
  constructor(
    private authService: AuthService,
    private sessionService: SessionService,
  ) {
    super();
  }

  signup = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { email, name, gender, password } = req.body;
      const data = await this.authService.signup({ email, name, gender, password });

      res.clearCookie(COOKIE_NAMES.IDENTITY_SESSION, { signed: true });
      res.clearCookie(COOKIE_NAMES.ACTIVE_SESSION, { signed: true });

      return {
        data,
        message: 'Account created successfully. Please verify your email address.',
        successRedirect: '/signup/verify',
        query: `&email=${encodeURIComponent(data.email)}`,
      };
    });
  };

  /** Called by email ui router */
  verifyEmail = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const token  = req.query.token as string;

      const ids = await this.authService.verifyEmail(token);

      await setSessionCookies(res, ids?.identitySessionId, ids?.activeSessionId);

      return {
        message: 'Email verified successfully. You are now signed in.',
        successRedirect: '/account',
      };
    });
  };

  resendVerificationEmail = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { email } = req.query;

      if (typeof email !== 'string') {
        throw new AppError('Invalid email', 400, ErrorCode.INVALID_EMAIL);
      }

      await this.authService.resendVerificationEmail(email);

      return {
        message: 'If an account exists, a verification email has been sent',
        successRedirect: '/signup/verify',
        query: `&email=${encodeURIComponent(email)}`,
      };
    });
  };

  signin = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { email, password } = req.body;

      const data = await this.authService.signin({ email, password });

      let message: string, successRedirect: string;
      if (!data?.mfaEnabled && data?.identitySessionId && data?.activeSessionId) {
        await setSessionCookies(res, data?.identitySessionId, data?.activeSessionId);
        message = `Signed-in successfully`;
        successRedirect = '/account';
      } else {
        message = `Sign-in verification email has been sent to the registered email address`;
        successRedirect = '/signin';
      }

      return {
        data: { email: data.email, mfaEnabled: data.mfaEnabled },
        message,
        successRedirect,
      };
    });
  };

  /** Called by email ui router */
  verifySignin = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const token = req.query.token as string;

      const data = await this.authService.verifySignIn(token);

      await setSessionCookies(res, data?.identitySessionId, data?.activeSessionId);

      return {
        data: { id: data.id, email: data.email },
        message: `Signed-in successfully`,
        successRedirect: '/account',
      };
    });
  };

  signout = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const isid = req.signedCookies[COOKIE_NAMES.IDENTITY_SESSION];
      const asid = req.signedCookies[COOKIE_NAMES.ACTIVE_SESSION];

      await this.authService.signout(isid, asid);

      res.clearCookie(COOKIE_NAMES.IDENTITY_SESSION, { signed: true });
      res.clearCookie(COOKIE_NAMES.ACTIVE_SESSION, { signed: true });

      return {
        message: 'User signed out successfully',
        successRedirect: '/account',
      };
    });
  };

  refreshActiveSession = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const isid = req.signedCookies[COOKIE_NAMES.IDENTITY_SESSION];

      const data = await this.sessionService.refreshActiveSession(isid);

      setSessionCookies(res, null, data.activeSessId);

      return { message: 'Session refreshed successfully' };
    });
  };

  forgotPassword = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { email } = req.body;

      await this.authService.initiateResetPassword(email);

      return {
        message: 'Password reset email sent',
        successRedirect: '/forgot-password',
      };
    });
  };

  resetPassword = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const { token, old_password, new_password } = req.body;

      await this.authService.resetPassword(token, old_password, new_password);

      return {
        message: 'Password reset successfully',
        successRedirect: '/signin',
      };
    });
  };
}
