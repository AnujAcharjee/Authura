import type { Request, Response, NextFunction } from 'express';
import { BaseController } from '@/controllers/base.controller';
import type { UserService, UserView } from '@/services/user.service';
import type { AllClientsView, ClientService } from '@/services/client.service';
import type { OAuthService, OAuthConsentView } from '@/services/OAuth.service';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';

export class PagesUiController extends BaseController {
  constructor(
    private readonly userService: UserService,
    private readonly clientService: ClientService,
    private readonly oauthService: OAuthService,
  ) {
    super();
  }

  // ---------- SHARED ----------

  private renderPage(
    req: Request,
    res: Response,
    next: NextFunction,
    view: string,
    locals: Record<string, unknown>,
  ) {
    return this.handleRequest(
      req,
      res,
      next,
      async () => {
        res.render(view, {
          ...locals,
          error: typeof req.query.error === 'string' ? req.query.error : undefined,
          success: typeof req.query.success === 'string' ? req.query.success : undefined,
        });
      },
      { raw: true },
    );
  }

  // ---------- AUTH ----------

  renderSignupPage = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/auth/signup', {
      title: 'Sign up',
    });

  renderSigninPage = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/auth/signin', {
      title: 'Sign in',
    });

  renderEmailVerificationPage = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/auth/emailVerification', {
      title: 'Email Verification',
    });

  renderForgotPasswordPage = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/auth/forgot-password', {
      title: 'Forgot Password',
    });

  renderResetPasswordPage = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/auth/reset-password', {
      title: 'Reset Password',
      resetToken:
        typeof req.params.token === 'string'
          ? req.params.token
          : typeof req.query.token === 'string'
            ? req.query.token
            : undefined,
    });

  // ---------- OAUTH ----------

  renderOAuthConsentPage = (req: Request, res: Response, next: NextFunction) =>
    this.handleRequest(
      req,
      res,
      next,
      async () => {
        const requestId = req.query.request_id;
        if (typeof requestId !== 'string') {
          throw new AppError('Missing request_id', 400, ErrorCode.INVALID_INPUT);
        }

        const authReq = await this.oauthService.getAuthorizationRequest(requestId);
        const client = await this.clientService.getClient(authReq.clientId);

        res.render('pages/oauth/consent', {
          title: 'Authorize Application',
          requestId: authReq.id,
          clientId: authReq.clientId,
          clientName: client.name,
          clientDomain: client.domain,
          scope: authReq.scopes,
        });
      },
      { raw: true },
    );

  // ---------- APP ----------

  renderLandingPage = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/app/landing', {
      title: 'Landing Page',
    });

  renderAccountDashboard = (req: Request, res: Response, next: NextFunction) =>
    this.handleRequest(
      req,
      res,
      next,
      async () => {
        const userId = req.user.id;
        const user: UserView = await this.userService.get(userId);
        const oauthConsents: OAuthConsentView[] = await this.oauthService.getUserConsents(userId);
        const clients: AllClientsView[] = await this.clientService.getAllClientsForUser(userId);

        res.render('pages/app/dashboards/account', {
          title: 'Account Dashboard',
          user,
          createdAtFormatted: new Date(user.createdAt).toLocaleDateString(),
          updatedAtFormatted: new Date(user.updatedAt).toLocaleDateString(),
          oauthConsents,
          clients,
          error: typeof req.query.error === 'string' ? req.query.error : undefined,
          success: typeof req.query.success === 'string' ? req.query.success : undefined,
        });
      },
      { raw: true },
    );

  renderClientDashboard = (req: Request, res: Response, next: NextFunction) =>
    this.handleRequest(
      req,
      res,
      next,
      async () => {
        const client = await this.clientService.getClient(req.params.client_id);

        // Flash-style secret delivery
        const clientSecret = req.cookies?.__flash_client_secret;
        res.clearCookie('__flash_client_secret');

        res.render('pages/app/dashboards/client', {
          title: 'OAuth Dashboard',
          client: {
            ...client,
            client_secret: clientSecret,
          },
          createdAtFormatted: new Date(client.createdAt).toLocaleDateString(),
          updatedAtFormatted: new Date(client.updatedAt).toLocaleDateString(),
          revokedAtFormatted: client.revokedAt ? new Date(client.revokedAt).toLocaleDateString() : null,
          error: typeof req.query.error === 'string' ? req.query.error : undefined,
          success: typeof req.query.success === 'string' ? req.query.success : undefined,
        });
      },
      { raw: true },
    );

  renderAddClient = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/app/forms/add-client', {
      title: 'Add Client',
    });

  renderClientConfirmation = (req: Request, res: Response, next: NextFunction) => {
    this.renderPage(req, res, next, 'pages/app/confirm-action/client', {
      title: 'Confirm Client Action',
      clientId: req.params.client_id,
      name: req.query.name,
      action: req.params.action,
    });
  };

  renderAccountConfirmation = (req: Request, res: Response, next: NextFunction) => {
    this.renderPage(req, res, next, 'pages/app/confirm-action/account', {
      title: 'Confirm Account Action',
      action: req.params.action,
    });
  };
}
