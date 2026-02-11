import type { Request, Response, NextFunction } from 'express';
import { BaseController } from '../../controllers/base.controller.js';
import type { AccountService, AccountView } from '../../services/account.service.js';
import type { AllClientsView, ClientService } from '../../services/client.service.js';
import type { OAuthService, OAuthConsentView } from '../../services/OAuth.service.js';
import { AppError } from '../../utils/appError.js';
import { ErrorCode } from '../../utils/errorCodes.js';
import { SERVER_URL } from '../../utils/constant.js';
import { ENV } from '../../config/env.js';

export class PagesUiController extends BaseController {
  constructor(
    private readonly accountService: AccountService,
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
          serverUrl: SERVER_URL,
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
      email: typeof req.query.email === 'string' ? req.query.email : '',
    });

  renderForgotPasswordPage = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/auth/forgot-password', {
      title: 'Forgot Password',
    });

  renderResetPasswordPage = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/auth/reset-password', {
      title: 'Reset Password',
      resetToken:
        typeof req.params.token === 'string' ? req.params.token
        : typeof req.query.token === 'string' ? req.query.token
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
          serverUrl: SERVER_URL,
          requestId: authReq.id,
          clientId: authReq.clientId,
          clientName: client.name,
          clientDomain: client.domain,
          scopes: authReq.scopes,
        });
      },
      { raw: true },
    );

  /**
   * This page is shown after the user submits the consent form,
   * to authorize and show a friendly message before redirecting to the client app.
   */
  renderOAuthConsentResultPage = (req: Request, res: Response, next: NextFunction) =>
    this.handleRequest(
      req,
      res,
      next,
      async () => {
        const result = req.params.result;

        const requestId = req.query.request_id;
        if (typeof requestId !== 'string') {
          throw new AppError('Missing request_id', 400, ErrorCode.INVALID_INPUT);
        }

        const authReq = await this.oauthService.getAuthorizationRequest(requestId);
        if (!authReq) {
          throw new AppError('Authorization request not found', 404, ErrorCode.NOT_FOUND);
        }

        const client = await this.clientService.getClient(authReq.clientId);

        let redirectURL: string;

        if (result === 'approved') {
          // Issue code
          redirectURL = await this.oauthService.authorize(authReq);
        } else if (result === 'denied') {
          // Build redirect with error
          this.oauthService.deleteAuthorizationRequest(authReq.id);
          const redirect = new URL(authReq.redirectUri);
          redirect.searchParams.set('error', 'access_denied');

          if (authReq.state) {
            redirect.searchParams.set('state', authReq.state);
          }

          redirectURL = redirect.toString();
        } else {
          throw new AppError('Invalid result type', 400, ErrorCode.INVALID_INPUT);
        }

        res.render('pages/oauth/consent-result', {
          title: 'Authorization Result',
          serverUrl: SERVER_URL,
          continueUrl: redirectURL,
          clientName: client.name,
          isDenied: result === 'denied',
        });
      },
      { raw: true },
    );

  // ---------- APP ----------

  renderLandingPage = (req: Request, res: Response, next: NextFunction) =>
    this.renderPage(req, res, next, 'pages/app/landing', {
      title: 'Landing Page',
      docUrl: ENV.APP_DOC_URL,
    });

  renderAccountDashboard = (req: Request, res: Response, next: NextFunction) =>
    this.handleRequest(
      req,
      res,
      next,
      async () => {
        const userId = req.user.id;
        const user: AccountView = await this.accountService.get(userId);
        const oauthConsents: OAuthConsentView[] = await this.oauthService.getUserConsents(userId);
        const clients: AllClientsView[] = await this.clientService.getAllClientsForUser(userId);

        res.render('pages/app/dashboards/account', {
          title: 'Account Dashboard',
          serverUrl: SERVER_URL,
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
          serverUrl: SERVER_URL,
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
      clientId: typeof req.query.clientId === 'string' ? req.query.clientId : undefined,
      clientDomain: typeof req.query.clientDomain === 'string' ? req.query.clientDomain : undefined,
    });
  };
}
