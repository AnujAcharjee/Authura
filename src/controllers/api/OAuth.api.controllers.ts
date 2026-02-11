import { BaseController } from '../base.controller.js';
import { CRYPTO_ALGORITHMS, SCOPES, type CryptoAlgorithm } from '../../utils/constant.js';
import type { Request, Response, NextFunction } from 'express';
import type { OAuthService } from '../../services/OAuth.service.js';
import type { AccountService } from '../../services/account.service.js';
import { AppError } from '../../utils/appError.js';
import { ErrorCode } from '../../utils/errorCodes.js';

/**
 * AUTHORIZE (GET) :
 *  1. validate & cache the req
 *  2. consent: true -> generate code -> redirect(redirect_uri)
 *  3. consent: false -> redirect(renderConsent page route + request_id)
 *
 * HANDLE CONSENT (POST):
 *  NOTE: browser blocks cross origin POST redirection, so we cant redirect directly from here
 *  1. consent -> request_id, decision
 *  2. get authorization request from cache
 *  3. decision: deny -> redirect(consent_result page + denied)
 *  4. decision: approve -> store consent -> redirect(consent_result page + approved + request_id)
 *
 * ISSUE TOKENS:
 *  1. get OIDC & Access tokens
 */

export class OAuthApiController extends BaseController {
  constructor(
    private oauthService: OAuthService,
    private accountService: AccountService,
  ) {
    super();
  }

  // ---------------- AUTHORIZE ----------------
  // 'OAuth/authorize' is NOT an API endpoint -> It is a browser flow endpoint

  authorizeClient = async (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(
      req,
      res,
      next,
      async () => {
        const algo = CRYPTO_ALGORITHMS[req.query.code_challenge_algo as CryptoAlgorithm];
        if (!algo) {
          throw new AppError('Invalid code_challenge_algo', 400, ErrorCode.INVALID_REQUEST);
        }

        const authReq = await this.oauthService.createAuthorizationRequest({
          responseType: String(req.query.response_type),
          clientId: String(req.query.client_id),
          redirectUri: String(req.query.redirect_uri),
          scope: String(req.query.scope || ''),
          state: typeof req.query.state === 'string' ? req.query.state : undefined,
          nonce: typeof req.query.nonce === 'string' ? req.query.nonce : undefined,
          codeChallenge: typeof req.query.code_challenge === 'string' ? req.query.code_challenge : undefined,
          codeChallengeAlgo: algo,
          requestId: req.requestId,
          userId: req.user!.id,
        });

        if (req.query.response_type !== 'code') {
          throw new AppError('Unsupported response_type', 400, ErrorCode.INVALID_REQUEST);
        }

        const hasConsent = await this.oauthService.hasConsent(
          authReq.userId,
          authReq.clientId,
          authReq.scopes,
        );

        if (!hasConsent) {
          return res.redirect(303, `/oauth/consent?request_id=${authReq.id}`);
        }

        const redirectURL = await this.oauthService.authorize(authReq);
        return res.redirect(303, redirectURL);
      },
      { raw: true },
    );
  };

  // ---------------- CONSENT SUBMIT ----------------

  handleConsentSubmit = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(
      req,
      res,
      next,
      async () => {
        const { request_id, decision } = req.body;

        const authReq = await this.oauthService.getAuthorizationRequest(request_id);
        if (!authReq) {
          throw new AppError('Authorization request not found', 404, ErrorCode.NOT_FOUND);
        }

        // DENY
        if (decision === 'deny') {
          const redirectURL = `/oauth/consent/denied?request_id=${encodeURIComponent(authReq.id)}`;
          return res.redirect(303, redirectURL);
        }

        // APPROVE
        if (decision === 'approve') {
          await this.oauthService.storeConsent(authReq.userId, authReq.clientId, authReq.scopes);
          const redirectURL = `/oauth/consent/approved?request_id=${encodeURIComponent(authReq.id)}`;
          return res.redirect(303, redirectURL);
        }

        throw new AppError('Invalid decision', 400, ErrorCode.INVALID_INPUT);
      },
      { raw: true },
    );
  };

  // ---------------- TOKEN ----------------

  issueTokens = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const tokens = await this.oauthService.issueTokens({
        grantType: req.body.grant_type,
        code: req.body.code,
        codeVerifier: req.body.code_verifier,
        clientId: req.body.client_id,
        clientSecret: req.body.client_secret,
      });

      return {
        data: tokens,
        message: 'Tokens issued successfully',
      };
    });
  };

  // ---------------- GET USER INFO ----------------

  getUserInfo = (req: Request, res: Response, next: NextFunction) => {
    this.handleRequest(req, res, next, async () => {
      const { userId, scopes } = req.client;

      const user = await this.accountService.get(userId);

      const data: Record<string, any> = {};
      if (scopes.includes(SCOPES.OPENID)) {
        data.sub = user.id;
      }
      if (scopes.includes(SCOPES.EMAIL)) {
        data.email = user.email;
        data.emailVerified = user.isEmailVerified ?? false;
      }
      if (scopes.includes(SCOPES.PROFILE)) {
        data.name = user.name;
      }
      if (scopes.includes(SCOPES.AVATAR)) {
        data.avatar = user.avatar;
      }

      return {
        data,
        message: 'User info sent successfully',
      };
    });
  };

  // ---------------- GET ALL CONSENTS ----------------

  getUserConsents = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      const data = await this.oauthService.getUserConsents(req.user.id);

      return {
        data,
        message: 'All user consents sent successfully',
        successRedirect: '/',
      };
    });
  };

  // ---------------- REVOKE CONSENT ----------------

  revokeConsent = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      await this.oauthService.revokeConsent(req.user.id, req.body.clientId);

      return {
        message: 'Consent revoked successfully',
        successRedirect: '/account',
      };
    });
  };

  // ---------------- REISSUE CONSENT ----------------

  reissueConsent = (req: Request, res: Response, next: NextFunction): void => {
    this.handleRequest(req, res, next, async () => {
      await this.oauthService.reissueConsent(req.user.id, req.body.clientId);

      return {
        message: 'Consent reissued successfully',
        successRedirect: '/account',
      };
    });
  };
}
