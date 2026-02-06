import { BaseController } from '@/controllers/base.controller';
import { CRYPTO_ALGORITHMS, SCOPES, type CryptoAlgorithm } from '@/utils/constant';
import type { Request, Response, NextFunction } from 'express';
import type { OAuthService } from '@/services/OAuth.service';
import type { UserService } from '@/services/user.service';

/**
 * AUTHORIZE :
 *  1. validate & cache the req
 *  2. consent: true -> generate code -> redirect(redirect_uri)
 *  3. consent: false -> redirect(renderConsent page route + request_id)
 *
 * HANDLE CONSENT:
 *  1. get -> request_id, decision
 *  2. get authorization request from cache
 *  3. decision: false -> redirect back to client with error=access_denied (redirectUri)
 *  4. decision: true -> store consent in DB -> authorize client (authCode) -> redirect to client url
 *
 * ISSUE TOKENS:
 *  1. get tokens and return
 */

export class OAuthApiController extends BaseController {
  constructor(
    private oauthService: OAuthService,
    private userService: UserService,
    // private clientService: ClientService,
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
        const authReq = await this.oauthService.createAuthorizationRequest({
          responseType: String(req.query.response_type),
          clientId: String(req.query.client_id),
          redirectUri: String(req.query.redirect_uri),
          scope: String(req.query.scope || ''),
          state: typeof req.query.state === 'string' ? req.query.state : undefined,
          nonce: typeof req.query.nonce === 'string' ? req.query.nonce : undefined,
          codeChallenge: typeof req.query.code_challenge === 'string' ? req.query.code_challenge : undefined,
          codeChallengeAlgo: CRYPTO_ALGORITHMS[req.query.code_challenge_algo as CryptoAlgorithm],
          requestId: req.requestId,
          userId: req.user!.id,
        });

        const hasConsent = await this.oauthService.hasConsent(
          authReq.userId,
          authReq.clientId,
          authReq.scopes,
        );

        if (!hasConsent) {
          return res.redirect(`/oauth/consent?request_id=${authReq.id}`);
        }

        const code = await this.oauthService.issueAuthorizationCode(authReq);
        const redirectURL = new URL(authReq.redirectUri);
        redirectURL.searchParams.set('code', code);
        if (authReq.state) redirectURL.searchParams.set('state', authReq.state);

        return res.redirect(redirectURL.toString());
      },
      { raw: true },
    );
  };

  // ---------------- CONSENT SUBMIT ----------------

  // TODO: Show some UI message or redirect user back to client; for now neither happens
  handleConsentSubmit = (req: Request, res: Response, next: NextFunction) => {
    return this.handleRequest(
      req,
      res,
      next,
      async () => {
        const { request_id, decision } = req.body;
        const authReq = await this.oauthService.getAuthorizationRequest(request_id);

        if (decision === 'deny' || decision !== 'approve') {
          const redirect = new URL(authReq.redirectUri);
          redirect.searchParams.set('error', 'access_denied');
          if (authReq.state) redirect.searchParams.set('state', authReq.state);
          return res.redirect(redirect.toString());
        }

        await this.oauthService.storeConsent(authReq.userId, authReq.clientId, authReq.scopes);

        const code = await this.oauthService.issueAuthorizationCode(authReq);
        const redirect = new URL(authReq.redirectUri);
        redirect.searchParams.set('code', code);
        if (authReq.state) redirect.searchParams.set('state', authReq.state);

        return res.redirect(redirect.toString());
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

      const user = await this.userService.get(userId);

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
}
