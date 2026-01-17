import { Request, Response, NextFunction } from 'express';
import { OAuth2Service } from '@/services/OAuth2.service';
import { BaseController } from '@/controllers/base.controller';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';

export class OAuth2Controller extends BaseController {
  constructor(private oauth2Service: OAuth2Service) {
    super();
  }

  // ---------------- REGISTER CLIENT ----------------
  registerClient = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { domain, client_type } = req.body;

      const data = await this.oauth2Service.registerClient({
        domain,
        clientType: client_type,
      });

      return {
        data,
        message: 'New client registered successfully',
      };
    });
  };

  // -------------------- UPDATE REDIRECT URIS -------------------
  updateRedirects = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { redirect_uri, action, client_id, client_secret } = req.body;

      const data = await this.oauth2Service.updateRedirects({
        redirectUri: redirect_uri,
        action,
        clientId: client_id,
        clientSecret: client_secret,
      });

      return {
        data,
        message: `Redirect URI ${action} successfully`,
      };
    });
  };

  // ---------------- JWKS ----------------
  getJwks = (_req: Request, res: Response): void => {
    const jwks = this.oauth2Service.getJwks();
    res.json(jwks);
  };

  // ---------------- AUTHORIZE ----------------
  // 'OAuth/authorize' is NOT an API endpoint -> It is a browser flow endpoint
  authorizeClient = async (req: Request, res: Response, next: NextFunction) => {
    try {
      const {
        response_type,
        client_id,
        redirect_uri,
        scope,
        state,
        nonce,
        code_challenge,
        code_challenge_method,
      } = req.query;

      const userId = req.user?.userId;
      if (!userId) {
        throw new AppError('User not authenticated', 401, ErrorCode.UNAUTHORIZED);
      }

      const authCode = await this.oauth2Service.authorizeClient({
        responseType: String(response_type),
        clientId: String(client_id),
        redirectUri: String(redirect_uri),
        scope: String(scope),
        nonce: nonce ? String(nonce) : undefined,
        codeChallenge: code_challenge ? String(code_challenge) : undefined,
        codeChallengeMethod: code_challenge_method as 'S256' | undefined,
        userId,
      });

      // Set CODE and STATE in  redirect url
      const redirectURL = new URL(String(redirect_uri));
      redirectURL.searchParams.set('code', authCode);
      redirectURL.searchParams.set('state', String(state));

      // redirect
      res.redirect(redirectURL.toString());
    } catch (error) {
      next(error);
    }
  };

  // ---------------- TOKEN ----------------
  issueTokens = (req: Request, res: Response, next: NextFunction): void => {
    this.handelRequest(req, res, next, async () => {
      const { grant_type, code, code_verifier, client_id, client_secret } = req.body;

      const data = await this.oauth2Service.issueTokens({
        grantType: grant_type,
        code,
        codeVerifier: code_verifier,
        clientId: client_id,
        clientSecret: client_secret,
      });

      return {
        data,
        message: 'Tokens issued successfully',
      };
    });
  };
}
