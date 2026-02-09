import prisma from '../config/database.js';
import redis from '../config/redis.js';
import { ENV } from '../config/env.js';
import { AppError } from '../utils/appError.js';
import { ErrorCode } from '../utils/errorCodes.js';
import { AppCrypto } from '../utils/crypto.js';
import { joseService, type JoseService } from '../services/jose.service.js';
import { SCOPES, CRYPTO_ALGORITHMS, type CryptoAlgorithm, type Scope } from '../utils/constant.js';
import { clientService, type ClientService } from '../services/client.service.js';

export interface AuthorizationRequest {
  id: string;
  userId: string;
  clientId: string;
  redirectUri: string;
  scopes: Scope[];
  state?: string;
  nonce?: string;
  codeChallenge?: string;
  codeChallengeAlgo?: CryptoAlgorithm;
  createdAt: number;
}

export type OAuthConsentView = {
  client: {
    id: string;
    domain: string;
  };
  scopes: string[];
  date: Date;
};

type AccessTokenPayload = {
  sub: string;
  scope: string;
};

type IdTokenPayload = {
  sub: string;
  nonce: string;
};

export class OAuthService {
  private readonly authCodeTTL = ENV.NODE_ENV === 'production' ? ENV.AUTH_CODE_EX : 300;
  private readonly authTokensTTL = ENV.NODE_ENV === 'production' ? ENV.AUTH_TOKENS_EX : '10m';
  private readonly authRequestTTL = ENV.NODE_ENV === 'production' ? ENV.AUTH_REQUEST_EX : 300;

  constructor(
    private joseService: JoseService,
    private clientService: ClientService,
  ) {}

  private authCodeKey = (hashedToken: string): string => `OAuth:authCode:${hashedToken}`;
  private authRequestKey = (id: string): string => `OAuth:req:${id}`;

  validateScopes(scope: string): Scope[] {
    if (typeof scope !== 'string') {
      throw new AppError('Scope should be of type string', 400, ErrorCode.INVALID_SCOPE);
    }

    const scopes: Scope[] = scope
      .split(' ')
      .map((s) => s.trim())
      .filter((s): s is Scope => Object.values(SCOPES).includes(s as Scope));

    if (scopes.length === 0)
      throw new AppError(`Insufficient scope: ${scope}`, 403, ErrorCode.INVALID_SCOPE);

    return scopes;
  }

  // ---------- CREATE AUTH REQUEST ----------

  async createAuthorizationRequest(input: {
    responseType: string;
    clientId: string;
    redirectUri: string;
    scope: string;
    state?: string;
    nonce?: string;
    codeChallenge?: string;
    codeChallengeAlgo?: CryptoAlgorithm;
    requestId: string;
    userId: string;
  }): Promise<AuthorizationRequest> {
    if (input.responseType !== 'code') {
      throw new AppError('Unsupported response type', 400, ErrorCode.INVALID_INPUT);
    }

    // client validation
    const client = await prisma.oAuthClient.findUnique({ where: { id: input.clientId } });
    if (!client || !client.isActive) {
      throw new AppError('Invalid client', 401, ErrorCode.INVALID_CLIENT);
    }

    // redirect uri validation
    if (!client.redirectURIs.includes(input.redirectUri)) {
      throw new AppError('Invalid redirect_uri', 400, ErrorCode.INVALID_REDIRECT_URI);
    }

    // scope validation
    const scopes: Scope[] = this.validateScopes(input.scope);

    // openid - nonce requirement check
    if (scopes.includes(SCOPES.OPENID) && !input.nonce) {
      throw new AppError('Nonce is required', 400, ErrorCode.INVALID_INPUT);
    }

    // enforce PKCE
    if (client.enforcePKCE && (!input.codeChallenge || !input.codeChallengeAlgo)) {
      throw new AppError('PKCE is required', 400, ErrorCode.PKCE_REQUIRED);
    }

    // Store req in cache
    const req: AuthorizationRequest = {
      id: input.requestId,
      userId: input.userId,
      clientId: client.id,
      redirectUri: input.redirectUri,
      scopes,
      state: input.state,
      nonce: input.nonce,
      codeChallenge: input.codeChallenge,
      codeChallengeAlgo: input.codeChallengeAlgo,
      createdAt: Date.now(),
    };

    await redis.set(this.authRequestKey(req.id), JSON.stringify(req), 'EX', this.authRequestTTL);
    return req;
  }

  // ---------- GET AUTH REQUEST ----------

  async getAuthorizationRequest(id: string): Promise<AuthorizationRequest> {
    const raw = await redis.get(this.authRequestKey(id));
    if (!raw) throw new AppError('Authorization request not found', 400, ErrorCode.INVALID_INPUT);
    return JSON.parse(raw);
  }

  // ---------- ISSUE AUTH CODE ----------

  async issueAuthorizationCode(req: AuthorizationRequest): Promise<string> {
    const code = AppCrypto.randomToken(32);
    const hash = AppCrypto.hash(code, CRYPTO_ALGORITHMS.sha256, 'hex');

    await redis.set(this.authCodeKey(hash), JSON.stringify(req), 'EX', this.authCodeTTL);
    await redis.del(this.authRequestKey(req.id));
    return code;
  }

  // ---------- CONSENT CHECK ----------

  async hasConsent(userId: string, clientId: string, scopes: string[]): Promise<boolean> {
    const consent = await prisma.oAuthConsent.findFirst({
      where: { userId, clientId, revokedAt: null },
    });

    return !!consent && scopes.every((s) => consent.scopes.includes(s));
  }

  // ---------- STORE CONSENT ----------

  async storeConsent(userId: string, clientId: string, scopes: string[]) {
    if (scopes.length === 0) return;

    await prisma.oAuthConsent.upsert({
      where: {
        userId_clientId: {
          userId,
          clientId,
        },
      },
      create: {
        userId,
        clientId,
        scopes,
      },
      update: {
        scopes,
        updatedAt: new Date(),
      },
    });
  }

  // ---------- TOKEN ----------

  async issueTokens(input: {
    grantType: string;
    code: string;
    codeVerifier?: string;
    clientId: string;
    clientSecret?: string;
  }) {
    if (input.grantType !== 'authorization_code') {
      throw new AppError('Unsupported grant_type', 400, ErrorCode.INVALID_INPUT);
    }

    // get cache
    const hash = AppCrypto.hash(input.code, CRYPTO_ALGORITHMS.sha256, 'hex');
    const raw = await redis.get(this.authCodeKey(hash));
    if (!raw) throw new AppError('Invalid grant', 400, ErrorCode.UNAUTHORIZED_CLIENT);

    const payload = JSON.parse(raw) as AuthorizationRequest;

    // Client validation
    if (payload.clientId !== input.clientId) {
      throw new AppError('Invalid client', 401, ErrorCode.INVALID_CLIENT);
    }

    const isValidClient = await this.clientService.verifyClient({
      clientId: input.clientId,
      clientSecret: input.clientSecret!,
    });
    if (!isValidClient) throw new AppError('Invalid client', 401, ErrorCode.INVALID_CLIENT);

    // PKCE validation
    if (payload.codeChallenge) {
      if (!payload.codeChallengeAlgo || !input.codeVerifier) {
        throw new AppError(
          'PKCE codeVerifier or codeChallengeAlgo missing.',
          400,
          ErrorCode.INVALID_INPUT,
          false,
        );
      }

      const ok = AppCrypto.verifyPKCE({
        codeVerifier: input.codeVerifier,
        codeChallenge: payload.codeChallenge,
        algorithm: payload.codeChallengeAlgo,
      });

      if (!ok) {
        throw new AppError('Invalid grant', 400, ErrorCode.UNAUTHORIZED_CLIENT);
      }
    }

    // delete cache
    await redis.del(this.authCodeKey(hash));

    const accessTokenPayload: AccessTokenPayload = {
      sub: payload.userId,
      scope: payload.scopes.join(' '), // 'openid profile email',
    };

    // generate tokens
    const accessToken = await this.joseService.signJwt(accessTokenPayload, {
      issuer: ENV.AUTH_ISSUER,
      audience: 'userinfo',
      expiresIn: this.authTokensTTL,
    });

    let idToken = undefined;
    // generate only if scopes contain openid
    if (payload.scopes.includes(SCOPES.OPENID)) {
      const idTokenPayload: IdTokenPayload = {
        sub: payload.userId,
        nonce: payload.nonce!,
      };

      idToken = await this.joseService.signJwt(idTokenPayload, {
        issuer: ENV.AUTH_ISSUER,
        audience: payload.clientId,
        expiresIn: this.authTokensTTL,
      });
    }

    return { accessToken, idToken };
  }

  // ---------- GET ALL CONSENTS FROM A USER ----------

  async getUserConsents(userId: string): Promise<OAuthConsentView[]> {
    const consents = await prisma.oAuthConsent.findMany({
      where: {
        userId,
      },
      select: {
        scopes: true,
        createdAt: true,
        client: {
          select: {
            id: true,
            domain: true,
          },
        },
      },
      orderBy: {
        createdAt: 'desc',
      },
    });

    return consents.map((consent) => ({
      client: {
        id: consent.client.id,
        domain: consent.client.domain,
      },
      scopes: consent.scopes,
      date: consent.createdAt,
    }));
  }
}

export const oauthService = new OAuthService(joseService, clientService);
