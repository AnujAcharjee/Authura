import prisma from '@/config/database';
import redis from '@/config/redis';
import bcrypt from 'bcrypt';
import fs from 'fs';
import jwt from 'jsonwebtoken';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';
import { randomToken, sha256, verifyPKCE, createPublicJWK } from '@/utils/crypto';
import { ENV } from '@/config/env';
import {
  RegisterClientResult,
  RegisterClientParams,
  UpdateRedirectsParams,
  AuthorizeClientParams,
  IssueTokensParams,
  IssueTokensResult,
  CachedClient,
} from '@/@types/OAuth2.types';

enum Scope {
  OPENID = 'openid',
  PROFILE = 'profile',
  EMAIL = 'email',
  AVATAR = 'avatar',
}

export class OAuth2Service {
  private authCodeExpiry = ENV.NODE_ENV === 'production' ? ENV.AUTH_CODE_EX : 300;
  private accessTokenExpiry = ENV.NODE_ENV === 'production' ? ENV.ACCESS_TOKEN_EX : 600;
  private jwtPrivateKey = fs.readFileSync(process.env.JWT_PRIVATE_KEY_PATH!, 'utf8');
  private jwtPublicKey = fs.readFileSync(process.env.JWT_PUBLIC_KEY_PATH!, 'utf8');
  private keyId = 'authura-key-1';

  private authCode_RK = (hashedToken: string): string => `OAuth:authCode:${hashedToken}`;

  private isValidDomain(slug: string): boolean {
    if (!slug) return false;

    const normalized = slug.trim().toLowerCase();

    // Length rules (DNS label rules)
    if (normalized.length < 3 || normalized.length > 63) {
      return false;
    }

    // Only lowercase letters, numbers, hyphens
    if (!/^[a-z0-9-]+$/.test(normalized)) {
      return false;
    }

    // Cannot start or end with hyphen
    if (normalized.startsWith('-') || normalized.endsWith('-')) {
      return false;
    }

    // Must start with a letter (Auth0 rule – optional but recommended)
    if (!/^[a-z]/.test(normalized)) {
      return false;
    }

    // Must not contain consecutive hyphens
    if (normalized.includes('--')) {
      return false;
    }

    // Reserved / blocked names
    const reserved = new Set([
      'www',
      'api',
      'admin',
      'auth',
      'login',
      'oauth',
      'id',
      'internal',
      'local',
      'localhost',
      'root',
      'support',
      'help',
    ]);

    if (reserved.has(normalized)) {
      return false;
    }

    return true;
  }

  private validateRedirectURI(uri: string): string {
    try {
      let url = new URL(uri);

      // Enforce HTTPS (except localhost)
      if (url.protocol !== 'https:' && url.hostname !== 'localhost' && ENV.NODE_ENV === 'production') {
        throw new AppError('redirect_uri must use HTTPS', 400, ErrorCode.INVALID_REDIRECT_URI);
      }

      // Prevent wildcards
      if (uri.includes('*')) {
        throw new AppError('Wildcard redirect URIs are not allowed', 400, ErrorCode.INVALID_REDIRECT_URI);
      }

      return url.toString();
    } catch (error) {
      throw new AppError('Invalid redirect URI format', 400, ErrorCode.INVALID_REDIRECT_URI);
    }
  }

  // -------- REGISTER CLIENT --------
  async registerClient({ domain, clientType }: RegisterClientParams): Promise<RegisterClientResult> {
    if (!domain) {
      throw new AppError('Missing required field', 400, ErrorCode.MISSING_REQUIRED_FIELD, false);
    }

    // Validate domain
    if (!this.isValidDomain(domain)) {
      throw new AppError('Invalid domain', 400, ErrorCode.INVALID_DOMAIN);
    }

    const clientSecret = randomToken(48);
    const clientSecretHash = await bcrypt.hash(clientSecret, 12);

    const client = await prisma.oAuthClient.create({
      data: {
        domain,
        clientSecretHash,
        clientType,
        enforcePKCE: true,
        isActive: true,
      },
    });

    return {
      clientId: client.id,
      clientSecret,
    };
  }

  // -------- UPDATE REDIRECT URIS --------
  async updateRedirects({ redirectUri, action, clientId, clientSecret }: UpdateRedirectsParams) {
    const client = await prisma.oAuthClient.findUnique({
      where: { id: clientId },
      select: {
        clientSecretHash: true,
        redirectURIs: true,
      },
    });

    if (!client || !client.clientSecretHash) {
      throw new AppError('Invalid client', 401, ErrorCode.INVALID_CLIENT);
    }

    const isValidSecret = bcrypt.compare(clientSecret, client.clientSecretHash);
    if (!isValidSecret) throw new AppError('Invalid client', 401, ErrorCode.INVALID_CLIENT);

    const existing = client.redirectURIs ?? [];
    const uri = this.validateRedirectURI(redirectUri);

    let updatedRedirectUris: string[];

    if (action === 'add') {
      if (existing.includes(uri)) {
        return existing; // idempotent
      }
      updatedRedirectUris = [...existing, uri];
    } else if (action === 'remove') {
      updatedRedirectUris = existing.filter((u) => u !== uri);

      if (updatedRedirectUris.length === existing.length) {
        throw new AppError('Redirect URI not found', 404, ErrorCode.NOT_FOUND);
      }
    } else {
      throw new AppError('Invalid action', 400, ErrorCode.INVALID_INPUT);
    }

    await prisma.oAuthClient.update({
      where: { id: clientId },
      data: { redirectURIs: updatedRedirectUris },
    });

    return {
      uri,
      action,
    };
  }

  // -------- GET JWKS --------
  getJwks() {
    const jwk = createPublicJWK(this.jwtPublicKey);

    return {
      keys: [
        {
          ...jwk,
          use: 'sig',
          alg: 'RS256',
          kid: this.keyId,
        },
      ],
    };
  }

  // -------- AUTHORIZE --------
  async authorizeClient({
    responseType,
    clientId,
    redirectUri,
    scope,
    nonce,
    codeChallenge,
    codeChallengeMethod,
    userId,
  }: AuthorizeClientParams): Promise<string> {
    if (responseType !== 'code') {
      throw new AppError('Invalid responseType', 400, ErrorCode.INVALID_INPUT);
    }

    // Validate client
    const client = await prisma.oAuthClient.findUnique({ where: { id: clientId } });

    if (!client || !client.isActive || !client.clientSecretHash) {
      throw new AppError('Invalid client', 401, ErrorCode.INVALID_CLIENT);
    }

    // Validate Redirect URI
    if (!client.redirectURIs.includes(redirectUri)) {
      throw new AppError('Invalid redirect_uri', 400, ErrorCode.INVALID_REDIRECT_URI);
    }

    // Validate Scope
    const requestedScopes = scope.split(' ');
    for (const s of requestedScopes) {
      if (!Object.values(Scope).includes(s as Scope)) {
        throw new AppError(`Invalid scope: ${s}`, 400, ErrorCode.INVALID_SCOPE);
      }
    }

    if (scope.toString().includes('openid') && !nonce) {
      throw new AppError('nonce required for OpenID Connect', 400, ErrorCode.INVALID_REQUEST);
    }

    // PKCE enforcement
    if (client.enforcePKCE && (!codeChallenge || codeChallengeMethod !== 'S256')) {
      throw new AppError('PKCE required', 400, ErrorCode.PKCE_REQUIRED);
    }

    const authCode = randomToken(32);
    const hashedAuthCode = sha256(authCode);

    const payload: CachedClient = {
      userId,
      clientId: client.id,
      domain: client.domain,
      clientSecretHash: client.clientSecretHash,
      scope: requestedScopes,
      codeChallenge,
      codeChallengeMethod,
      nonce: nonce ? nonce : undefined,
      authTime: Math.floor(Date.now() / 1000),
    };

    redis.set(this.authCode_RK(hashedAuthCode), JSON.stringify(payload), 'EX', this.authCodeExpiry);

    return authCode;
  }

  // -------- TOKEN --------
  async issueTokens({
    grantType,
    code,
    codeVerifier,
    clientId,
    clientSecret,
  }: IssueTokensParams): Promise<IssueTokensResult> {
    if (grantType !== 'authorization_code') {
      throw new AppError('Invalid grant_type', 400, ErrorCode.INVALID_INPUT);
    }

    // get cached data
    const authCodeHash = sha256(code);

    const rawPayload = await redis.get(this.authCode_RK(authCodeHash));

    if (!rawPayload) {
      throw new AppError('Invalid or expired authorization code', 400, ErrorCode.INVALID_GRANT);
    }

    const payload = JSON.parse(rawPayload) as CachedClient;

    // Validate client
    const isValidSecret = await bcrypt.compare(clientSecret, payload.clientSecretHash);

    if (payload.clientId !== clientId || !isValidSecret) {
      throw new AppError('Invalid client', 401, ErrorCode.INVALID_CLIENT);
    }

    // PKCE verification
    const isValidPKCE = verifyPKCE({
      codeVerifier,
      codeChallenge: payload.codeChallenge,
      method: payload.codeChallengeMethod,
    });

    if (!isValidPKCE) {
      throw new AppError('PKCE verification failed', 400, ErrorCode.INVALID_GRANT);
    }

    // delete cache
    await redis.del(this.authCode_RK(authCodeHash));

    const now = Math.floor(Date.now() / 1000);

    // Issue Access Token
    const accessToken = jwt.sign(
      {
        iss: ENV.OAUTH_ISSUER,
        aud: payload.clientId,
        sub: payload.userId,
        scope: payload.scope,
        iat: now,
        exp: now + this.accessTokenExpiry,
      },
      this.jwtPrivateKey,
      {
        algorithm: 'RS256',
        keyid: this.keyId,
      },
    );

    // Issue ID Token
    const idToken = jwt.sign(
      {
        iss: ENV.OAUTH_ISSUER,
        aud: payload.clientId,
        sub: payload.userId,
        iat: now,
        exp: now + this.accessTokenExpiry,
        auth_time: payload.authTime,
        nonce: payload.nonce,
      },
      this.jwtPrivateKey,
      {
        algorithm: 'RS256',
        keyid: this.keyId,
      },
    );

    return {
      accessToken,
      idToken,
    };
  }
}
