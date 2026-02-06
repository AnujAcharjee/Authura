import prisma from '@/config/database';
import redis from '@/config/redis';
import { joseService } from '@/services/jose.service';
import { sessionService } from '@/services/session.service';
import { oauthService } from '@/services/OAuth.service';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';
import { AppCrypto } from '@/utils/crypto';
import { COOKIE_NAMES, setSessionCookies } from '@/utils/cookies';
import { CRYPTO_ALGORITHMS } from '@/utils/constant';
import type { Role, Scope } from '@/utils/constant';
import type { Request, Response, NextFunction } from 'express';

/**
 * AUTHENTICATE
 *  1. api: check for active session; if no return UNAUTHORIZED
 *  2. ssr: check for active session; if no refresh it if a valid id session present; else return UNAUTHORIZE
 *  3. client: check for client JWT access token issued by OAuth
 *
 * AUTHORIZE
 *  1. role: validate user for all the roles required (USER, DEVELOPER, ADMIN)
 */

export class Authentication {
  private static activeSession_RK = (sid: string) => `session:active:${sid}`;

  static async api(req: Request, _res: Response, next: NextFunction): Promise<void> {
    try {
      const asid = req.signedCookies[COOKIE_NAMES.ACTIVE_SESSION];

      if (!asid) {
        throw new AppError('Access session expired', 401, ErrorCode.ACTIVE_SESSION_EXPIRED);
      }

      const cached = await redis.get(
        Authentication.activeSession_RK(AppCrypto.hash(asid, CRYPTO_ALGORITHMS.sha256, 'hex')),
      );

      if (!cached) {
        throw new AppError('Invalid session', 401, ErrorCode.UNAUTHORIZED);
      }

      const { userId, roles, createdAt } = JSON.parse(cached);

      // verify
      if (!userId || !roles || !createdAt) {
        throw new AppError('Corrupted session', 401, ErrorCode.UNAUTHORIZED);
      }

      req.user = { id: userId, roles };

      return next();
    } catch (error) {
      next(error);
    }
  }

  static async ssr(req: Request, res: Response, next: NextFunction): Promise<void> {
    try {
      const asid = req.signedCookies[COOKIE_NAMES.ACTIVE_SESSION];
      const isid = req.signedCookies[COOKIE_NAMES.IDENTITY_SESSION];

      // Check for valid Active Session
      if (asid) {
        const cached = await redis.get(
          Authentication.activeSession_RK(AppCrypto.hash(asid, CRYPTO_ALGORITHMS.sha256, 'hex')),
        );

        if (cached) {
          const { userId, roles, createdAt } = JSON.parse(cached);

          if (userId && roles && createdAt) {
            req.user = { id: userId, roles };
            return next();
          }
        }
      }

      // fall through → try refresh
      if (isid) {
        const data = await sessionService.refreshActiveSession(isid);

        await setSessionCookies(res, null, data.activeSessId);

        req.user = {
          id: data.userId,
          roles: data.roles,
        };

        return next();
      }

      return res.redirect('/signin?error=Session expired');
    } catch (error) {
      return res.redirect('/signin?error=Authentication failed');
    }
  }

  static async client(req: Request, _res: Response, next: NextFunction): Promise<void> {
    try {
      const auth = req.headers.authorization;

      // get access token from client req header
      if (!auth?.startsWith('Bearer ')) {
        throw new AppError('Missing access token', 401, ErrorCode.UNAUTHORIZED);
      }

      const token = auth.slice(7);
      const payload = await joseService.verifyJwt(token, 'userinfo');

      if (String(payload.sub) !== String(req.params.id)) {
        throw new AppError('Forbidden', 403, ErrorCode.FORBIDDEN);
      }

      const scopes: Scope[] = oauthService.validateScopes(payload.scope);

      req.client = {
        id: String(payload.aud),
        userId: String(payload.sub),
        scopes,
      };

      next();
    } catch (error) {
      next(error);
    }
  }
}

export class Authorize {
  static role(roles: Role[]) {
    return (req: Request, _res: Response, next: NextFunction): void => {
      try {
        const userRoles = req.user?.roles ?? [];
        const allowed = roles.some((role) => userRoles.includes(role));
        if (!allowed) {
          throw new AppError('Forbidden - Insufficient permissions', 403, ErrorCode.FORBIDDEN);
        }

        next();
      } catch (error) {
        next(error);
      }
    };
  }

  static async clientOwnership(req: Request, _res: Response, next: NextFunction) {
    const clientId = req.params.client_id || req.body.client_id;

    if (!clientId) {
      throw new AppError('Client ID missing', 400, ErrorCode.INVALID_REQUEST);
    }

    const client = await prisma.oAuthClient.findFirst({
      where: {
        id: clientId,
        userId: req.user!.id,
      },
    });

    if (!client) {
      throw new AppError('Forbidden', 403, ErrorCode.FORBIDDEN);
    }

    next();
  }
}
