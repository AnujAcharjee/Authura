import { Request, Response, NextFunction } from 'express';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';
import { COOKIE_NAMES } from '@/utils/cookies';
import { sha256 } from '@/utils/crypto';
import { logger } from '@/config/logger';
import redis from '@/config/redis';
import { sessionService } from '@/services/session.service';
import prisma from '@/config/database';

const activeSession_RK = (sid: string) => `session:active:${sid}`;

export const ensureAuth = async (req: Request, res: Response, next: NextFunction): Promise<void> => {
  try {
    const asid = req.signedCookies[COOKIE_NAMES.ACTIVE_SESSION];

    if (!asid) {
      throw new AppError('Active session expired', 401, ErrorCode.ASESS_EXPIRED);
    }

    const cached = await redis.get(activeSession_RK(sha256(asid)));

    if (!cached) {
      throw new AppError('Invalid session', 401, ErrorCode.UNAUTHORIZED);
    }

    const { userId, role, createdAt } = JSON.parse(cached);

    // verify
    if (!userId || !role || !createdAt) {
      throw new AppError('Corrupted session', 401, ErrorCode.UNAUTHORIZED);
    }

    req.user = { userId, role };

    return next();
  } catch (error) {
    next(error);
  }
};

export const ensureRole = (roles: string[]) => {
  return (req: Request, res: Response, next: NextFunction): void => {
    try {
      if (!req.user?.role || !roles.includes(req.user.role)) {
        logger.warn({
          message: 'Insufficient permissions',
          context: 'AuthMiddleware.ensureRole',
          requiredRoles: roles,
          userRole: req.user?.role,
          userId: req.user?.userId,
        });

        throw new AppError('Forbidden - Insufficient permissions', 403, ErrorCode.FORBIDDEN);
      }

      next();
    } catch (error) {
      next(error);
    }
  };
};
