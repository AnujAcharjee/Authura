import redis from '@/config/redis';
import { ENV } from '@/config/env';
import prisma from '@/config/database';
import { randomToken, sha256 } from '@/utils/crypto';
import { UserRole } from '@/config/database';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';

class SessionService {
  private activeSessionExpiry: number;
  private identitySessionExpiry: number;

  constructor() {
    this.activeSessionExpiry = ENV.NODE_ENV === 'development' ? 15 * 60 : ENV.ACTIVE_SESSION_EX;
    this.identitySessionExpiry = ENV.NODE_ENV === 'development' ? 30 * 24 * 60 * 60 : ENV.IDENTITY_SESSION_EX;
  }

  // Redis Key
  private activeSession_RK = (asidHash: string) => `session:active:${asidHash}`;

  // Long lived
  async createIdentitySession(userId: string): Promise<string> {
    if (!userId) {
      throw new AppError(
        'Invariant violation: userId is required to create identity session',
        500,
        ErrorCode.INTERNAL_SERVER_ERROR,
        false,
      );
    }

    const MAX_RETRIES = 5;

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      const isid = randomToken(32);
      const isidHash = sha256(isid);

      try {
        await prisma.identitySession.create({
          data: {
            token: isidHash,
            userId,
            issuedAt: new Date(),
            lastUsedAt: new Date(),
            expiresAt: new Date(Date.now() + this.identitySessionExpiry * 1000),
          },
        });

        return isid;
      } catch (err: any) {
        // Prisma unique constraint violation
        if (err.code === 'P2002') {
          continue; // retry with a new token
        }

        throw err;
      }
    }

    throw new Error('Failed to create unique identity session');
  }

  // Short lived
  async createActiveSession(userId: string, role: UserRole): Promise<string> {
    if (!userId || !role) {
      throw new AppError(
        'Invariant violation: userId & role is required',
        500,
        ErrorCode.INTERNAL_SERVER_ERROR,
        false,
      );
    }

    const MAX_RETRIES = 5;

    for (let attempt = 0; attempt < MAX_RETRIES; attempt++) {
      const asid = randomToken(32);
      const asidHash = sha256(asid);

      const payload = {
        userId,
        role,
        createdAt: Date.now(),
      };

      const result = await redis.set(
        this.activeSession_RK(asidHash),
        JSON.stringify(payload),
        'EX',
        this.activeSessionExpiry,
        'NX',
      );

      if (result === 'OK') {
        return asid;
      }
    }

    throw new Error('Failed to create unique active session');
  }

  // Revocation
  async revokeIdentitySession(isid: string) {
    if (!isid) {
      throw new AppError(
        'Invariant violation: isid is required',
        500,
        ErrorCode.INTERNAL_SERVER_ERROR,
        false,
      );
    }

    const isidHash = sha256(isid);
    await prisma.identitySession.updateMany({
      where: {
        token: isidHash,
        revoked: false,
      },
      data: {
        revoked: true,
        lastUsedAt: new Date(),
      },
    });
  }

  async revokeActiveSession(asid: string) {
    if (!asid) {
      throw new AppError(
        'Invariant violation: asid is required',
        500,
        ErrorCode.INTERNAL_SERVER_ERROR,
        false,
      );
    }

    const asidHash = sha256(asid);
    await redis.del(this.activeSession_RK(asidHash));
  }
}

export const sessionService = new SessionService();
