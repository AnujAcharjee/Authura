import prisma from '@/config/database';
import redis from '@/config/redis';
import { AppError } from '@/utils/appError';
import { ENV } from '@/config/env';
import { ErrorCode } from '@/utils/errorCodes';
import type { Role } from '@/utils/constant';

interface ProfileUpdateInput {
  name?: string;
  avatar?: string;
  roles?: Role[];
  email?: string;
  gender?: string;
  updatesAt: Date;
}

export type UserView = {
  id: string;
  name: string;
  avatar: string | null;
  email: string;
  gender: string;
  roles: Role[];
  isEmailVerified: boolean;
  emailVerifiedAt: Date | null;
  mfaEnabled: boolean;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
};

export class UserService {
  private readonly profileCacheEX = ENV.NODE_ENV == 'production' ? ENV.PROFILE_CACHE_EX : 15 * 60;

  private profileKey = (userId: string): string => `profile:${userId}`;

  async get(userId: string): Promise<UserView> {
    const cachedUser = await redis.get(this.profileKey(userId));

    if (cachedUser) {
      return JSON.parse(cachedUser) as UserView;
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        name: true,
        avatar: true,
        email: true,
        gender: true,
        roles: true,
        isEmailVerified: true,
        emailVerifiedAt: true,
        mfaEnabled: true,
        isActive: true,
        createdAt: true,
        updatedAt: true,
      },
    });

    if (!user) {
      throw new AppError('User not found', 404, ErrorCode.NOT_FOUND);
    }

    await redis.set(this.profileKey(userId), JSON.stringify(user), 'EX', this.profileCacheEX);
    return user;
  }

  async update(userId: string, updates: ProfileUpdateInput): Promise<UserView> {
    if (Object.keys(updates).length === 0) {
      throw new AppError('No updates provided', 400, ErrorCode.INVALID_GRANT);
    }

    const user = await prisma.user
      .update({
        where: { id: userId },
        data: {
          ...(updates.name !== undefined && { name: updates.name }),
          ...(updates.avatar !== undefined && { avatar: updates.avatar }),
        },
        select: {
          id: true,
          name: true,
          avatar: true,
          email: true,
          gender: true,
          roles: true,
          isEmailVerified: true,
          emailVerifiedAt: true,
          mfaEnabled: true,
          isActive: true,
          createdAt: true,
          updatedAt: true,
        },
      })
      .catch(() => null);

    if (!user) {
      throw new AppError('User not found', 404, ErrorCode.NOT_FOUND);
    }

    // Invalidate cache
    await redis.del(this.profileKey(userId));
    return user;
  }

  async deactivate(userId: string): Promise<void> {
    const result = await prisma.user.updateMany({
      where: {
        id: userId,
        isActive: true,
      },
      data: {
        isActive: false,
        updatedAt: new Date(),
      },
    });

    if (result.count === 0) {
      throw new AppError('User already deactivated or not found', 400, ErrorCode.INVALID_REQUEST);
    }

    await prisma.identitySession.updateMany({
      where: { userId, revoked: false },
      data: { revoked: true, lastUsedAt: new Date() },
    });

    await redis.del(this.profileKey(userId));
  }

  async activate(userId: string): Promise<void> {
    const result = await prisma.user.updateMany({
      where: {
        id: userId,
        isActive: false,
      },
      data: {
        isActive: true,
        updatedAt: new Date(),
      },
    });

    if (result.count === 0) {
      throw new AppError('User already active or not found', 400, ErrorCode.INVALID_REQUEST);
    }

    await redis.del(this.profileKey(userId));
  }

  async delete(userId: string): Promise<void> {
    // ensure user exists
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true },
    });

    if (!user) {
      throw new AppError('User not found', 404, ErrorCode.NOT_FOUND);
    }

    // transactional delete
    await prisma.$transaction([
      prisma.identitySession.deleteMany({ where: { userId } }),
      prisma.oAuthClient.deleteMany({ where: { userId } }),
      prisma.user.delete({ where: { id: userId } }),
    ]);

    await redis.del(this.profileKey(userId));
  }
}

export const userService = new UserService();
