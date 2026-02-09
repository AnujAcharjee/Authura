import bcrypt from 'bcrypt';
import prisma from '../config/database.js';
import redis from '../config/redis.js';
import { AppError } from '../utils/appError.js';
import { ErrorCode } from '../utils/errorCodes.js';
import { AppCrypto } from '../utils/crypto.js';
import { emailService } from '../services/email.service.js';
import { ENV } from '../config/env.js';
import { sessionService } from '../services/session.service.js';
import { ROLES, GENDERS, AUTH_PROVIDERS, CRYPTO_ALGORITHMS, type Role, type Gender } from '../utils/constant.js';

export class AuthService {
  private readonly emailVerificationTokenExpiry =
    ENV.NODE_ENV === 'production' ? ENV.EMAIL_VERIFICATION_TOKEN_EX : 24 * 60 * 60;
  private readonly signinFailCountExpiry =
    ENV.NODE_ENV === 'production' ? ENV.SIGN_IN_FAIL_COUNT_EX : 24 * 60 * 60;
  private readonly signinVerificationTokenExpiry =
    ENV.NODE_ENV === 'production' ? ENV.SIGN_VERIFICATION_TOKEN_EX : 24 * 60 * 60;
  private readonly signinLockUntil = ENV.NODE_ENV === 'production' ? ENV.SIGNIN_LOCK_UNTIL : 6 * 60 * 60;
  private readonly maxSigninFailures = ENV.NODE_ENV === 'production' ? ENV.MAX_SIGNIN_FAILURES : 20;
  private readonly resetPasswordExpiry = ENV.NODE_ENV === 'production' ? ENV.RESET_PASSWORD_EX : 60 * 60;

  // Redis keys
  private emailVerificationTokenKey = (hashedToken: string): string => `email-verify:token:${hashedToken}`;
  private emailVerificationUserKey = (userId: string): string => `email-verify:user:${userId}`;
  private signinFailCountKey = (userId: string) => `signin:fail-count:${userId}`;
  private signinVerificationTokenKey = (hashedToken: string) => `signin:verify-token:${hashedToken}`;
  private resetPasswordTokenKey = (hashedToken: string) => `reset-password:${hashedToken}`;

  // REDIS methods
  private async setVerificationTokenInRedis(token: string, userId: string, roles: Role[]): Promise<void> {
    await redis
      .multi()
      .set(
        this.emailVerificationTokenKey(token),
        JSON.stringify({ userId, roles }),
        'EX',
        this.emailVerificationTokenExpiry,
      )
      .set(this.emailVerificationUserKey(userId), token, 'EX', this.emailVerificationTokenExpiry)
      .exec();
  }

  private async delVerificationTokenInRedis(tokenKey: string, userKey: string): Promise<void> {
    await redis.multi().del(tokenKey).del(userKey).exec();
  }

  // SIGNUP
  async signup(input: { name: string; email: string; gender: Gender; password: string }): Promise<{
    id: string;
    email: string;
    name: string;
    roles: Role[];
    createdAt: Date;
  }> {
    const { name, email, gender, password } = input;

    const isExistingUser = await prisma.user.findUnique({ where: { email }, select: { id: true } });
    if (isExistingUser) {
      throw new AppError('Email already exists', 400, ErrorCode.ALREADY_EXISTS);
    }

    if (!Object.values(GENDERS).includes(gender)) {
      throw new AppError('Invalid gender value', 400, ErrorCode.INVALID_REQUEST);
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        gender,
        email,
        password: hashPassword,
        roles: [ROLES.USER],
        provider: AUTH_PROVIDERS.DEFAULT,
      },
      select: {
        id: true,
        email: true,
        name: true,
        roles: true,
        createdAt: true,
      },
    });

    const verificationToken = AppCrypto.randomToken(32);
    const hashedVerificationToken = AppCrypto.hash(verificationToken, CRYPTO_ALGORITHMS.sha256, 'hex');

    await this.setVerificationTokenInRedis(hashedVerificationToken, user.id, user.roles);

    // Send email verification email
    emailService.sendVerificationEmail(email, name, verificationToken);

    return user;
  }

  // VERIFY EMAIL
  async verifyEmail(token: string): Promise<{
    identitySessionId: string;
    activeSessionId: string;
  }> {
    const hashedToken = AppCrypto.hash(token, CRYPTO_ALGORITHMS.sha256, 'hex');

    const cached = await redis.get(this.emailVerificationTokenKey(hashedToken));
    if (!cached) {
      throw new AppError('Invalid or expired verification token', 400, ErrorCode.INVALID_TOKEN);
    }

    const { userId, roles } = JSON.parse(cached);

    const updated = await prisma.user.updateMany({
      where: {
        id: userId,
        isEmailVerified: false,
      },
      data: {
        isEmailVerified: true,
        emailVerifiedAt: new Date(),
      },
    });

    // delete tokens
    const userKey = this.emailVerificationUserKey(userId);
    await this.delVerificationTokenInRedis(token, userKey);

    if (updated.count === 0) {
      throw new AppError('Email already verified', 400, ErrorCode.INVALID_TOKEN);
    }

    // create session
    const identitySessionId = await sessionService.createIdentitySession(userId);
    const activeSessionId = await sessionService.createActiveSession(userId, roles);

    return { identitySessionId, activeSessionId };
  }

  // RESEND VERIFICATION EMAIL
  async resendVerificationEmail(email: string): Promise<void> {
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        isEmailVerified: true,
        email: true,
        name: true,
        roles: true,
      },
    });

    if (!user || user.isEmailVerified) {
      return;
    }

    const userKey = this.emailVerificationUserKey(user.id);
    const existingToken = await redis.get(userKey);

    if (existingToken) {
      const tokenKey = this.emailVerificationTokenKey(existingToken);
      this.delVerificationTokenInRedis(tokenKey, userKey);
    }

    const verificationToken = AppCrypto.randomToken(32);
    const hashedVerificationToken = AppCrypto.hash(verificationToken, CRYPTO_ALGORITHMS.sha256, 'hex');

    await this.setVerificationTokenInRedis(hashedVerificationToken, user.id, user.roles);

    // Send email verification email
    emailService.sendVerificationEmail(user.email, user.name, verificationToken);
  }

  // SIGNIN
  async signin(input: { email: string; password: string }): Promise<{
    id: string;
    email: string;
    mfaEnabled: boolean;
    identitySessionId: string | undefined;
    activeSessionId: string | undefined;
  }> {
    const { email, password } = input;

    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        name: true,
        email: true,
        roles: true,
        password: true,
        mfaEnabled: true,
        isEmailVerified: true,
        isLocked: true,
        lockedUntil: true,
      },
    });

    if (!user || !user.password) {
      throw new AppError('Invalid credentials', 401, ErrorCode.INVALID_CREDENTIALS);
    }

    // ----------------------- Check if email verified or not -----------------------

    if (!user.isEmailVerified) {
      throw new AppError('Please verify your email before signing in', 403, ErrorCode.EMAIL_NOT_VERIFIED);
    }

    // ----------------------- Handel locked user -----------------------

    if (user.isLocked) {
      if (user.lockedUntil && user.lockedUntil > new Date()) {
        throw new AppError(
          `Account is locked until ${user.lockedUntil.toISOString()}`,
          423,
          ErrorCode.ACCOUNT_LOCKED,
        );
      }

      // auto-unlock if lock expired
      await prisma.user.update({
        where: { id: user.id },
        data: {
          isLocked: false,
          lockedUntil: null,
        },
      });
    }

    // ----------------------- Handle password validation -----------------------

    const isPasswordValid = await bcrypt.compare(password, user.password);

    // ----------------------- if invalid password -----------------------
    // increase failed login count
    // if exceed limit lock  user

    let identitySessionId: string | undefined = undefined;
    let activeSessionId: string | undefined = undefined;

    const failureCountKey = this.signinFailCountKey(user.id);

    if (!isPasswordValid) {
      const failureCount = await redis.incr(failureCountKey);

      if (failureCount === 1) {
        await redis.expire(failureCountKey, this.signinFailCountExpiry);
      }

      if (failureCount >= this.maxSigninFailures) {
        // Lock account
        const lockedUntil = new Date(Date.now() + this.signinLockUntil * 1000);

        await prisma.user.update({
          where: { id: user.id },
          data: {
            isLocked: true,
            lockedUntil,
          },
        });

        // delete failureCount
        await redis.del(failureCountKey);

        // send account locked email
      }

      throw new AppError('Invalid credentials', 401, ErrorCode.INVALID_CREDENTIALS);
    }

    // ----------------------- if valid password -----------------------
    // delete failure count from redis

    await redis.del(failureCountKey);

    // ----------------------- if mfa enabled - send email, else create new session -----------------------

    if (user.mfaEnabled) {
      const verificationToken = AppCrypto.randomToken(32);
      const hashedVerificationToken = AppCrypto.hash(verificationToken, CRYPTO_ALGORITHMS.sha256, 'hex');

      await redis.set(
        this.signinVerificationTokenKey(hashedVerificationToken),
        user.id,
        'EX',
        this.signinVerificationTokenExpiry,
      );

      emailService.sendSignInVerifyEmail(user.email, user.name, verificationToken);
    } else {
      // create session
      identitySessionId = await sessionService.createIdentitySession(user.id);
      activeSessionId = await sessionService.createActiveSession(user.id, user.roles);

      if (!identitySessionId || !activeSessionId) {
        throw new AppError(
          'Identity & Active session ids are null',
          500,
          ErrorCode.INTERNAL_SERVER_ERROR,
          false,
        );
      }
    }

    return {
      id: user.id,
      email,
      mfaEnabled: user.mfaEnabled,
      identitySessionId,
      activeSessionId,
    };
  }

  // VERIFY SIGNIN MFA
  async verifySignIn(token: string): Promise<{
    id: string;
    email: string;
    identitySessionId: string;
    activeSessionId: string;
  }> {
    const hashedToken = AppCrypto.hash(token, CRYPTO_ALGORITHMS.sha256, 'hex');
    const key = this.signinVerificationTokenKey(hashedToken);

    const userId = await redis.get(key);

    if (!userId) {
      throw new AppError('Invalid or expired verification token', 400, ErrorCode.INVALID_TOKEN);
    }

    // delete token
    await redis.del(key);

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        roles: true,
      },
    });

    if (!user) {
      throw new AppError('Invalid user id', 401, ErrorCode.INVALID_CREDENTIALS);
    }

    // create Session
    const identitySessionId = await sessionService.createIdentitySession(user.id);
    const activeSessionId = await sessionService.createActiveSession(user.id, user.roles);

    return {
      id: user.id,
      email: user.email,
      identitySessionId,
      activeSessionId,
    };
  }

  // SIGNOUT
  async signout(isid: string, asid: string): Promise<void> {
    if (isid) {
      await sessionService.revokeIdentitySession(isid);
    }

    if (asid) {
      await sessionService.revokeActiveSession(asid);
    }
  }

  // FORGOT PASSWORD
  // generates a token and send it via verified email
  // user get in to the reset password via that email link + token
  async forgotPassword(email: string): Promise<void> {
    const user = await prisma.user.findUnique({
      where: { email },
      select: { id: true, name: true },
    });

    if (!user) {
      return;
    }

    const resetToken = AppCrypto.randomToken(32);
    const hashedToken = AppCrypto.hash(resetToken, CRYPTO_ALGORITHMS.sha256, 'hex');

    await redis.set(this.resetPasswordTokenKey(hashedToken), user.id, 'EX', this.resetPasswordExpiry);

    try {
      await emailService.sendPasswordResetEmail(email, user.name, resetToken);
    } catch (error) {
      // If email fails, clear the reset token
      await redis.del(this.resetPasswordTokenKey(hashedToken));
      throw error;
    }
  }

  // RESET PASSWORD
  async resetPassword(token: string, newPassword: string): Promise<void> {
    const hashedToken = AppCrypto.hash(token, CRYPTO_ALGORITHMS.sha256, 'hex');
    const userId = await redis.get(this.resetPasswordTokenKey(hashedToken));

    if (!userId) {
      throw new AppError('Invalid or expired reset token', 400, ErrorCode.INVALID_TOKEN);
    }

    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        isActive: true,
        isLocked: true,
      },
    });

    if (!user || !user.isActive) {
      throw new AppError('Account disabled', 403, ErrorCode.FORBIDDEN);
    }

    if (user.isLocked) {
      throw new AppError('Account locked', 423, ErrorCode.ACCOUNT_LOCKED);
    }

    const hashedPassword = await bcrypt.hash(newPassword, 10);

    await prisma.$transaction([
      prisma.user.update({
        where: { id: userId },
        data: { password: hashedPassword },
      }),

      prisma.identitySession.updateMany({
        where: { userId },
        data: { revoked: true },
      }),
    ]);

    await redis.del(this.resetPasswordTokenKey(hashedToken));
  }

  // MANAGE MFA
  async manageMfa(userId: string, enable: boolean): Promise<void> {
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { id: true, isActive: true },
    });

    if (!user || !user.isActive) {
      throw new AppError('Account disabled', 403, ErrorCode.FORBIDDEN);
    }

    await prisma.user.update({
      where: { id: userId },
      data: {
        mfaEnabled: enable,
        updatedAt: new Date(),
      },
    });

    await redis.del(`profile:${userId}`);
  }
}

export const authService = new AuthService();
