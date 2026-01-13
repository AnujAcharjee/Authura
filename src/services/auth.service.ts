import prisma, { UserRole } from '@/config/database';
import bcrypt from 'bcrypt';
import redis from '@/config/redis';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';
import {
  SignupParams,
  SignupResult,
  VerifyEmailResult,
  SigninParams,
  SigninResult,
  VerifySignInResult,
} from '@/@types/auth.types';
import { emailService } from '@/services/email.service';
import { randomToken, sha256 } from '@/utils/crypto';
import { ENV } from '@/config/env';
import { sessionService } from '@/services/session.service';

export class AuthService {
  private emailVerificationTokenExpiry: number;
  private signinFailCountExpiry: number;
  private signinVerificationTokenExpiry: number;
  private signinLockUntil: number;
  private maxSigninFailures: number;
  private resetPasswordExpiry: number;

  constructor() {
    this.emailVerificationTokenExpiry =
      ENV.NODE_ENV == 'production' ? ENV.EMAIL_VERIFICATION_TOKEN_EX : 24 * 60 * 60;
    this.signinFailCountExpiry = ENV.NODE_ENV == 'production' ? ENV.SIGN_IN_FAIL_COUNT_EX : 24 * 60 * 60;
    this.signinVerificationTokenExpiry =
      ENV.NODE_ENV == 'production' ? ENV.SIGN_VERIFICATION_TOKEN_EX : 24 * 60 * 60;
    this.signinLockUntil = ENV.NODE_ENV == 'production' ? ENV.SIGNIN_LOCK_UNTIL : 6 * 60 * 60;
    this.maxSigninFailures = ENV.NODE_ENV == 'production' ? ENV.MAX_SIGNIN_FAILURES : 20;
    this.resetPasswordExpiry = 60 * 60;
  }

  // Redis keys
  private emailVerificationToken_RK = (hashedToken: string): string => `email-verify:token:${hashedToken}`;
  private emailVerificationUser_RK = (userId: string): string => `email-verify:user:${userId}`;
  private signinFailCount_RK = (userId: string) => `signin:fail-count:${userId}`;
  private signinVerificationToken_RK = (hashedToken: string) => `signin:verify-token:${hashedToken}`;
  private resetPasswordToken_RK = (hashedToken: string) => `reset-password:${hashedToken}`;

  // REDIS methods
  private async setVerificationTokenInRedis(token: string, userId: string, role: UserRole): Promise<void> {
    await redis
      .multi()
      .set(
        this.emailVerificationToken_RK(token),
        JSON.stringify({ userId, role }),
        'EX',
        this.emailVerificationTokenExpiry,
      )
      .set(this.emailVerificationUser_RK(userId), token, 'EX', this.emailVerificationTokenExpiry)
      .exec();
  }

  private async delVerificationTokenInRedis(tokenKey: string, userKey: string): Promise<void> {
    await redis.multi().del(tokenKey).del(userKey).exec();
  }

  // SIGNUP
  async signup({ name, email, password }: SignupParams): Promise<SignupResult> {
    const isExistingUser = await prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (isExistingUser) {
      throw new AppError('Email already exists', 400, ErrorCode.ALREADY_EXISTS);
    }

    const hashPassword = await bcrypt.hash(password, 10);

    const user = await prisma.user.create({
      data: {
        name,
        email,
        password: hashPassword,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    const verificationToken = randomToken(32);
    const hashedVerificationToken = sha256(verificationToken);

    await this.setVerificationTokenInRedis(hashedVerificationToken, user.id, user.role);

    // Send email verification email
    emailService.sendVerificationEmail(email, name, verificationToken);

    return {
      id: user.id,
      email: user.email,
      name: user.name,
      role: user.role,
      createdAt: user.createdAt,
    };
  }

  // VERIFY EMAIL
  async verifyEmail(token: string): Promise<VerifyEmailResult> {
    const hashedToken = sha256(token);
    const tokenKey = this.emailVerificationToken_RK(hashedToken);

    const userInfo = await redis.get(tokenKey);

    if (!userInfo) {
      throw new AppError('Invalid or expired verification token', 400, ErrorCode.INVALID_TOKEN);
    }

    const parsed = JSON.parse(userInfo);

    const updated = await prisma.user.updateMany({
      where: {
        id: parsed.userId,
        isEmailVerified: false,
      },
      data: {
        isEmailVerified: true,
        emailVerifiedAt: new Date(),
      },
    });

    // delete tokens
    const userKey = this.emailVerificationUser_RK(parsed.userId);
    await this.delVerificationTokenInRedis(token, userKey);

    if (updated.count === 0) {
      throw new AppError('Email already verified', 400, ErrorCode.INVALID_TOKEN);
    }

    // create session
    const identitySessionId = await sessionService.createIdentitySession(parsed.userId);
    const activeSessionId = await sessionService.createActiveSession(parsed.userId, parsed.role);

    return {
      identitySessionId,
      activeSessionId,
    };
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
        role: true,
      },
    });

    if (!user || user.isEmailVerified) {
      return;
    }

    const userKey = this.emailVerificationUser_RK(user.id);
    const existingToken = await redis.get(userKey);

    if (existingToken) {
      const tokenKey = this.emailVerificationToken_RK(existingToken);
      this.delVerificationTokenInRedis(tokenKey, userKey);
    }

    const verificationToken = randomToken();
    const hashedVerificationToken = sha256(verificationToken);

    await this.setVerificationTokenInRedis(hashedVerificationToken, user.id, user.role);

    // Send email verification email
    emailService.sendVerificationEmail(user.email, user.name, verificationToken);
  }

  // SIGNIN
  async signin({ email, password }: SigninParams): Promise<SigninResult> {
    const user = await prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
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
    // if locked throw err
    // else unlock

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

    let identitySessionId, activeSessionId;
    const failureCountKey = this.signinFailCount_RK(user.id);

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
      const verificationToken = randomToken(32);
      const hashedVerificationToken = sha256(verificationToken);

      await redis.set(
        this.signinVerificationToken_RK(hashedVerificationToken),
        user.id,
        'EX',
        this.signinVerificationTokenExpiry,
      );

      emailService.sendSignInVerifyEmail(user.email, user.name, verificationToken);
    } else {
      // create session
      identitySessionId = await sessionService.createIdentitySession(user.id);
      activeSessionId = await sessionService.createActiveSession(user.id, user.role);
    }

    return {
      mfaEnabled: user.mfaEnabled,
      identitySessionId,
      activeSessionId,
    };
  }

  // VERIFY SIGNIN MFA
  async verifySignIn(token: string): Promise<VerifySignInResult> {
    const hashedToken = sha256(token);
    const key = this.signinVerificationToken_RK(hashedToken);

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
        role: true,
      },
    });

    if (!user) {
      throw new AppError('Invalid user id', 401, ErrorCode.INVALID_CREDENTIALS);
    }

    // create Session
    const identitySessionId = await sessionService.createIdentitySession(user.id);
    const activeSessionId = await sessionService.createActiveSession(user.id, user.role);

    return {
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

  // REFRESH ACTIVE SESSION
  async refreshActiveSession(isid: string): Promise<string> {
    if (!isid) {
      throw new AppError('Identity session token is missing. Sign in again.', 401, ErrorCode.ISESS_EXPIRED);
    }

    const isidHash = sha256(isid);

    const session = await prisma.identitySession.findUnique({
      where: { token: isidHash },
      include: {
        user: {
          select: {
            id: true,
            role: true,
            isActive: true,
            isLocked: true,
          },
        },
      },
    });

    if (!session || !session.user) {
      throw new AppError('Invalid session', 401, ErrorCode.UNAUTHORIZED);
    }

    // verify
    if (!session.user.isActive) {
      throw new AppError('Account disabled', 403, ErrorCode.FORBIDDEN);
    }

    if (session.user.isLocked) {
      throw new AppError('Account is locked. Try again later.', 423, ErrorCode.ACCOUNT_LOCKED);
    }

    if (session.revoked || session.expiresAt.getTime() < Date.now()) {
      throw new AppError('Session expired. Sign in again', 401, ErrorCode.UNAUTHORIZED);
    }

    // create new active session
    const activeSessId = await sessionService.createActiveSession(session.user.id, session.user.role);

    return activeSessId;
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

    const resetToken = randomToken(32);
    const hashedToken = sha256(resetToken);

    await redis.set(this.resetPasswordToken_RK(hashedToken), user.id, 'EX', this.resetPasswordExpiry);

    try {
      await emailService.sendPasswordResetEmail(email, user.name, resetToken);
    } catch (error) {
      // If email fails, clear the reset token
      await redis.del(this.resetPasswordToken_RK(hashedToken));
      throw error;
    }
  }

  // RESET PASSWORD
  async resetPassword(token: string, newPassword: string) {
    const hashedToken = sha256(token);
    const userId = await redis.get(this.resetPasswordToken_RK(hashedToken));

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

    await redis.del(this.resetPasswordToken_RK(hashedToken));
  }
}
