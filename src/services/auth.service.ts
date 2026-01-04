import prisma, { UserRole } from '@/config/database';
import crypto from 'crypto';
import bcrypt from 'bcrypt';
import redis from '@/config/redis';
import { AppError } from '@/utils/appError';
import { ErrorCode } from '@/utils/errorCodes';
import {
  SignupInput,
  SignupResult,
  VerifyEmailInput,
  VerifyEmailResult,
  ResendVerificationEmailInput,
  ResendVerificationEmailResult,
  SigninInput,
  SigninResult,
} from '@/@types/auth.types';
import { emailService } from '@/services/email.service';

export class AuthService {
  private verificationTokenExpiry: number;
  // private emailService: EmailService;

  constructor() {
    this.verificationTokenExpiry = 24 * 60 * 60;
    // this.emailService = new EmailService();
  }

  // Redis keys
  private emailVerificationToken_RK = (hashedToken: string): string => `email:verify:v1:token:${hashedToken}`;
  private emailVerificationUser_RK = (userId: string): string => `email:verify:v1:user:${userId}`;

  // Helper methods
  private generateVerificationToken = (): string => crypto.randomBytes(32).toString('hex');

  private hashedVerificationToken = (verificationToken: string): string =>
    crypto.createHash('sha256').update(verificationToken).digest('hex');

  // redis methods
  private async setVerificationTokenInRedis(token: string, userId: string): Promise<void> {
    await redis
      .multi()
      .set(this.emailVerificationToken_RK(token), userId, 'EX', this.verificationTokenExpiry)
      .set(this.emailVerificationUser_RK(userId), token, 'EX', this.verificationTokenExpiry)
      .exec();
  }

  private async delVerificationTokenInRedis(tokenKey: string, userKey: string): Promise<void> {
    await redis.multi().del(tokenKey).del(userKey).exec();
  }

  async signup({ name, email, password }: SignupInput): Promise<SignupResult> {
    const isExistingUser = await prisma.user.findUnique({
      where: { email },
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
        role: UserRole.USER,
      },
      select: {
        id: true,
        email: true,
        name: true,
        role: true,
        createdAt: true,
      },
    });

    const verificationToken = this.generateVerificationToken();
    const hashedVerificationToken = this.hashedVerificationToken(verificationToken);

    await this.setVerificationTokenInRedis(hashedVerificationToken, user.id);

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

  async verifyEmail({ token }: VerifyEmailInput): Promise<VerifyEmailResult> {
    const hashedToken = this.hashedVerificationToken(token);

    const tokenKey = this.emailVerificationToken_RK(hashedToken);
    const userId = await redis.get(tokenKey);

    if (!userId) {
      throw new AppError('Invalid or expired verification token', 400, ErrorCode.INVALID_TOKEN);
    }

    const updated = await prisma.user.updateMany({
      where: {
        id: userId,
        emailVerifiedAt: null,
      },
      data: {
        emailVerifiedAt: new Date(),
      },
    });

    if (updated.count === 0) {
      throw new AppError('Email already verified', 400, ErrorCode.INVALID_TOKEN);
    }

    const userKey = this.emailVerificationUser_RK(userId);
    await this.delVerificationTokenInRedis(token, userKey);

    return { message: 'Email verified successfully' };
  }

  async resendVerificationEmail({
    email,
  }: ResendVerificationEmailInput): Promise<ResendVerificationEmailResult> {
    const genericResponse = {
      message: 'If an account exists, a verification email has been sent',
    };

    const user = await prisma.user.findUnique({
      where: { email },
      select: { id: true, emailVerifiedAt: true, email: true, name: true },
    });

    if (!user || user.emailVerifiedAt) {
      return genericResponse;
    }

    const userKey = this.emailVerificationUser_RK(user.id);
    const existingToken = await redis.get(userKey);

    if (existingToken) {
      const tokenKey = this.emailVerificationToken_RK(existingToken);
      this.delVerificationTokenInRedis(tokenKey, userKey);
    }

    const verificationToken = this.generateVerificationToken();
    const hashedVerificationToken = this.hashedVerificationToken(verificationToken);

    await this.setVerificationTokenInRedis(hashedVerificationToken, user.id);

    // Send email verification email
    emailService.sendVerificationEmail(user.email, user.name, verificationToken);

    return genericResponse;
  }
}
