import nodemailer from 'nodemailer';
import { ENV } from '@/config/env';
import { logger } from '@/config/logger';
import {
  getEmailVerificationTemplate,
  getPasswordResetEmailTemplate,
  getSignInVerificationTemplate,
} from '@/templates/email';

class EmailService {
  private transporter!: nodemailer.Transporter;
  private readonly fromAddress: string;
  private initialized = false;
  private initPromise: Promise<void> | null = null;

  constructor() {
    logger.info('Using SMTP configuration', {
      context: 'EmailService.constructor',
      host: ENV.SMTP_HOST,
    });

    this.fromAddress = ENV.SMTP_FROM ?? 'authura@localhost';
    this.precompileTemplates();
  }

  async init() {
    if (this.initialized) return;
    if (this.initPromise) return this.initPromise;

    this.initPromise = (async () => {
      if (ENV.NODE_ENV === 'development') {
        await this.initEthereal();
      } else {
        await this.initProductionSMTP();
      }

      this.initialized = true;
      this.initPromise = null;
    })();

    return this.initPromise;
  }

  // -----------------------
  // DEV: Ethereal
  // -----------------------
  private async initEthereal() {
    const testAccount = await nodemailer.createTestAccount();

    this.transporter = nodemailer.createTransport({
      host: 'smtp.ethereal.email',
      port: 587,
      auth: {
        user: testAccount.user,
        pass: testAccount.pass,
      },
    });

    await this.transporter.verify();

    logger.info('Using Ethereal SMTP (development)', {
      context: 'EmailService.initEthereal',
      user: testAccount.user,
    });
  }

  // -----------------------
  // PROD: Real SMTP
  // -----------------------
  private async initProductionSMTP() {
    this.transporter = nodemailer.createTransport({
      host: ENV.SMTP_HOST,
      port: ENV.SMTP_PORT,
      secure: ENV.SMTP_PORT === 465,
      auth: {
        user: ENV.SMTP_USER,
        pass: ENV.SMTP_PASSWORD,
      },
      requireTLS: ENV.SMTP_PORT === 587,
      tls: {
        rejectUnauthorized: true,
      },
      connectionTimeout: 10_000,
      greetingTimeout: 10_000,
      socketTimeout: 10_000,
    });

    await this.transporter.verify();

    logger.info('Production SMTP verified', {
      context: 'EmailService.initProductionSMTP',
      host: ENV.SMTP_HOST,
    });
  }

  private precompileTemplates() {
    try {
      // Pre-compile by running once
      getEmailVerificationTemplate('test', 'test_url');
      getPasswordResetEmailTemplate('test', 'test_url');
      getSignInVerificationTemplate('test', 'test_url');

      logger.info('Email templates precompiled successfully');
    } catch (error) {
      logger.error('Failed to precompile email templates', { error });
    }
  }

  async sendVerificationEmail(to: string, name: string, verificationToken: string): Promise<void> {
    const verificationUrl = `${ENV.SERVER_URL}/api/auth/verify-email/${verificationToken}`;

    try {
      const info = await this.transporter.sendMail({
        from: this.fromAddress,
        to,
        subject: 'Verify your email address',
        html: getEmailVerificationTemplate(name, verificationUrl),
      });

      logger.info('Verification email sent', {
        context: 'EmailService.sendVerificationEmail',
        to,
        messageId: info.messageId,
        previewUrl: ENV.NODE_ENV === 'development' ? nodemailer.getTestMessageUrl(info) : undefined,
      });
    } catch (error) {
      logger.error('Failed to send verification email', {
        context: 'EmailService.sendVerificationEmail',
        error: error instanceof Error ? error.message : 'Unknown error',
        to,
      });
      throw error;
    }
  }

  async sendSignInVerifyEmail(to: string, name: string, verificationToken: string): Promise<void> {
    const verificationUrl = `${ENV.SERVER_URL}/api/auth/verify-email/${verificationToken}`;

    try {
      const info = await this.transporter.sendMail({
        from: this.fromAddress,
        to,
        subject: 'Verify your email address',
        html: getSignInVerificationTemplate(name, verificationUrl),
      });

      logger.info('Sign-in verification email sent', {
        context: 'EmailService.sendSignInVerifyEmail',
        to,
        messageId: info.messageId,
        previewUrl: ENV.NODE_ENV === 'development' ? nodemailer.getTestMessageUrl(info) : undefined,
      });
    } catch (error) {
      logger.error('Failed to send sign-in verification email', {
        context: 'EmailService.sendSignInVerifyEmail',
        error: error instanceof Error ? error.message : 'Unknown error',
        to,
      });
      throw error;
    }
  }

  async sendPasswordResetEmail(to: string, name: string, resetToken: string): Promise<void> {
    const resetUrl = `${ENV.FRONTEND_URL}/reset-password?token=${resetToken}`;

    try {
      const info = await this.transporter.sendMail({
        from: this.fromAddress,
        to,
        subject: 'Reset Your Password',
        html: getPasswordResetEmailTemplate(name, resetUrl),
      });

      logger.info('Password reset email sent', {
        context: 'EmailService.sendPasswordResetEmail',
        to,
        messageId: info.messageId,
        previewUrl: ENV.NODE_ENV === 'development' ? nodemailer.getTestMessageUrl(info) : undefined,
      });
    } catch (error) {
      logger.error('Failed to send password reset email', {
        context: 'EmailService.sendPasswordResetEmail',
        error: error instanceof Error ? error.message : 'Unknown error',
        to,
      });
      throw error;
    }
  }
}

export const emailService = new EmailService();
