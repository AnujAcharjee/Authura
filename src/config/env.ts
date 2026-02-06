import { z } from 'zod';
import 'dotenv/config';

const envSchema = z.object({
  NODE_ENV: z.enum(['development', 'production', 'test']),
  PORT: z
    .string()
    .transform(Number)
    .refine((n) => n >= 1024 && n <= 65535, {
      message: 'Port must be between 1024 and 65535',
    }),
  APP_NAME:
    process.env.NODE_ENV === 'development' ?
      z.string().optional().default('Express Boilerplate')
    : z.string(),
  SERVER_URL: z.url(),
  FRONTEND_URL: z.url(),
  COOKIE_SECRET: z.string(),
  NEON_PG_DATABASE_URL: z.string(),

  // redis
  REDIS_HOST: z.string(),
  REDIS_USERNAME: z.string(),
  REDIS_PORT: z
    .string()
    .transform(Number)
    .refine((n) => n >= 1024 && n <= 65535, {
      message: 'Port must be between 1024 and 65535',
    }),
  REDIS_PASSWORD: z.string(),

  // node-mail
  SMTP_HOST: process.env.NODE_ENV === 'development' ? z.string().optional() : z.string(),
  SMTP_PORT:
    process.env.NODE_ENV === 'development' ?
      z.string().transform(Number).optional()
    : z.string().transform(Number),
  SMTP_USER: process.env.NODE_ENV === 'development' ? z.string().optional() : z.string(),
  SMTP_PASSWORD: process.env.NODE_ENV === 'development' ? z.string().optional() : z.string(),
  SMTP_FROM: process.env.NODE_ENV === 'development' ? z.email().optional() : z.email(),

  // Auth expiries are in secondes
  ACTIVE_SESSION_EX: z
    .string()
    .transform(Number)
    .refine((n) => n >= 10 * 60 && n <= 30 * 60, {
      message: 'Active session expiry must be between 10 to 30 mins',
    }),
  IDENTITY_SESSION_EX: z
    .string()
    .transform(Number)
    .refine((n) => n >= 180 * 24 * 60 * 60 && n <= 360 * 24 * 60 * 60, {
      message: 'Identity session expiry must be between 180 to 360 days',
    }),
  EMAIL_VERIFICATION_TOKEN_EX: z
    .string()
    .transform(Number)
    .refine((n) => n <= 24 * 60 * 60, {
      message: 'Email verification token expiry must be <= 24 hrs',
    }),
  SIGN_IN_FAIL_COUNT_EX: z.string().transform(Number),
  SIGN_VERIFICATION_TOKEN_EX: z
    .string()
    .transform(Number)
    .refine((n) => n <= 24 * 60 * 60, {
      message: 'Sign-in verification token expiry must be <= 24 hrs',
    }),
  SIGNIN_LOCK_UNTIL: z.string().transform(Number),
  MAX_SIGNIN_FAILURES: z.string().transform(Number),
  RESET_PASSWORD_EX: z.string().transform(Number),

  // OAuth
  AUTH_ISSUER: z.url(),
  AUTH_CODE_EX: z.string().transform(Number),
  AUTH_TOKENS_EX: z.string(),
  AUTH_REQUEST_EX: z.string(),
  KEY_ENC_SECRET: z.string().regex(/^[0-9a-f]{64}$/, {
    message: 'KEY_ENC_SECRET must be exactly 32 bytes (64 hex characters)',
  }),

  // Profile
  PROFILE_CACHE_EX: z.string().transform(Number),

  // Client
  CLIENT_CACHE_EX: z.string().transform(Number),
  CLIENT_SECRET_KEY: z.string(),
});

export const ENV = envSchema.parse(process.env);

// Validation for production environment
if (process.env.NODE_ENV === 'production') {
  const requiredFields = ['SMTP_HOST', 'SMTP_PORT', 'SMTP_USER', 'SMTP_PASSWORD'];

  requiredFields.forEach((field) => {
    if (!process.env[field]) {
      throw new Error(`Missing required env variable: ${field}`);
    }
  });
}
