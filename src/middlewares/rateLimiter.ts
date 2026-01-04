import { ENV } from '@/config/env';
import rateLimit from 'express-rate-limit';

export const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50, // Reduced from 100 to 50 attempts per window
  message: {
    success: false,
    message: 'Too many login attempts, please try again later',
  },
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers
  keyGenerator: (req) => {
    return req.ip || (req.headers['x-forwarded-for'] as string);
  },
  skipSuccessfulRequests: true, // Only count failed attempts
});

export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50, // Reduced from 100 to 50 requests per 15 minutes
  message: {
    success: false,
    message: 'Too many requests, please try again later',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const emailVerificationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 3, // 3 attempts per hour
  message: {
    success: false,
    message: 'Too many verification attempts, please try again later',
  },
  standardHeaders: true,
  legacyHeaders: false,
});
