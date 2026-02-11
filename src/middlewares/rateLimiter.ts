import rateLimit, { ipKeyGenerator } from 'express-rate-limit';

export const signupLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, // 1 hour
  max: 5, // 5 signups per IP per hour
  standardHeaders: true, // Return rate limit info in the `RateLimit-*` headers
  legacyHeaders: false, // Disable the `X-RateLimit-*` headers

  message: {
    success: false,
    message: 'Too many signup attempts, please try again later',
  },

  // Count ALL attempts (success + failure)
  skipSuccessfulRequests: false,

  keyGenerator: (req) => {
    const email = req.body?.email;
    if (email) {
      return `signup:${String(email).toLowerCase()}`;
    }
    return ipKeyGenerator(req as any);
  },
});

export const signinLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 50,
  standardHeaders: true,
  legacyHeaders: false,

  message: {
    success: false,
    message: 'Too many login attempts, please try again later',
  },

  skipSuccessfulRequests: true, // Only count failed attempts

  keyGenerator: (req) => ipKeyGenerator(req as any),
});

export const forgotPasswordLimiter = rateLimit({
  windowMs: 60 * 60 * 1000,
  max: 5,
  message: {
    success: false,
    message: 'Too many password reset attempts, please try again later',
  },
  standardHeaders: true,
  legacyHeaders: false,

  // Count ALL attempts
  skipSuccessfulRequests: false,

  keyGenerator: (req) => {
    const email = req.body?.email;
    if (email) {
      return `forgot:${String(email).toLowerCase()}`;
    }
    return ipKeyGenerator(req as any);
  },
});

export const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 50,
  message: {
    success: false,
    message: 'Too many requests, please try again later',
  },
  standardHeaders: true,
  legacyHeaders: false,
});

export const emailVerificationLimiter = rateLimit({
  windowMs: 60 * 60 * 1000, 
  max: 3, 
  message: {
    success: false,
    message: 'Too many verification attempts, please try again later',
  },
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true,
  keyGenerator: (req) => (req.query.token as string) || ipKeyGenerator(req as any),
});
