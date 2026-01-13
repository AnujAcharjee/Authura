import { z } from 'zod';

export const signupSchema = z.object({
  body: z.object({
    name: z.string().min(2).max(99),
    email: z.email().max(99),
    password: z
      .string()
      .min(8)
      .max(99)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
        'Password must contain at least one uppercase letter, one lowercase letter, one number and one special character',
      ),
  }),
});

export const verifyEmailSchema = z.object({
  params: z.object({
    token: z.string().min(1, 'Verification token is required'),
  }),
});

export const resendVerificationEmailSchema = z.object({
  body: z.object({
    email: z.email('Invalid email address'),
  }),
});

export const signinSchema = z.object({
  body: z.object({
    email: z.email().max(99),
    password: z
      .string()
      .min(8)
      .max(99)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
        'Password must contain at least one uppercase letter, one lowercase letter, one number and one special character',
      ),
  }),
});

export const verifySignInSchema = z.object({
  params: z.object({
    token: z.string().min(1, 'Verification token is required'),
  }),
});

export const forgotPasswordSchema = z.object({
  body: z.object({
    email: z.email().max(99),
  }),
});

export const resetPasswordSchema = z.object({
  params: z.object({
    token: z.string().min(1, 'Verification token is required'),
  }),
  body: z.object({
    password: z
      .string()
      .min(8)
      .max(99)
      .regex(
        /^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]/,
        'Password must contain at least one uppercase letter, one lowercase letter, one number and one special character',
      ),
  }),
});
