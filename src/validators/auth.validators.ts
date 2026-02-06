import { z } from 'zod';
import { UtilFields } from './util.fields';

export class AuthZSchema {
  static signupSchema = z.object({
    body: z.object({
      name: UtilFields.nameField,
      email: UtilFields.emailField,
      gender: UtilFields.genderField,
      password: UtilFields.passwordField,
    }),
  });

  static verifyEmailSchema = z.object({
    params: z.object({
      token: UtilFields.tokenField('Verification link'),
    }),
  });

  static resendVerificationEmailSchema = z.object({
    query: z.object({
      email: UtilFields.emailField,
    }),
  });

  static signinSchema = z.object({
    body: z.object({
      email: UtilFields.emailField,
      password: UtilFields.passwordField,
    }),
  });

  static verifySignInSchema = z.object({
    params: z.object({
      token: UtilFields.tokenField('Verification link'),
    }),
  });

  static forgotPasswordSchema = z.object({
    body: z.object({
      email: UtilFields.emailField,
    }),
  });

  static resetPasswordSchema = z.object({
    body: z.object({
      token: UtilFields.tokenField('Reset link'),
      password: UtilFields.passwordField,
    }),
  });

  static manageMfaSchema = z.object({
    body: z.object({
      action: z.enum(['enable', 'disable']),
    }),
  });
}
