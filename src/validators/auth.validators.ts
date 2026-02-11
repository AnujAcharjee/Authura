import { z } from 'zod';
import { UtilFields } from './util.fields.js';

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
    query: z.object({
      token: UtilFields.tokenField(),
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
    query: z.object({
      token: UtilFields.tokenField(),
    }),
  });

  static forgotPasswordSchema = z.object({
    body: z.object({
      email: UtilFields.emailField,
    }),
  });

  static resetPasswordSchema = z.object({
    body: z.object({
      token: UtilFields.tokenField(),
      old_password: UtilFields.passwordField,
      new_password: UtilFields.passwordField,
      confirm_new_password: UtilFields.passwordField,
    }),
  }).refine((data) => data.body.new_password === data.body.confirm_new_password, {
    message: 'New password and confirm password must match',
    path: ['body', 'confirm_new_password'],
  });
}
