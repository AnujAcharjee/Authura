import { z } from 'zod';
import { UtilFields } from '../validators/util.fields.js';

export class UserZSchema {
  static getProfileSchema = z.object({
    params: z.object({
      user_id: z.string().min(1, 'user_id is required'),
    }),
  });

  static updateProfileSchema = z
    .object({
      params: z.object({
        user_id: z.string().min(1),
      }),
      body: z.object({
        updates: z
          .object({
            name: UtilFields.nameField,
            email: UtilFields.emailField,
            avatar: z.url().optional(),
          })
          .strict(),
      }),
    })
    .refine((data) => Object.keys(data.body.updates).length > 0, {
      message: 'At least one field must be updated',
    });
}
