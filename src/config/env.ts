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
});

export const ENV = envSchema.parse(process.env);
