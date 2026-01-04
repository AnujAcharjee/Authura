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
  NEON_PG_DATABASE_URL: z.string(),
  SERVER_URL: z.url(),
  FRONTEND_URL: z.url(),
  REDIS_HOST: z.string(),
  REDIS_USERNAME: z.string(),
  REDIS_PORT: z
    .string()
    .transform(Number)
    .refine((n) => n >= 1024 && n <= 65535, {
      message: 'Port must be between 1024 and 65535',
    }),
  REDIS_PASSWORD: z.string(),
  SMTP_HOST: process.env.NODE_ENV === "development" ? z.string().optional() : z.string(),
  SMTP_PORT: process.env.NODE_ENV === "development" ? z.string().transform(Number).optional() : z.string().transform(Number),
  SMTP_USER: process.env.NODE_ENV === "development" ? z.string().optional() : z.string(),
  SMTP_PASSWORD: process.env.NODE_ENV === "development" ? z.string().optional() : z.string(),
  SMTP_FROM: process.env.NODE_ENV === "development" ? z.email().optional() : z.email(),
});

export const ENV = envSchema.parse(process.env);

// Validation for production environment
if (process.env.NODE_ENV === 'production') {
  const requiredFields = [
    'SMTP_HOST',
    'SMTP_PORT',
    'SMTP_USER',
    'SMTP_PASSWORD'
  ];
  
  requiredFields.forEach(field => {
    if (!process.env[field]) {
      throw new Error(`Missing required env variable: ${field}`);
    }
  });
}