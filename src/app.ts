import express, { Express, Request, Response } from 'express';
import cors from 'cors';
import cookieParser from 'cookie-parser';
import { ENV } from '@/config/env';
import { errorMiddleware } from '@/middlewares/errorMiddleware';
import { notFoundHandler } from '@/middlewares/notFound';
import { loggingMiddleware } from '@/middlewares/loggingMiddleware';
import { setupSecurityHeaders } from '@/middlewares/securityHeaders';
import { ensureRequestId } from '@/middlewares/requestId';
import { authLimiter, apiLimiter } from '@/middlewares/rateLimiter';
import authRoutes from '@/routes/auth.routes';

const app = express();

// Trust the first proxy in front of the app (e.g. Nginx, load balancer, Docker)
// This is required so Express correctly reads the real client IP from
// X-Forwarded-For headers, which is critical for rate limiting, logging,
// and security controls. Do NOT enable this unless the app is actually
// behind a trusted reverse proxy.
app.set('trust proxy', 1);

// middlewares
const setupMiddleware = (app: express.Application) => {
  // Security
  setupSecurityHeaders(app as Express);
  app.use(ensureRequestId);
  app.use(cors({ origin: ENV.FRONTEND_URL, credentials: true }));

  // Performance
  app.use(express.json({ limit: '10kb' }));
  app.use(cookieParser(ENV.COOKIE_SECRET));

  // Monitoring
  app.use(loggingMiddleware);

  // Rate Limiting
  app.use('/api/auth', authLimiter);
  app.use('/api', apiLimiter);
};

setupMiddleware(app);

// Routes
app.get('/', (req: Request, res: Response) => {
  res.json({ message: '🚀 Hello from Authura Backend!' });
});

// Health Check
app.get('/health', (req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date(),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
  });
});

app.use('/api/auth', authRoutes);

// 404 handler
app.use(notFoundHandler);

// Global Error Handler
app.use(errorMiddleware);

export default app;
