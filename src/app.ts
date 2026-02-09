import express, { type Express, type Request, type Response } from 'express';
import cookieParser from 'cookie-parser';
import path from 'path';
import ejsMate from 'ejs-mate';
import methodOverride from 'method-override';

import { ENV } from './config/env.js';
import { errorMiddleware } from './middlewares/errorMiddleware.js';
import { notFoundHandler } from './middlewares/notFound.js';
import { loggingMiddleware } from './middlewares/loggingMiddleware.js';
import { setupSecurityHeaders } from './middlewares/securityHeaders.js';
import { ensureRequestId } from './middlewares/requestId.js';
import { authLimiter, apiLimiter } from './middlewares/rateLimiter.js';
import authRoutes from './routes/api/auth.api.routes.js';
import oauthRoutes from './routes/api/OAuth.api.routes.js';
import clientRoutes from './routes/api/client.api.routes.js';
import userRoutes from './routes/api/user.api.routes.js';
import pagesRoutes from './routes/ui/ui.routes.js';


const app = express();

// ejs setup
app.engine('ejs', ejsMate);
app.set('view engine', 'ejs');
app.set('views', path.join(process.cwd(), 'src', 'views'));

// Trust the first proxy in front of the app (e.g. Nginx, Caddy, load balancer, Docker)
// This is required so Express correctly reads the real client IP from
// X-Forwarded-For headers, which is critical for rate limiting, logging, and security controls.
app.set('trust proxy', true);

const setupMiddleware = (app: express.Application) => {
  // Security
  setupSecurityHeaders(app as Express);
  app.use(ensureRequestId);

  // Performance
  app.use(express.urlencoded({ extended: false }));
  app.use(express.json({ limit: '10kb' }));
  app.use(cookieParser(ENV.COOKIE_SECRET));
  app.use(express.static(path.join(process.cwd(), 'public')));
  app.use(methodOverride('_method'));

  // Monitoring
  app.use(loggingMiddleware);

  // Rate Limiting
  // app.use('/api/auth', authLimiter);
  // app.use('/api', apiLimiter);
};

setupMiddleware(app);

// Health Check
app.get('/health', (_req: Request, res: Response) => {
  res.json({
    status: 'ok',
    timestamp: new Date(),
    uptime: process.uptime(),
    memoryUsage: process.memoryUsage(),
  });
});

// Pages (ejs)
app.use('/', pagesRoutes);

// API (JSON)
app.use('/api/auth', authRoutes);
app.use('/api/oauth', oauthRoutes);
app.use('/api/client', clientRoutes);
app.use('/api/user', userRoutes);

// 404 handler
app.use(notFoundHandler);

// Global Error Handler
app.use(errorMiddleware);

export default app;
