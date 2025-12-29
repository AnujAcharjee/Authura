import express, { Request, Response } from 'express';
import cors from 'cors';
import { ENV } from '@/config/env';
import { errorMiddleware } from '@/middlewares/errorMiddleware';
import { notFoundHandler } from '@/middlewares/notFound';
import { loggingMiddleware } from '@/middlewares/loggingMiddleware';
import { requestId } from '@/middlewares/requestId';

const app = express();

// middlewares
const setupMiddleware = (app: express.Application) => {
  // Security
  app.use(requestId);
  app.use(cors({ origin: ENV.FRONTEND_URL, credentials: true }));

  // Performance
  app.use(express.json({ limit: '10kb' }));

  // Monitoring
  app.use(loggingMiddleware);
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

// 404 handler
app.use(notFoundHandler);

// Global Error Handler
app.use(errorMiddleware);

export default app;
