import app from './app';
import { ENV } from '@/config/env';
import { logger } from '@/config/logger';
import prisma from '@/config/database';
import { emailService } from '@/services/email.service';
import { Server } from 'node:http';

let server: Server | undefined;
let isShuttingDown = false;

// Init server
async function init() {
  await emailService.init();

  server = app.listen(ENV.PORT, () => {
    logger.info(`Server running on port ${ENV.PORT} in ${ENV.NODE_ENV} mode`);
  });
}

init().catch((error) => {
  logger.error('Failed to start server', error);
  process.exit(1);
});

// Graceful shutdown
const shutdown = async (signal: string) => {
  if (isShuttingDown) return;
  isShuttingDown = true;

  logger.info('Shutdown signal received');

  if (!server) {
    logger.warn('Server not started yet, exiting');
    await prisma.$disconnect();
    logger.info('Database connections closed');
    process.exit(0);
  }

  // Stop accepting new connections
  server.close(async () => {
    logger.info('HTTP server closed');

    try {
      await prisma.$disconnect();
      logger.info('Database connections closed');
      process.exit(0);
    } catch (err) {
      logger.error('Error during shutdown:', err);
      process.exit(1);
    }
  });

  // Force shutdown after 30 seconds
  setTimeout(() => {
    logger.error('Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 30_000);
};

process.on('SIGTERM', shutdown);
process.on('SIGINT', shutdown);

export default server;
